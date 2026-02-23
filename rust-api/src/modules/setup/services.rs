use bson::doc;
use chrono::Utc;
use mongodb::Database;

use crate::errors::AppError;
use crate::middleware::auth::{create_token, parse_expires_in};
use crate::middleware::password::{hash_password, validate_password};
use crate::middleware::rbac::Role;
use crate::models::control::{Control, ControlStatus};
use crate::models::framework::{Framework, FrameworkStatus};
use crate::models::organization::Organization;
use crate::models::policy::{Policy, PolicyStatus};
use crate::models::user::User;
use crate::seed::{DEFAULT_POLICIES, ISO_ANNEX_A_CONTROLS};

use super::models::{AdminSetup, InitializeResponse, OrganizationSetup};

/// Check if the system has been initialized (any organization exists).
pub async fn can_setup(db: &Database) -> Result<bool, AppError> {
    let count = db
        .collection::<Organization>("organizations")
        .count_documents(doc! {})
        .await?;
    Ok(count == 0)
}

/// One-time system initialization:
/// 1. Create organization
/// 2. Create SUPER_ADMIN user
/// 3. Create ISO 27001 framework
/// 4. Seed 93 ISO controls
/// 5. Seed 26 default policies
/// 6. Return JWT token
pub async fn initialize(
    db: &Database,
    org_req: OrganizationSetup,
    admin_req: AdminSetup,
    jwt_secret: &str,
    jwt_expires_in: &str,
    bcrypt_cost: u32,
) -> Result<InitializeResponse, AppError> {
    // Guard: only allow setup once
    if !can_setup(db).await? {
        return Err(AppError::Conflict(
            "System already initialized".into(),
        ));
    }

    // Validate password
    validate_password(&admin_req.password)?;

    let now = Utc::now();

    // 1. Create organization
    let org = Organization {
        id: None,
        name: org_req.name,
        domain: org_req.domain,
        vanta_id: None,
        deleted_at: None,
        created_at: now,
        updated_at: now,
    };
    let org_result = db
        .collection::<Organization>("organizations")
        .insert_one(&org)
        .await?;
    let org_id = org_result
        .inserted_id
        .as_object_id()
        .ok_or_else(|| AppError::Internal("Failed to get org ID".into()))?;

    // 2. Create SUPER_ADMIN user
    let password_hash = hash_password(&admin_req.password, bcrypt_cost)?;
    let user = User {
        id: None,
        email: admin_req.email.clone(),
        password: Some(password_hash),
        google_id: None,
        name: Some(admin_req.name),
        role: Role::SuperAdmin,
        org_id,
        deleted_at: None,
        created_at: now,
        updated_at: now,
    };
    let user_result = db
        .collection::<User>("users")
        .insert_one(&user)
        .await?;
    let user_id = user_result
        .inserted_id
        .as_object_id()
        .ok_or_else(|| AppError::Internal("Failed to get user ID".into()))?;

    // 3. Create ISO 27001 framework
    let framework = Framework {
        id: None,
        org_id,
        name: "ISO 27001:2022".to_string(),
        description: Some("Information security management systems — Requirements".to_string()),
        version: Some("2022".to_string()),
        status: FrameworkStatus::Active,
        total_controls: ISO_ANNEX_A_CONTROLS.len() as i32,
        implemented_controls: 0,
        compliance_percentage: 0.0,
        vanta_id: None,
        vanta_synced_at: None,
        deleted_at: None,
        created_at: now,
        updated_at: now,
    };
    let fw_result = db
        .collection::<Framework>("frameworks")
        .insert_one(&framework)
        .await?;
    let framework_id = fw_result
        .inserted_id
        .as_object_id()
        .ok_or_else(|| AppError::Internal("Failed to get framework ID".into()))?;

    // 4. Seed ISO 27001 Annex A controls (93)
    let controls: Vec<Control> = ISO_ANNEX_A_CONTROLS
        .iter()
        .map(|seed| Control {
            id: None,
            org_id,
            code: seed.code.to_string(),
            title: seed.title.to_string(),
            description: Some(seed.description.to_string()),
            status: ControlStatus::NotImplemented,
            justification: None,
            framework_ids: vec![framework_id],
            owner_id: None,
            vanta_id: None,
            vanta_synced_at: None,
            deleted_at: None,
            created_at: now,
            updated_at: now,
        })
        .collect();

    db.collection::<Control>("controls")
        .insert_many(&controls)
        .await?;

    // 5. Seed default policies (26)
    let policies: Vec<Policy> = DEFAULT_POLICIES
        .iter()
        .map(|seed| Policy {
            id: None,
            org_id,
            name: seed.name.to_string(),
            version: seed.version.to_string(),
            status: PolicyStatus::Draft,
            document_url: None,
            content: Some(seed.description.to_string()),
            approved_by: None,
            approved_at: None,
            vanta_id: None,
            vanta_synced_at: None,
            deleted_at: None,
            created_at: now,
            updated_at: now,
        })
        .collect();

    db.collection::<Policy>("policies")
        .insert_many(&policies)
        .await?;

    tracing::info!(
        org_id = %org_id,
        "System initialized: 1 org, 1 admin, 1 framework, {} controls, {} policies",
        ISO_ANNEX_A_CONTROLS.len(),
        DEFAULT_POLICIES.len()
    );

    // 6. Create JWT
    let expires_secs = parse_expires_in(jwt_expires_in);
    let token = create_token(
        &user_id.to_hex(),
        &admin_req.email,
        Role::SuperAdmin,
        &org_id.to_hex(),
        jwt_secret,
        expires_secs,
    )?;

    // Build response
    let mut org_with_id = org;
    org_with_id.id = Some(org_id);
    let mut user_with_id = user;
    user_with_id.id = Some(user_id);

    Ok(InitializeResponse {
        token,
        user: user_with_id.into(),
        organization: org_with_id.into(),
    })
}
