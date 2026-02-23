use bson::doc;
use bson::oid::ObjectId;
use chrono::Utc;
use mongodb::Database;

use crate::config::AppConfig;
use crate::errors::AppError;
use crate::middleware::auth::{create_token, parse_expires_in, Claims};
use crate::middleware::password::{hash_password, validate_password, verify_password};
use crate::middleware::rbac::Role;
use crate::models::organization::Organization;
use crate::models::user::User;

use super::models::{
    AuthResponse, ChangePasswordRequest, LoginRequest, MessageResponse, RegisterRequest,
    UpdateProfileRequest,
};

/// Authenticate a user by email + password and return a JWT.
pub async fn login(db: &Database, config: &AppConfig, req: LoginRequest) -> Result<AuthResponse, AppError> {
    // Find user by email
    let user = db
        .collection::<User>("users")
        .find_one(doc! { "email": &req.email, "deleted_at": null })
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid credentials".into()))?;

    // Verify password
    let password_hash = user
        .password
        .as_ref()
        .ok_or_else(|| AppError::Unauthorized("This account uses SSO login".into()))?;

    verify_password(&req.password, password_hash)?;

    // Look up the organization
    let org = db
        .collection::<Organization>("organizations")
        .find_one(doc! { "_id": user.org_id, "deleted_at": null })
        .await?
        .ok_or_else(|| AppError::Internal("User's organization not found".into()))?;

    // Create JWT
    let user_id = user.id.ok_or_else(|| AppError::Internal("User has no ID".into()))?;
    let expires_secs = parse_expires_in(&config.jwt_expires_in);
    let token = create_token(
        &user_id.to_hex(),
        &user.email,
        user.role,
        &user.org_id.to_hex(),
        &config.jwt_secret,
        expires_secs,
    )?;

    Ok(AuthResponse {
        token,
        user: user.into(),
        organization: org.into(),
    })
}

/// Register a new user within the same organization as the inviter.
/// Only SUPER_ADMIN, ADMIN, or SECURITY_OWNER can register new users (enforced in handler via RBAC).
/// New users default to VIEWER role.
pub async fn register(
    db: &Database,
    config: &AppConfig,
    org_id: ObjectId,
    req: RegisterRequest,
) -> Result<AuthResponse, AppError> {
    // Validate password strength
    validate_password(&req.password)?;

    // Check for existing user with same email
    let existing = db
        .collection::<User>("users")
        .find_one(doc! { "email": &req.email })
        .await?;

    if existing.is_some() {
        return Err(AppError::Conflict(
            "A user with this email already exists".into(),
        ));
    }

    // Verify the organization exists
    let org = db
        .collection::<Organization>("organizations")
        .find_one(doc! { "_id": org_id, "deleted_at": null })
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    let now = Utc::now();
    let password_hash = hash_password(&req.password, config.bcrypt_cost)?;

    let user = User {
        id: None,
        email: req.email.clone(),
        password: Some(password_hash),
        google_id: None,
        name: req.name,
        role: Role::Viewer, // New registrations default to Viewer
        org_id,
        deleted_at: None,
        created_at: now,
        updated_at: now,
    };

    let result = db
        .collection::<User>("users")
        .insert_one(&user)
        .await?;

    let user_id = result
        .inserted_id
        .as_object_id()
        .ok_or_else(|| AppError::Internal("Failed to get user ID".into()))?;

    // Create JWT for the new user
    let expires_secs = parse_expires_in(&config.jwt_expires_in);
    let token = create_token(
        &user_id.to_hex(),
        &req.email,
        Role::Viewer,
        &org_id.to_hex(),
        &config.jwt_secret,
        expires_secs,
    )?;

    let mut user_with_id = user;
    user_with_id.id = Some(user_id);

    Ok(AuthResponse {
        token,
        user: user_with_id.into(),
        organization: org.into(),
    })
}

/// Get the currently authenticated user and their organization.
pub async fn get_me_with_config(
    db: &Database,
    config: &AppConfig,
    claims: &Claims,
) -> Result<AuthResponse, AppError> {
    let user_id = claims.user_object_id()?;
    let org_id = claims.org_object_id()?;

    let user = db
        .collection::<User>("users")
        .find_one(doc! { "_id": user_id, "deleted_at": null })
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    let org = db
        .collection::<Organization>("organizations")
        .find_one(doc! { "_id": org_id, "deleted_at": null })
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".into()))?;

    // Re-issue a fresh token
    let expires_secs = parse_expires_in(&config.jwt_expires_in);
    let token = create_token(
        &claims.sub,
        &claims.email,
        claims.role,
        &claims.org_id,
        &config.jwt_secret,
        expires_secs,
    )?;

    Ok(AuthResponse {
        token,
        user: user.into(),
        organization: org.into(),
    })
}

/// Change the authenticated user's password.
pub async fn change_password(
    db: &Database,
    config: &AppConfig,
    claims: &Claims,
    req: ChangePasswordRequest,
) -> Result<MessageResponse, AppError> {
    let user_id = claims.user_object_id()?;

    // Find the user
    let user = db
        .collection::<User>("users")
        .find_one(doc! { "_id": user_id, "deleted_at": null })
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    // Verify current password
    let current_hash = user
        .password
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("This account uses SSO — no password to change".into()))?;

    verify_password(&req.current_password, current_hash)?;

    // Validate new password
    validate_password(&req.new_password)?;

    // Hash and update
    let new_hash = hash_password(&req.new_password, config.bcrypt_cost)?;
    let now = Utc::now();

    db.collection::<User>("users")
        .update_one(
            doc! { "_id": user_id },
            doc! { "$set": { "password": new_hash, "updated_at": bson::to_bson(&now).unwrap() } },
        )
        .await?;

    Ok(MessageResponse {
        message: "Password changed successfully".to_string(),
    })
}

/// Update the authenticated user's profile (name only for now).
pub async fn update_profile(
    db: &Database,
    claims: &Claims,
    req: UpdateProfileRequest,
) -> Result<crate::models::user::UserResponse, AppError> {
    let user_id = claims.user_object_id()?;
    let now = Utc::now();

    let mut update_doc = doc! {
        "updated_at": bson::to_bson(&now).unwrap()
    };

    if let Some(ref name) = req.name {
        update_doc.insert("name", name);
    }

    db.collection::<User>("users")
        .update_one(
            doc! { "_id": user_id, "deleted_at": null },
            doc! { "$set": update_doc },
        )
        .await?;

    // Fetch and return updated user
    let user = db
        .collection::<User>("users")
        .find_one(doc! { "_id": user_id })
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".into()))?;

    Ok(user.into())
}
