use actix_web::{FromRequest, HttpRequest, dev::Payload};
use serde::{Deserialize, Serialize};
use std::future::{Ready, ready};

use super::auth::Claims;
use crate::errors::AppError;

// ─── Roles ───────────────────────────────────────────────────────────────────

/// User roles ordered from highest to lowest privilege.
/// Matches the legacy TypeScript backend exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Role {
    SuperAdmin,
    #[serde(rename = "ORG_ADMIN")]
    Admin,
    SecurityOwner,
    Auditor,
    Contributor,
    Viewer,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::SuperAdmin => write!(f, "SUPER_ADMIN"),
            Role::Admin => write!(f, "ORG_ADMIN"),
            Role::SecurityOwner => write!(f, "SECURITY_OWNER"),
            Role::Auditor => write!(f, "AUDITOR"),
            Role::Contributor => write!(f, "CONTRIBUTOR"),
            Role::Viewer => write!(f, "VIEWER"),
        }
    }
}

// ─── Permissions ─────────────────────────────────────────────────────────────

/// All 23 permissions used across the ISMS platform.
/// Format: `action:resource`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    // Organization
    ReadOrg,
    WriteOrg,
    ManageUsers,

    // Users
    ReadUsers,
    WriteUsers,
    DeleteUsers,

    // Assets
    ReadAssets,
    WriteAssets,
    DeleteAssets,

    // Risks
    ReadRisks,
    WriteRisks,
    DeleteRisks,
    ApproveRisks,

    // Controls
    ReadControls,
    WriteControls,
    DeleteControls,

    // Evidence
    ReadEvidence,
    WriteEvidence,
    DeleteEvidence,

    // Policies
    ReadPolicies,
    WritePolicies,
    ApprovePolicies,

    // Audits
    ReadAudits,
    WriteAudits,
    ApproveAudits,
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Permission::ReadOrg => "read:org",
            Permission::WriteOrg => "write:org",
            Permission::ManageUsers => "manage:users",
            Permission::ReadUsers => "read:users",
            Permission::WriteUsers => "write:users",
            Permission::DeleteUsers => "delete:users",
            Permission::ReadAssets => "read:assets",
            Permission::WriteAssets => "write:assets",
            Permission::DeleteAssets => "delete:assets",
            Permission::ReadRisks => "read:risks",
            Permission::WriteRisks => "write:risks",
            Permission::DeleteRisks => "delete:risks",
            Permission::ApproveRisks => "approve:risks",
            Permission::ReadControls => "read:controls",
            Permission::WriteControls => "write:controls",
            Permission::DeleteControls => "delete:controls",
            Permission::ReadEvidence => "read:evidence",
            Permission::WriteEvidence => "write:evidence",
            Permission::DeleteEvidence => "delete:evidence",
            Permission::ReadPolicies => "read:policies",
            Permission::WritePolicies => "write:policies",
            Permission::ApprovePolicies => "approve:policies",
            Permission::ReadAudits => "read:audits",
            Permission::WriteAudits => "write:audits",
            Permission::ApproveAudits => "approve:audits",
        };
        write!(f, "{}", s)
    }
}

// ─── Role → Permission Mapping ───────────────────────────────────────────────

/// Returns the list of permissions granted to a given role.
/// Mirrors the legacy TypeScript `rolePermissions` map exactly.
pub fn role_permissions(role: Role) -> &'static [Permission] {
    use Permission::*;

    match role {
        Role::SuperAdmin => &[
            // SUPER_ADMIN gets ALL permissions
            ReadOrg,
            WriteOrg,
            ManageUsers,
            ReadUsers,
            WriteUsers,
            DeleteUsers,
            ReadAssets,
            WriteAssets,
            DeleteAssets,
            ReadRisks,
            WriteRisks,
            DeleteRisks,
            ApproveRisks,
            ReadControls,
            WriteControls,
            DeleteControls,
            ReadEvidence,
            WriteEvidence,
            DeleteEvidence,
            ReadPolicies,
            WritePolicies,
            ApprovePolicies,
            ReadAudits,
            WriteAudits,
            ApproveAudits,
        ],
        Role::Admin => &[
            ReadOrg,
            WriteOrg,
            ManageUsers,
            ReadUsers,
            ReadAssets,
            WriteAssets,
            DeleteAssets,
            ReadRisks,
            WriteRisks,
            DeleteRisks,
            ReadControls,
            WriteControls,
            DeleteControls,
            ReadEvidence,
            WriteEvidence,
            DeleteEvidence,
            ReadPolicies,
            WritePolicies,
            ApprovePolicies,
            ReadAudits,
            WriteAudits,
            ApproveAudits,
        ],
        Role::SecurityOwner => &[
            ReadAssets,
            WriteAssets,
            ReadRisks,
            WriteRisks,
            ApproveRisks,
            ReadControls,
            WriteControls,
            ReadEvidence,
            WriteEvidence,
            ReadPolicies,
            WritePolicies,
            ReadAudits,
            WriteAudits,
        ],
        Role::Auditor => &[
            ReadAssets,
            ReadRisks,
            ReadControls,
            ReadEvidence,
            WriteEvidence,
            ReadPolicies,
            ReadAudits,
            WriteAudits,
        ],
        Role::Contributor => &[
            ReadAssets,
            ReadRisks,
            WriteRisks,
            ReadControls,
            WriteControls,
            ReadEvidence,
            WriteEvidence,
            ReadPolicies,
            ReadAudits,
        ],
        Role::Viewer => &[
            ReadAssets,
            ReadRisks,
            ReadControls,
            ReadEvidence,
            ReadPolicies,
            ReadAudits,
        ],
    }
}

/// Check if a role has a specific permission.
pub fn has_permission(role: Role, permission: Permission) -> bool {
    role_permissions(role).contains(&permission)
}

// ─── Permission Guard (Actix-web extractor) ──────────────────────────────────

/// A wrapper around `Claims` that also verifies a required permission.
///
/// Usage: Create a factory function per-endpoint that returns a configured guard.
///
/// Example in routes:
/// ```ignore
/// use actix_web::web;
///
/// web::scope("/controls")
///     .route("", web::get().to(handlers::list))    // handler extracts Claims directly
///     .route("", web::post().to(handlers::create))  // handler uses RequirePermission
/// ```
///
/// Example in handler:
/// ```ignore
/// use crate::middleware::rbac::{Permission, require_permission};
///
/// async fn create_control(
///     claims: Claims,
///     db: web::Data<Database>,
///     body: web::Json<CreateControlRequest>,
/// ) -> Result<HttpResponse, AppError> {
///     require_permission(&claims, Permission::WriteControls)?;
///     // ... proceed with creation
/// }
/// ```
pub fn require_permission(claims: &Claims, permission: Permission) -> Result<(), AppError> {
    if has_permission(claims.role, permission) {
        Ok(())
    } else {
        tracing::warn!(
            user_id = %claims.sub,
            role = %claims.role,
            permission = %permission,
            "Permission denied"
        );
        Err(AppError::Forbidden(format!(
            "Insufficient permissions: {} required",
            permission
        )))
    }
}

/// Require that the authenticated user has a specific role (or is SUPER_ADMIN).
pub fn require_role(claims: &Claims, required_role: Role) -> Result<(), AppError> {
    if claims.role == required_role || claims.role == Role::SuperAdmin {
        Ok(())
    } else {
        tracing::warn!(
            user_id = %claims.sub,
            role = %claims.role,
            required_role = %required_role,
            "Role check failed"
        );
        Err(AppError::Forbidden(format!(
            "Role {} required",
            required_role
        )))
    }
}

/// Optional auth extractor — returns `Option<Claims>`.
/// Does not reject the request if no token is provided.
/// Useful for endpoints that behave differently for authenticated vs anonymous users
/// (e.g., trust center public pages).
pub struct OptionalAuth(pub Option<Claims>);

impl FromRequest for OptionalAuth {
    type Error = AppError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
        match Claims::from_request(req, payload).into_inner() {
            Ok(claims) => ready(Ok(OptionalAuth(Some(claims)))),
            Err(_) => ready(Ok(OptionalAuth(None))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_super_admin_has_all_permissions() {
        // SUPER_ADMIN should have every permission
        assert!(has_permission(Role::SuperAdmin, Permission::ReadOrg));
        assert!(has_permission(Role::SuperAdmin, Permission::WriteOrg));
        assert!(has_permission(Role::SuperAdmin, Permission::ManageUsers));
        assert!(has_permission(Role::SuperAdmin, Permission::DeleteUsers));
        assert!(has_permission(Role::SuperAdmin, Permission::ApproveRisks));
        assert!(has_permission(Role::SuperAdmin, Permission::ApproveAudits));
        assert!(has_permission(
            Role::SuperAdmin,
            Permission::ApprovePolicies
        ));
    }

    #[test]
    fn test_admin_permissions() {
        assert!(has_permission(Role::Admin, Permission::ReadOrg));
        assert!(has_permission(Role::Admin, Permission::WriteOrg));
        assert!(has_permission(Role::Admin, Permission::ManageUsers));
        assert!(has_permission(Role::Admin, Permission::ReadUsers));
        assert!(has_permission(Role::Admin, Permission::ApproveAudits));
        // Admin does NOT have ApproveRisks (only SecurityOwner + SuperAdmin)
        assert!(!has_permission(Role::Admin, Permission::ApproveRisks));
    }

    #[test]
    fn test_security_owner_permissions() {
        assert!(has_permission(
            Role::SecurityOwner,
            Permission::ApproveRisks
        ));
        assert!(has_permission(Role::SecurityOwner, Permission::WriteAssets));
        assert!(has_permission(Role::SecurityOwner, Permission::WriteAudits));
        // Cannot manage users or org
        assert!(!has_permission(
            Role::SecurityOwner,
            Permission::ManageUsers
        ));
        assert!(!has_permission(Role::SecurityOwner, Permission::WriteOrg));
        assert!(!has_permission(
            Role::SecurityOwner,
            Permission::DeleteAssets
        ));
    }

    #[test]
    fn test_auditor_permissions() {
        assert!(has_permission(Role::Auditor, Permission::ReadAssets));
        assert!(has_permission(Role::Auditor, Permission::WriteAudits));
        assert!(has_permission(Role::Auditor, Permission::WriteEvidence));
        // Auditor cannot write controls or risks
        assert!(!has_permission(Role::Auditor, Permission::WriteControls));
        assert!(!has_permission(Role::Auditor, Permission::WriteRisks));
        assert!(!has_permission(Role::Auditor, Permission::DeleteAssets));
    }

    #[test]
    fn test_contributor_permissions() {
        assert!(has_permission(Role::Contributor, Permission::WriteRisks));
        assert!(has_permission(Role::Contributor, Permission::WriteControls));
        assert!(has_permission(Role::Contributor, Permission::WriteEvidence));
        // Contributor cannot approve or delete
        assert!(!has_permission(Role::Contributor, Permission::ApproveRisks));
        assert!(!has_permission(Role::Contributor, Permission::DeleteAssets));
        assert!(!has_permission(Role::Contributor, Permission::WriteAudits));
    }

    #[test]
    fn test_viewer_is_read_only() {
        assert!(has_permission(Role::Viewer, Permission::ReadAssets));
        assert!(has_permission(Role::Viewer, Permission::ReadRisks));
        assert!(has_permission(Role::Viewer, Permission::ReadControls));
        assert!(has_permission(Role::Viewer, Permission::ReadEvidence));
        assert!(has_permission(Role::Viewer, Permission::ReadPolicies));
        assert!(has_permission(Role::Viewer, Permission::ReadAudits));
        // Viewer cannot write anything
        assert!(!has_permission(Role::Viewer, Permission::WriteAssets));
        assert!(!has_permission(Role::Viewer, Permission::WriteRisks));
        assert!(!has_permission(Role::Viewer, Permission::WriteControls));
        assert!(!has_permission(Role::Viewer, Permission::WriteEvidence));
        assert!(!has_permission(Role::Viewer, Permission::WritePolicies));
        assert!(!has_permission(Role::Viewer, Permission::WriteAudits));
    }

    #[test]
    fn test_role_serialization() {
        assert_eq!(
            serde_json::to_string(&Role::SuperAdmin).unwrap(),
            "\"SUPER_ADMIN\""
        );
        assert_eq!(
            serde_json::to_string(&Role::Admin).unwrap(),
            "\"ORG_ADMIN\""
        );
        assert_eq!(
            serde_json::to_string(&Role::SecurityOwner).unwrap(),
            "\"SECURITY_OWNER\""
        );
        assert_eq!(
            serde_json::to_string(&Role::Auditor).unwrap(),
            "\"AUDITOR\""
        );
        assert_eq!(
            serde_json::to_string(&Role::Contributor).unwrap(),
            "\"CONTRIBUTOR\""
        );
        assert_eq!(serde_json::to_string(&Role::Viewer).unwrap(), "\"VIEWER\"");
    }

    #[test]
    fn test_role_deserialization() {
        let admin: Role = serde_json::from_str("\"ORG_ADMIN\"").unwrap();
        assert_eq!(admin, Role::Admin);

        let super_admin: Role = serde_json::from_str("\"SUPER_ADMIN\"").unwrap();
        assert_eq!(super_admin, Role::SuperAdmin);
    }

    #[test]
    fn test_require_permission_success() {
        let claims = Claims {
            sub: "507f1f77bcf86cd799439011".to_string(),
            email: "admin@test.com".to_string(),
            role: Role::Admin,
            org_id: "507f1f77bcf86cd799439012".to_string(),
            exp: 9999999999,
            iat: 1000000000,
        };

        assert!(require_permission(&claims, Permission::ReadOrg).is_ok());
        assert!(require_permission(&claims, Permission::WriteOrg).is_ok());
    }

    #[test]
    fn test_require_permission_denied() {
        let claims = Claims {
            sub: "507f1f77bcf86cd799439011".to_string(),
            email: "viewer@test.com".to_string(),
            role: Role::Viewer,
            org_id: "507f1f77bcf86cd799439012".to_string(),
            exp: 9999999999,
            iat: 1000000000,
        };

        assert!(require_permission(&claims, Permission::WriteAssets).is_err());
        assert!(require_permission(&claims, Permission::DeleteAssets).is_err());
    }

    #[test]
    fn test_require_role_super_admin_bypass() {
        let claims = Claims {
            sub: "507f1f77bcf86cd799439011".to_string(),
            email: "super@test.com".to_string(),
            role: Role::SuperAdmin,
            org_id: "507f1f77bcf86cd799439012".to_string(),
            exp: 9999999999,
            iat: 1000000000,
        };

        // SuperAdmin should pass any role check
        assert!(require_role(&claims, Role::Admin).is_ok());
        assert!(require_role(&claims, Role::Auditor).is_ok());
        assert!(require_role(&claims, Role::Viewer).is_ok());
    }

    #[test]
    fn test_require_role_mismatch() {
        let claims = Claims {
            sub: "507f1f77bcf86cd799439011".to_string(),
            email: "viewer@test.com".to_string(),
            role: Role::Viewer,
            org_id: "507f1f77bcf86cd799439012".to_string(),
            exp: 9999999999,
            iat: 1000000000,
        };

        assert!(require_role(&claims, Role::Admin).is_err());
        assert!(require_role(&claims, Role::Viewer).is_ok());
    }
}
