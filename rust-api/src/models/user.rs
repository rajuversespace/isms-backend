use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::middleware::rbac::Role;

/// User document stored in MongoDB `users` collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub email: String,

    /// Bcrypt hash. None for SSO-only users.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Google OAuth ID (for SSO login).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    pub role: Role,
    pub org_id: ObjectId,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Onboarding progress — embedded or separate collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserOnboarding {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub user_id: ObjectId,
    pub org_id: ObjectId,

    /// Task 1: Accept all policies
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_accepted_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_version_accepted: Option<String>,

    /// Task 2: MDM enrollment
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mdm_enrolled_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,

    /// Task 3: Security training
    #[serde(skip_serializing_if = "Option::is_none")]
    pub training_started_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub training_completed_at: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to register a new user.
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub name: Option<String>,
}

/// Request to update user (admin).
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub role: Option<Role>,
}

/// Response DTO — NEVER include password hash.
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub role: Role,
    pub org_id: String,
    pub created_at: String,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id.map(|oid| oid.to_hex()).unwrap_or_default(),
            email: user.email,
            name: user.name,
            role: user.role,
            org_id: user.org_id.to_hex(),
            created_at: user.created_at.to_rfc3339(),
        }
    }
}
