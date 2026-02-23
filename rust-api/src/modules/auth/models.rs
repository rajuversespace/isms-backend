use serde::{Deserialize, Serialize};

use crate::models::organization::OrganizationResponse;
use crate::models::user::UserResponse;

/// POST /api/v1/auth/login
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// POST /api/v1/auth/register
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub name: Option<String>,
}

/// POST /api/v1/auth/change-password
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// PUT /api/v1/auth/profile
#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    #[serde(default)]
    pub name: Option<String>,
}

/// Response for login/register — returns JWT + user + org.
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserResponse,
    pub organization: OrganizationResponse,
}

/// Simple message response for operations like change-password.
#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}
