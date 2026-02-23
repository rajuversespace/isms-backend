use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct InitializeRequest {
    pub organization: OrganizationSetup,
    pub admin: AdminSetup,
}

#[derive(Debug, Deserialize)]
pub struct OrganizationSetup {
    pub name: String,
    #[serde(default)]
    pub domain: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AdminSetup {
    pub name: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct SetupStatusResponse {
    pub can_setup: bool,
}

#[derive(Debug, Serialize)]
pub struct InitializeResponse {
    pub token: String,
    pub user: crate::models::user::UserResponse,
    pub organization: crate::models::organization::OrganizationResponse,
}
