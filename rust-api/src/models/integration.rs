use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Third-party integration (GitHub, Google Drive, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Integration {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub org_id: ObjectId,

    /// Provider name (e.g., "GITHUB", "GOOGLE_DRIVE", "VANTA")
    pub provider: String,

    /// AES-256 encrypted access token
    pub access_token: String,

    /// AES-256 encrypted refresh token (Google Drive only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    /// Access token expiry
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Provider-specific metadata (e.g., folder IDs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,

    pub status: IntegrationStatus,
    pub connected_by: ObjectId,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrationStatus {
    Active,
    Disconnected,
}

/// Response DTO — NEVER include access_token or refresh_token.
#[derive(Debug, Serialize)]
pub struct IntegrationResponse {
    pub id: String,
    pub provider: String,
    pub status: IntegrationStatus,
    pub connected_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Integration> for IntegrationResponse {
    fn from(i: Integration) -> Self {
        Self {
            id: i.id.map(|oid| oid.to_hex()).unwrap_or_default(),
            provider: i.provider,
            status: i.status,
            connected_by: i.connected_by.to_hex(),
            metadata: i.metadata,
            created_at: i.created_at.to_rfc3339(),
            updated_at: i.updated_at.to_rfc3339(),
        }
    }
}
