use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Security control mapped to one or more frameworks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Control {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub org_id: ObjectId,

    /// ISO reference code (e.g., "A.5.1", "CC6.1")
    pub code: String,

    pub title: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    pub status: ControlStatus,

    /// Justification for status (especially for NOT_IMPLEMENTED)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,

    /// Framework(s) this control belongs to
    #[serde(default)]
    pub framework_ids: Vec<ObjectId>,

    /// Assigned owner (user ID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<ObjectId>,

    /// Vanta sync fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vanta_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vanta_synced_at: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlStatus {
    Implemented,
    PartiallyImplemented,
    NotImplemented,
}

/// Request to create a control.
#[derive(Debug, Deserialize)]
pub struct CreateControlRequest {
    pub code: String,
    pub title: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub status: Option<ControlStatus>,
    #[serde(default)]
    pub justification: Option<String>,
    #[serde(default)]
    pub framework_ids: Vec<String>,
    #[serde(default)]
    pub owner_id: Option<String>,
}

/// Request to update a control.
#[derive(Debug, Deserialize)]
pub struct UpdateControlRequest {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub status: Option<ControlStatus>,
    #[serde(default)]
    pub justification: Option<String>,
    #[serde(default)]
    pub framework_ids: Option<Vec<String>>,
    #[serde(default)]
    pub owner_id: Option<String>,
}

/// Response DTO for control.
#[derive(Debug, Serialize)]
pub struct ControlResponse {
    pub id: String,
    pub code: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub status: ControlStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    pub framework_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Control> for ControlResponse {
    fn from(c: Control) -> Self {
        Self {
            id: c.id.map(|oid| oid.to_hex()).unwrap_or_default(),
            code: c.code,
            title: c.title,
            description: c.description,
            status: c.status,
            justification: c.justification,
            framework_ids: c.framework_ids.iter().map(|oid| oid.to_hex()).collect(),
            owner_id: c.owner_id.map(|oid| oid.to_hex()),
            created_at: c.created_at.to_rfc3339(),
            updated_at: c.updated_at.to_rfc3339(),
        }
    }
}
