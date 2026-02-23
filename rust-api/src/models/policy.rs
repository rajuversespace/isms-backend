use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Policy document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub org_id: ObjectId,
    pub name: String,

    #[serde(default = "default_version")]
    pub version: String,

    pub status: PolicyStatus,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<ObjectId>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<DateTime<Utc>>,

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

fn default_version() -> String {
    "1.0".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyStatus {
    Draft,
    Approved,
    Archived,
}

#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub document_url: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePolicyRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub status: Option<PolicyStatus>,
    #[serde(default)]
    pub document_url: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PolicyResponse {
    pub id: String,
    pub name: String,
    pub version: String,
    pub status: PolicyStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Policy> for PolicyResponse {
    fn from(p: Policy) -> Self {
        Self {
            id: p.id.map(|oid| oid.to_hex()).unwrap_or_default(),
            name: p.name,
            version: p.version,
            status: p.status,
            document_url: p.document_url,
            approved_by: p.approved_by.map(|oid| oid.to_hex()),
            approved_at: p.approved_at.map(|dt| dt.to_rfc3339()),
            created_at: p.created_at.to_rfc3339(),
            updated_at: p.updated_at.to_rfc3339(),
        }
    }
}
