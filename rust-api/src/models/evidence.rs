use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Evidence document attached to a control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub org_id: ObjectId,
    pub control_id: ObjectId,

    #[serde(rename = "type")]
    pub evidence_type: EvidenceType,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_url: Option<String>,

    /// SHA-256 hash of the file content
    pub hash: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub collected_by: Option<ObjectId>,

    #[serde(default)]
    pub automated: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceType {
    File,
    Link,
    Screenshot,
    Log,
    Automated,
}

#[derive(Debug, Deserialize)]
pub struct CreateEvidenceRequest {
    pub control_id: String,
    #[serde(rename = "type")]
    pub evidence_type: EvidenceType,
    #[serde(default)]
    pub file_name: Option<String>,
    #[serde(default)]
    pub file_url: Option<String>,
    pub hash: String,
    #[serde(default)]
    pub automated: bool,
}

#[derive(Debug, Serialize)]
pub struct EvidenceResponse {
    pub id: String,
    pub control_id: String,
    #[serde(rename = "type")]
    pub evidence_type: EvidenceType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_url: Option<String>,
    pub hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collected_by: Option<String>,
    pub automated: bool,
    pub created_at: String,
}

impl From<Evidence> for EvidenceResponse {
    fn from(e: Evidence) -> Self {
        Self {
            id: e.id.map(|oid| oid.to_hex()).unwrap_or_default(),
            control_id: e.control_id.to_hex(),
            evidence_type: e.evidence_type,
            file_name: e.file_name,
            file_url: e.file_url,
            hash: e.hash,
            collected_by: e.collected_by.map(|oid| oid.to_hex()),
            automated: e.automated,
            created_at: e.created_at.to_rfc3339(),
        }
    }
}
