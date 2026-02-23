use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Compliance framework (e.g., ISO 27001:2022, SOC 2 Type II).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Framework {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub org_id: ObjectId,
    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    pub status: FrameworkStatus,

    /// Computed compliance metrics
    #[serde(default)]
    pub total_controls: i32,
    #[serde(default)]
    pub implemented_controls: i32,
    #[serde(default)]
    pub compliance_percentage: f64,

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
pub enum FrameworkStatus {
    Active,
    Inactive,
    Draft,
    Archived,
}

/// Request to create a framework.
#[derive(Debug, Deserialize)]
pub struct CreateFrameworkRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}

/// Request to update a framework.
#[derive(Debug, Deserialize)]
pub struct UpdateFrameworkRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub status: Option<FrameworkStatus>,
}

/// Response DTO for framework.
#[derive(Debug, Serialize)]
pub struct FrameworkResponse {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub status: FrameworkStatus,
    pub total_controls: i32,
    pub implemented_controls: i32,
    pub compliance_percentage: f64,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Framework> for FrameworkResponse {
    fn from(fw: Framework) -> Self {
        Self {
            id: fw.id.map(|oid| oid.to_hex()).unwrap_or_default(),
            name: fw.name,
            description: fw.description,
            version: fw.version,
            status: fw.status,
            total_controls: fw.total_controls,
            implemented_controls: fw.implemented_controls,
            compliance_percentage: fw.compliance_percentage,
            created_at: fw.created_at.to_rfc3339(),
            updated_at: fw.updated_at.to_rfc3339(),
        }
    }
}
