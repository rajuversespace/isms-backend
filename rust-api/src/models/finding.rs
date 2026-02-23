use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Audit finding — an issue discovered during an audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub org_id: ObjectId,
    pub audit_id: ObjectId,
    pub control_id: ObjectId,

    pub severity: FindingSeverity,
    pub status: FindingStatus,
    pub description: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation_plan: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub due_date: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_to: Option<ObjectId>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingSeverity {
    Minor,
    Major,
    Observation,
    /// Opportunity for Improvement
    Ofi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingStatus {
    Open,
    InRemediation,
    ReadyForReview,
    Closed,
}

#[derive(Debug, Deserialize)]
pub struct CreateFindingRequest {
    pub audit_id: String,
    pub control_id: String,
    pub severity: FindingSeverity,
    pub description: String,
    #[serde(default)]
    pub remediation_plan: Option<String>,
    #[serde(default)]
    pub due_date: Option<String>,
    #[serde(default)]
    pub assigned_to: Option<String>,
    #[serde(default)]
    pub evidence_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateFindingRequest {
    #[serde(default)]
    pub severity: Option<FindingSeverity>,
    #[serde(default)]
    pub status: Option<FindingStatus>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub remediation_plan: Option<String>,
    #[serde(default)]
    pub due_date: Option<String>,
    #[serde(default)]
    pub assigned_to: Option<String>,
    #[serde(default)]
    pub evidence_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FindingResponse {
    pub id: String,
    pub audit_id: String,
    pub control_id: String,
    pub severity: FindingSeverity,
    pub status: FindingStatus,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation_plan: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub due_date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<String>,
    pub created_at: String,
}

impl From<Finding> for FindingResponse {
    fn from(f: Finding) -> Self {
        Self {
            id: f.id.map(|oid| oid.to_hex()).unwrap_or_default(),
            audit_id: f.audit_id.to_hex(),
            control_id: f.control_id.to_hex(),
            severity: f.severity,
            status: f.status,
            description: f.description,
            remediation_plan: f.remediation_plan,
            due_date: f.due_date.map(|dt| dt.to_rfc3339()),
            assigned_to: f.assigned_to.map(|oid| oid.to_hex()),
            evidence_url: f.evidence_url,
            closed_at: f.closed_at.map(|dt| dt.to_rfc3339()),
            created_at: f.created_at.to_rfc3339(),
        }
    }
}
