use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Risk register entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Risk {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub org_id: ObjectId,
    pub title: String,
    pub description: String,

    pub impact: RiskLevel,
    pub likelihood: RiskLevel,
    pub risk_score: i32,
    pub status: RiskStatus,

    pub asset_id: ObjectId,

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

/// Risk treatment — links a risk to a control.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskTreatment {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub risk_id: ObjectId,
    pub control_id: ObjectId,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskStatus {
    Open,
    Mitigated,
    Accepted,
    Transferred,
}

// ─── DTOs ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateRiskRequest {
    pub title: String,
    pub description: String,
    pub impact: RiskLevel,
    pub likelihood: RiskLevel,
    pub asset_id: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRiskRequest {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub impact: Option<RiskLevel>,
    #[serde(default)]
    pub likelihood: Option<RiskLevel>,
    #[serde(default)]
    pub status: Option<RiskStatus>,
}

#[derive(Debug, Serialize)]
pub struct RiskResponse {
    pub id: String,
    pub title: String,
    pub description: String,
    pub impact: RiskLevel,
    pub likelihood: RiskLevel,
    pub risk_score: i32,
    pub status: RiskStatus,
    pub asset_id: String,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Risk> for RiskResponse {
    fn from(r: Risk) -> Self {
        Self {
            id: r.id.map(|oid| oid.to_hex()).unwrap_or_default(),
            title: r.title,
            description: r.description,
            impact: r.impact,
            likelihood: r.likelihood,
            risk_score: r.risk_score,
            status: r.status,
            asset_id: r.asset_id.to_hex(),
            created_at: r.created_at.to_rfc3339(),
            updated_at: r.updated_at.to_rfc3339(),
        }
    }
}
