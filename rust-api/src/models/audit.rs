use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Compliance audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Audit {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub org_id: ObjectId,
    pub name: String,

    #[serde(rename = "type")]
    pub audit_type: AuditType,

    /// Framework name (e.g., "ISO 27001:2022")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub period_start: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub period_end: Option<DateTime<Utc>>,

    pub start_date: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_date: Option<DateTime<Utc>>,

    pub status: AuditStatus,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_auditor_id: Option<ObjectId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_auditor_email: Option<String>,

    pub owner_id: ObjectId,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<DateTime<Utc>>,

    // Final report fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executive_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_conclusion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_pdf_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_by_id: Option<ObjectId>,
    #[serde(default)]
    pub is_locked: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditType {
    Internal,
    External,
    Surveillance,
    Recertification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditStatus {
    Draft,
    Planned,
    InProgress,
    Completed,
}

/// Per-control review status within an audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditControl {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub audit_id: ObjectId,
    pub control_id: ObjectId,

    pub review_status: AuditControlStatus,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_by: Option<ObjectId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditControlStatus {
    Pending,
    Compliant,
    NonCompliant,
    NotApplicable,
}

/// Immutable metrics snapshot captured at audit completion time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSnapshot {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub audit_id: ObjectId,
    pub org_id: ObjectId,
    pub captured_at: DateTime<Utc>,

    // Control metrics
    pub total_controls: i32,
    pub compliant_controls: i32,
    pub non_compliant_controls: i32,
    pub not_applicable_controls: i32,
    pub pending_controls: i32,
    pub compliance_pct: f64,

    // Finding metrics
    pub total_findings: i32,
    pub open_findings: i32,
    pub closed_findings: i32,
    pub major_findings: i32,
    pub minor_findings: i32,
    pub observation_findings: i32,
    pub ofi_findings: i32,

    // Risk summary
    #[serde(default)]
    pub critical_risks: i32,
    #[serde(default)]
    pub high_risks: i32,
    #[serde(default)]
    pub medium_risks: i32,
    #[serde(default)]
    pub low_risks: i32,
}

// ─── Request/Response DTOs ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateAuditRequest {
    pub name: String,
    #[serde(rename = "type")]
    pub audit_type: AuditType,
    #[serde(default)]
    pub framework_name: Option<String>,
    pub start_date: String,
    #[serde(default)]
    pub end_date: Option<String>,
    #[serde(default)]
    pub period_start: Option<String>,
    #[serde(default)]
    pub period_end: Option<String>,
    #[serde(default)]
    pub assigned_auditor_id: Option<String>,
    #[serde(default)]
    pub external_auditor_email: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAuditRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub status: Option<AuditStatus>,
    #[serde(default)]
    pub end_date: Option<String>,
    #[serde(default)]
    pub executive_summary: Option<String>,
    #[serde(default)]
    pub audit_conclusion: Option<String>,
    #[serde(default)]
    pub assigned_auditor_id: Option<String>,
    #[serde(default)]
    pub external_auditor_email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuditResponse {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub audit_type: AuditType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework_name: Option<String>,
    pub status: AuditStatus,
    pub start_date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_date: Option<String>,
    pub owner_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_auditor_id: Option<String>,
    pub is_locked: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Audit> for AuditResponse {
    fn from(a: Audit) -> Self {
        Self {
            id: a.id.map(|oid| oid.to_hex()).unwrap_or_default(),
            name: a.name,
            audit_type: a.audit_type,
            framework_name: a.framework_name,
            status: a.status,
            start_date: a.start_date.to_rfc3339(),
            end_date: a.end_date.map(|dt| dt.to_rfc3339()),
            owner_id: a.owner_id.to_hex(),
            assigned_auditor_id: a.assigned_auditor_id.map(|oid| oid.to_hex()),
            is_locked: a.is_locked,
            created_at: a.created_at.to_rfc3339(),
            updated_at: a.updated_at.to_rfc3339(),
        }
    }
}
