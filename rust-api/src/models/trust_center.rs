use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Trust center settings for an organization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustCenterSettings {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub org_id: ObjectId,

    #[serde(default)]
    pub enabled: bool,

    /// URL slug (e.g., "bitcoin-com") for public URL: /trust/:slug
    pub org_slug: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,

    #[serde(default = "default_primary_color")]
    pub primary_color: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_email: Option<String>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn default_primary_color() -> String {
    "#2563eb".to_string()
}

/// Trust center document (publicly shared).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustDocument {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub org_id: ObjectId,
    pub name: String,
    pub category: TrustDocumentCategory,
    pub file_url: String,

    #[serde(default)]
    pub requires_nda: bool,
    #[serde(default)]
    pub public_visible: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    pub uploaded_by: ObjectId,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustDocumentCategory {
    Policy,
    Report,
    Certificate,
    Whitepaper,
    Other,
}

/// Access request for a trust center document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAccessRequest {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub org_id: ObjectId,
    pub requester_name: String,
    pub requester_email: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub company: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_id: Option<ObjectId>,

    pub status: TrustAccessStatus,

    #[serde(default)]
    pub nda_signed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_by: Option<ObjectId>,

    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustAccessStatus {
    Pending,
    Approved,
    Rejected,
}

/// Trust center announcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustAnnouncement {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub org_id: ObjectId,
    pub title: String,
    pub content: String,

    #[serde(rename = "type")]
    pub announcement_type: TrustAnnouncementType,

    #[serde(default)]
    pub published: bool,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustAnnouncementType {
    SecurityUpdate,
    Incident,
    Certification,
    General,
}

/// Trust center questionnaire request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustQuestionnaireRequest {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub org_id: ObjectId,
    pub requester_email: String,

    #[serde(default = "default_questionnaire_type")]
    pub questionnaire_type: String,

    #[serde(default = "default_questionnaire_status")]
    pub status: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_file_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,

    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responded_at: Option<DateTime<Utc>>,
}

fn default_questionnaire_type() -> String {
    "STANDARD".to_string()
}
fn default_questionnaire_status() -> String {
    "PENDING".to_string()
}

/// Compliance metrics snapshot for trust center display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustMetricsSnapshot {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub org_id: ObjectId,
    pub framework_name: String,
    pub compliance_percentage: f64,
    pub control_count: i32,
    pub completed_controls: i32,
    pub snapshot_date: DateTime<Utc>,
}
