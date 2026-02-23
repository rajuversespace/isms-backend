use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Compliance test record.
/// Named `TestRecord` to avoid conflict with Rust's built-in `test` keyword.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRecord {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub org_id: ObjectId,
    pub name: String,
    pub category: TestCategory,
    pub owner_id: ObjectId,

    #[serde(rename = "type")]
    pub test_type: TestType,

    pub status: TestStatus,
    pub due_date: DateTime<Utc>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,

    // Linked entities (stored as ObjectId arrays for M:N)
    #[serde(default)]
    pub control_ids: Vec<ObjectId>,
    #[serde(default)]
    pub framework_ids: Vec<ObjectId>,
    #[serde(default)]
    pub evidence_ids: Vec<ObjectId>,
    #[serde(default)]
    pub audit_ids: Vec<ObjectId>,

    // Automated test fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integration_id: Option<ObjectId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_run_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_result: LastResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_result_details: Option<serde_json::Value>,
    #[serde(default)]
    pub auto_remediation_supported: bool,

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
pub enum TestCategory {
    Custom,
    Engineering,
    #[serde(rename = "HR")]
    Hr,
    #[serde(rename = "IT")]
    It,
    Policy,
    Risks,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TestType {
    Document,
    Automated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TestStatus {
    DueSoon,
    NeedsRemediation,
    Ok,
    Overdue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum LastResult {
    Pass,
    Fail,
    Warning,
    #[default]
    #[serde(rename = "Not_Run")]
    NotRun,
}

// ─── DTOs ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateTestRequest {
    pub name: String,
    pub category: TestCategory,
    pub owner_id: String,
    #[serde(rename = "type")]
    pub test_type: TestType,
    pub due_date: String,
    #[serde(default)]
    pub control_ids: Vec<String>,
    #[serde(default)]
    pub framework_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTestRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub status: Option<TestStatus>,
    #[serde(default)]
    pub due_date: Option<String>,
    #[serde(default)]
    pub owner_id: Option<String>,
    #[serde(default)]
    pub last_result: Option<LastResult>,
}

#[derive(Debug, Serialize)]
pub struct TestResponse {
    pub id: String,
    pub name: String,
    pub category: TestCategory,
    pub owner_id: String,
    #[serde(rename = "type")]
    pub test_type: TestType,
    pub status: TestStatus,
    pub due_date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    pub last_result: LastResult,
    pub control_ids: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<TestRecord> for TestResponse {
    fn from(t: TestRecord) -> Self {
        Self {
            id: t.id.map(|oid| oid.to_hex()).unwrap_or_default(),
            name: t.name,
            category: t.category,
            owner_id: t.owner_id.to_hex(),
            test_type: t.test_type,
            status: t.status,
            due_date: t.due_date.to_rfc3339(),
            completed_at: t.completed_at.map(|dt| dt.to_rfc3339()),
            last_result: t.last_result,
            control_ids: t.control_ids.iter().map(|oid| oid.to_hex()).collect(),
            created_at: t.created_at.to_rfc3339(),
            updated_at: t.updated_at.to_rfc3339(),
        }
    }
}
