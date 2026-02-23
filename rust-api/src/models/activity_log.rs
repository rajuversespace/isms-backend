use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Immutable audit trail entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivityLog {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub org_id: ObjectId,
    pub user_id: ObjectId,

    /// Action performed (e.g., "CREATE", "UPDATE", "DELETE", "LOGIN")
    pub action: String,

    /// Entity type (e.g., "control", "policy", "audit")
    pub entity: String,

    /// Entity ID affected
    pub entity_id: String,

    /// Optional details/diff
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,

    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ActivityLogResponse {
    pub id: String,
    pub user_id: String,
    pub action: String,
    pub entity: String,
    pub entity_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    pub timestamp: String,
}

impl From<ActivityLog> for ActivityLogResponse {
    fn from(log: ActivityLog) -> Self {
        Self {
            id: log.id.map(|oid| oid.to_hex()).unwrap_or_default(),
            user_id: log.user_id.to_hex(),
            action: log.action,
            entity: log.entity,
            entity_id: log.entity_id,
            details: log.details,
            timestamp: log.timestamp.to_rfc3339(),
        }
    }
}
