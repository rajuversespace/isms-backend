use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Organization — the top-level tenant.
/// Every other entity is scoped to an organization via `org_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub name: String,

    /// Optional domain (e.g., "bitcoin.com")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,

    /// Vanta organization ID (if synced)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vanta_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create an organization.
#[derive(Debug, Deserialize)]
pub struct CreateOrganizationRequest {
    pub name: String,
    #[serde(default)]
    pub domain: Option<String>,
}

/// Response DTO for organization.
#[derive(Debug, Serialize)]
pub struct OrganizationResponse {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    pub created_at: String,
}

impl From<Organization> for OrganizationResponse {
    fn from(org: Organization) -> Self {
        Self {
            id: org.id.map(|oid| oid.to_hex()).unwrap_or_default(),
            name: org.name,
            domain: org.domain,
            created_at: org.created_at.to_rfc3339(),
        }
    }
}
