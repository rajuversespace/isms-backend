use bson::oid::ObjectId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// IT asset (device, application, cloud resource, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub org_id: ObjectId,
    pub name: String,

    #[serde(rename = "type")]
    pub asset_type: AssetType,

    pub owner_id: ObjectId,
    pub criticality: super::risk::RiskLevel,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    pub status: AssetStatus,

    // Endpoint-specific fields (MDM)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<DateTime<Utc>>,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssetType {
    Cloud,
    Application,
    Database,
    Saas,
    Endpoint,
    Network,
    Repository,
    Vendor,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssetStatus {
    Active,
    Inactive,
    Retired,
}

/// Device compliance snapshot (embedded or separate collection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCompliance {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub asset_id: ObjectId,

    #[serde(default)]
    pub disk_encryption_enabled: bool,
    #[serde(default)]
    pub screen_lock_enabled: bool,
    #[serde(default)]
    pub firewall_enabled: bool,
    #[serde(default)]
    pub antivirus_enabled: bool,
    #[serde(default)]
    pub system_integrity_enabled: bool,
    #[serde(default)]
    pub auto_update_enabled: bool,
    #[serde(default)]
    pub gatekeeper_enabled: bool,

    pub compliance_status: ComplianceStatus,
    pub last_checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComplianceStatus {
    Compliant,
    NonCompliant,
    Unknown,
}

// ─── DTOs ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateAssetRequest {
    pub name: String,
    #[serde(rename = "type")]
    pub asset_type: AssetType,
    pub owner_id: String,
    pub criticality: super::risk::RiskLevel,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAssetRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, rename = "type")]
    pub asset_type: Option<AssetType>,
    #[serde(default)]
    pub criticality: Option<super::risk::RiskLevel>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub status: Option<AssetStatus>,
    #[serde(default)]
    pub owner_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AssetResponse {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub asset_type: AssetType,
    pub owner_id: String,
    pub criticality: super::risk::RiskLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub status: AssetStatus,
    pub created_at: String,
    pub updated_at: String,
}

impl From<Asset> for AssetResponse {
    fn from(a: Asset) -> Self {
        Self {
            id: a.id.map(|oid| oid.to_hex()).unwrap_or_default(),
            name: a.name,
            asset_type: a.asset_type,
            owner_id: a.owner_id.to_hex(),
            criticality: a.criticality,
            description: a.description,
            status: a.status,
            created_at: a.created_at.to_rfc3339(),
            updated_at: a.updated_at.to_rfc3339(),
        }
    }
}
