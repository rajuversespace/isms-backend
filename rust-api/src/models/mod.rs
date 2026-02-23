use serde::Serialize;

// Domain models
pub mod activity_log;
pub mod asset;
pub mod audit;
pub mod control;
pub mod evidence;
pub mod finding;
pub mod framework;
pub mod integration;
pub mod organization;
pub mod policy;
pub mod risk;
pub mod test_record;
pub mod trust_center;
pub mod user;

// Re-export all enums for convenience
pub use activity_log::ActivityLog;
pub use asset::{Asset, AssetStatus, AssetType, ComplianceStatus, DeviceCompliance};
pub use audit::{Audit, AuditControl, AuditControlStatus, AuditSnapshot, AuditStatus, AuditType};
pub use control::{Control, ControlStatus};
pub use evidence::{Evidence, EvidenceType};
pub use finding::{Finding, FindingSeverity, FindingStatus};
pub use framework::{Framework, FrameworkStatus};
pub use integration::Integration;
pub use organization::Organization;
pub use policy::{Policy, PolicyStatus};
pub use risk::{Risk, RiskLevel, RiskStatus, RiskTreatment};
pub use test_record::{LastResult, TestCategory, TestRecord, TestStatus, TestType};
pub use trust_center::*;
pub use user::{User, UserOnboarding};

/// Standard API response envelope.
/// All endpoints return this shape.
#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub data: Option<T>,
    pub error: Option<ApiError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<PaginationMeta>,
}

/// Error object within the API response.
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

/// Pagination metadata for list endpoints.
#[derive(Debug, Serialize)]
pub struct PaginationMeta {
    pub page: u64,
    pub per_page: u64,
    pub total: u64,
    pub total_pages: u64,
}

impl<T: Serialize> ApiResponse<T> {
    /// Wrap a single item in a success response.
    pub fn success(data: T) -> Self {
        Self {
            data: Some(data),
            error: None,
            meta: None,
        }
    }

    /// Wrap a list of items with pagination metadata.
    pub fn paginated(data: T, page: u64, per_page: u64, total: u64) -> Self {
        let total_pages = if per_page > 0 {
            total.div_ceil(per_page)
        } else {
            0
        };

        Self {
            data: Some(data),
            error: None,
            meta: Some(PaginationMeta {
                page,
                per_page,
                total,
                total_pages,
            }),
        }
    }
}

impl ApiResponse<()> {
    /// Create an error response (no data).
    pub fn error(code: &str, message: &str) -> Self {
        Self {
            data: None,
            error: Some(ApiError {
                code: code.to_string(),
                message: message.to_string(),
            }),
            meta: None,
        }
    }
}

/// Common pagination query parameters.
#[derive(Debug, serde::Deserialize)]
pub struct PaginationQuery {
    #[serde(default = "default_page")]
    pub page: u64,
    #[serde(default = "default_per_page")]
    pub per_page: u64,
}

fn default_page() -> u64 {
    1
}
fn default_per_page() -> u64 {
    20
}
