use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;
use std::fmt;

/// Application error type.
/// All service/handler errors are converted to this type.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("MongoDB error: {0}")]
    Database(#[from] mongodb::error::Error),

    #[error("BSON serialization error: {0}")]
    BsonSer(#[from] bson::ser::Error),

    #[error("BSON deserialization error: {0}")]
    BsonDe(#[from] bson::de::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Error response body sent to clients.
/// Never exposes internal details.
#[derive(Debug, Serialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

impl fmt::Display for ErrorBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        // Log the full error server-side
        tracing::error!("AppError: {:?}", self);

        match self {
            AppError::NotFound(msg) => HttpResponse::NotFound()
                .json(crate::models::ApiResponse::<()>::error("NOT_FOUND", msg)),
            AppError::BadRequest(msg) => HttpResponse::BadRequest()
                .json(crate::models::ApiResponse::<()>::error("BAD_REQUEST", msg)),
            AppError::Unauthorized(msg) => HttpResponse::Unauthorized()
                .json(crate::models::ApiResponse::<()>::error("UNAUTHORIZED", msg)),
            AppError::Forbidden(msg) => HttpResponse::Forbidden()
                .json(crate::models::ApiResponse::<()>::error("FORBIDDEN", msg)),
            AppError::Conflict(msg) => HttpResponse::Conflict()
                .json(crate::models::ApiResponse::<()>::error("CONFLICT", msg)),
            // All other errors: return generic 500, never expose internals
            _ => HttpResponse::InternalServerError().json(crate::models::ApiResponse::<()>::error(
                "INTERNAL_ERROR",
                "An internal error occurred",
            )),
        }
    }
}
