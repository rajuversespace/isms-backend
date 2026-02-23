use actix_web::{web, HttpResponse};
use mongodb::Database;

use crate::config::AppConfig;
use crate::errors::AppError;
use crate::models::ApiResponse;

use super::models::InitializeRequest;
use super::services;

/// GET /api/v1/setup/status
///
/// Returns whether the system can still be initialized (no orgs exist yet).
/// This is a public endpoint — no auth required.
pub async fn get_status(db: web::Data<Database>) -> Result<HttpResponse, AppError> {
    let can_setup = services::can_setup(&db).await?;

    Ok(HttpResponse::Ok().json(ApiResponse::success(
        super::models::SetupStatusResponse { can_setup },
    )))
}

/// POST /api/v1/setup/initialize
///
/// One-time system initialization. Creates the first organization, admin user,
/// ISO 27001 framework, seeds 93 controls and 26 policies, and returns a JWT.
///
/// This is a public endpoint — no auth required (but only works once).
pub async fn initialize(
    db: web::Data<Database>,
    config: web::Data<AppConfig>,
    body: web::Json<InitializeRequest>,
) -> Result<HttpResponse, AppError> {
    let req = body.into_inner();

    let response = services::initialize(
        &db,
        req.organization,
        req.admin,
        &config.jwt_secret,
        &config.jwt_expires_in,
        config.bcrypt_cost,
    )
    .await?;

    Ok(HttpResponse::Created().json(ApiResponse::success(response)))
}
