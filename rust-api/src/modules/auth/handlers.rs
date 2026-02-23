use actix_web::{web, HttpResponse};
use mongodb::Database;

use crate::config::AppConfig;
use crate::errors::AppError;
use crate::middleware::auth::Claims;
use crate::middleware::rbac::{require_permission, Permission};
use crate::models::ApiResponse;

use super::models::{ChangePasswordRequest, LoginRequest, RegisterRequest, UpdateProfileRequest};
use super::services;

/// POST /api/v1/auth/login
///
/// Public endpoint. Authenticate with email + password, receive JWT.
pub async fn login(
    db: web::Data<Database>,
    config: web::Data<AppConfig>,
    body: web::Json<LoginRequest>,
) -> Result<HttpResponse, AppError> {
    let req = body.into_inner();
    let response = services::login(&db, &config, req).await?;

    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

/// POST /api/v1/auth/register
///
/// Protected endpoint. Requires `ManageUsers` permission.
/// Registers a new user in the same organization as the caller.
pub async fn register(
    db: web::Data<Database>,
    config: web::Data<AppConfig>,
    claims: Claims,
    body: web::Json<RegisterRequest>,
) -> Result<HttpResponse, AppError> {
    require_permission(&claims, Permission::ManageUsers)?;

    let org_id = claims.org_object_id()?;
    let req = body.into_inner();
    let response = services::register(&db, &config, org_id, req).await?;

    Ok(HttpResponse::Created().json(ApiResponse::success(response)))
}

/// GET /api/v1/auth/me
///
/// Protected endpoint. Returns the current user's profile and organization.
/// Also re-issues a fresh JWT.
pub async fn get_me(
    db: web::Data<Database>,
    config: web::Data<AppConfig>,
    claims: Claims,
) -> Result<HttpResponse, AppError> {
    let response = services::get_me_with_config(&db, &config, &claims).await?;

    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

/// POST /api/v1/auth/change-password
///
/// Protected endpoint. Change the authenticated user's password.
pub async fn change_password(
    db: web::Data<Database>,
    config: web::Data<AppConfig>,
    claims: Claims,
    body: web::Json<ChangePasswordRequest>,
) -> Result<HttpResponse, AppError> {
    let req = body.into_inner();
    let response = services::change_password(&db, &config, &claims, req).await?;

    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}

/// PUT /api/v1/auth/profile
///
/// Protected endpoint. Update the authenticated user's profile.
pub async fn update_profile(
    db: web::Data<Database>,
    claims: Claims,
    body: web::Json<UpdateProfileRequest>,
) -> Result<HttpResponse, AppError> {
    let req = body.into_inner();
    let response = services::update_profile(&db, &claims, req).await?;

    Ok(HttpResponse::Ok().json(ApiResponse::success(response)))
}
