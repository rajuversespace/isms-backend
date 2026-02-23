use actix_web::web;

use super::handlers;

/// Register setup routes under `/api/v1/setup`.
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/setup")
            .route("/status", web::get().to(handlers::get_status))
            .route("/initialize", web::post().to(handlers::initialize)),
    );
}
