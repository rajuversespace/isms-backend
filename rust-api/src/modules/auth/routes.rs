use actix_web::web;

use super::handlers;

/// Register auth routes under `/api/v1/auth`.
pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            // Public
            .route("/login", web::post().to(handlers::login))
            // Protected (Claims extractor will reject unauthenticated requests)
            .route("/register", web::post().to(handlers::register))
            .route("/me", web::get().to(handlers::get_me))
            .route(
                "/change-password",
                web::post().to(handlers::change_password),
            )
            .route("/profile", web::put().to(handlers::update_profile)),
    );
}
