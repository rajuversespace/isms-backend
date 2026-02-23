use actix_cors::Cors;
use actix_web::{App, HttpResponse, HttpServer, middleware as actix_mw, web};
use tracing_actix_web::TracingLogger;

mod config;
mod db;
mod errors;
mod middleware;
mod models;
mod modules;
mod seed;

/// Health check endpoint: GET /health
async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "service": "isms-api",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load .env file (ignore if missing)
    dotenvy::dotenv().ok();

    // Initialize tracing/logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Load configuration
    let app_config = config::AppConfig::from_env();
    let bind_addr = format!("{}:{}", app_config.host, app_config.port);

    tracing::info!("Starting ISMS API server on {}", bind_addr,);

    // Connect to MongoDB
    let db = db::connect(&app_config.mongodb_uri, &app_config.mongodb_database)
        .await
        .expect("Failed to connect to MongoDB");

    tracing::info!(
        "Connected to MongoDB database: {}",
        app_config.mongodb_database
    );

    // Create indexes
    db::create_indexes(&db)
        .await
        .expect("Failed to create database indexes");

    tracing::info!("Database indexes created");

    // Store shared state
    let db_data = web::Data::new(db);
    let config_data = web::Data::new(app_config.clone());

    // Start HTTP server
    HttpServer::new(move || {
        // CORS configuration
        let cors = Cors::default()
            .allowed_origin(&app_config.cors_origin)
            .allowed_methods(vec!["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
            .allowed_headers(vec![
                actix_web::http::header::CONTENT_TYPE,
                actix_web::http::header::AUTHORIZATION,
                actix_web::http::header::ACCEPT,
            ])
            .supports_credentials()
            .max_age(3600);

        App::new()
            // Middleware
            .wrap(TracingLogger::default())
            .wrap(cors)
            .wrap(actix_mw::Compress::default())
            // Shared state
            .app_data(db_data.clone())
            .app_data(config_data.clone())
            // Health check (no auth required)
            .route("/health", web::get().to(health_check))
            // API v1 routes
            .service(
                web::scope("/api/v1")
                    .configure(modules::setup::routes::config)
                    .configure(modules::auth::routes::config),
            )
    })
    .bind(&bind_addr)?
    .run()
    .await
}
