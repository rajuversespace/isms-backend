use std::env;

/// Application configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct AppConfig {
    // Server
    pub host: String,
    pub port: u16,

    // MongoDB
    pub mongodb_uri: String,
    pub mongodb_database: String,

    // JWT
    pub jwt_secret: String,
    pub jwt_expires_in: String,

    // CORS
    pub cors_origin: String,

    // Bcrypt
    pub bcrypt_cost: u32,

    // Vanta (optional)
    pub vanta_client_id: Option<String>,
    pub vanta_client_secret: Option<String>,
}

impl AppConfig {
    /// Load configuration from environment variables.
    /// Panics on missing required variables (fail fast at startup).
    pub fn from_env() -> Self {
        Self {
            host: env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            port: env::var("PORT")
                .unwrap_or_else(|_| "8080".to_string())
                .parse::<u16>()
                .expect("PORT must be a valid u16"),
            mongodb_uri: env::var("MONGODB_URI")
                .unwrap_or_else(|_| "mongodb://localhost:27017".to_string()),
            mongodb_database: env::var("MONGODB_DATABASE").unwrap_or_else(|_| "isms".to_string()),
            jwt_secret: env::var("JWT_SECRET")
                .unwrap_or_else(|_| "dev-secret-change-in-production".to_string()),
            jwt_expires_in: env::var("JWT_EXPIRES_IN").unwrap_or_else(|_| "24h".to_string()),
            cors_origin: env::var("CORS_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:5173".to_string()),
            bcrypt_cost: env::var("BCRYPT_COST")
                .unwrap_or_else(|_| "12".to_string())
                .parse::<u32>()
                .expect("BCRYPT_COST must be a valid u32"),
            vanta_client_id: env::var("VANTA_CLIENT_ID").ok(),
            vanta_client_secret: env::var("VANTA_CLIENT_SECRET").ok(),
        }
    }
}
