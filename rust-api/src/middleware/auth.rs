use actix_web::{FromRequest, HttpRequest, dev::Payload};
use bson::oid::ObjectId;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::future::{Ready, ready};

use super::rbac::Role;
use crate::errors::AppError;

/// JWT claims payload stored inside every token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — the user's ID (ObjectId hex string)
    pub sub: String,
    /// User's email address
    pub email: String,
    /// User's role
    pub role: Role,
    /// Organization ID (ObjectId hex string)
    pub org_id: String,
    /// Expiration time (UTC timestamp)
    pub exp: usize,
    /// Issued at (UTC timestamp)
    pub iat: usize,
}

impl Claims {
    /// Parse `org_id` string into a BSON ObjectId.
    pub fn org_object_id(&self) -> Result<ObjectId, AppError> {
        ObjectId::parse_str(&self.org_id)
            .map_err(|_| AppError::Internal("Invalid org_id in token".into()))
    }

    /// Parse `sub` (user ID) string into a BSON ObjectId.
    pub fn user_object_id(&self) -> Result<ObjectId, AppError> {
        ObjectId::parse_str(&self.sub)
            .map_err(|_| AppError::Internal("Invalid user id in token".into()))
    }
}

/// Create a signed JWT token from the given claims.
pub fn create_token(
    user_id: &str,
    email: &str,
    role: Role,
    org_id: &str,
    secret: &str,
    expires_in_secs: u64,
) -> Result<String, AppError> {
    let now = chrono::Utc::now().timestamp() as usize;
    let claims = Claims {
        sub: user_id.to_string(),
        email: email.to_string(),
        role,
        org_id: org_id.to_string(),
        exp: now + expires_in_secs as usize,
        iat: now,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| AppError::Internal(format!("Failed to create token: {}", e)))
}

/// Verify and decode a JWT token, returning the claims.
pub fn verify_token(token: &str, secret: &str) -> Result<Claims, AppError> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
            AppError::Unauthorized("Token expired".into())
        }
        jsonwebtoken::errors::ErrorKind::InvalidToken => {
            AppError::Unauthorized("Invalid token".into())
        }
        _ => AppError::Unauthorized(format!("Token validation failed: {}", e)),
    })?;

    Ok(token_data.claims)
}

/// Parse the "expires_in" config string (e.g. "24h", "7d", "3600") into seconds.
pub fn parse_expires_in(value: &str) -> u64 {
    let trimmed = value.trim();

    if let Some(hours) = trimmed.strip_suffix('h') {
        return hours.parse::<u64>().unwrap_or(24) * 3600;
    }
    if let Some(days) = trimmed.strip_suffix('d') {
        return days.parse::<u64>().unwrap_or(1) * 86400;
    }
    if let Some(minutes) = trimmed.strip_suffix('m') {
        return minutes.parse::<u64>().unwrap_or(60) * 60;
    }

    // Default: try parsing as raw seconds
    trimmed.parse::<u64>().unwrap_or(86400)
}

/// Extract the Bearer token from the Authorization header.
fn extract_bearer_token(req: &HttpRequest) -> Result<String, AppError> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".into()))?
        .to_str()
        .map_err(|_| AppError::Unauthorized("Invalid Authorization header".into()))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Unauthorized(
            "Authorization header must use Bearer scheme".into(),
        ));
    }

    Ok(auth_header[7..].to_string())
}

/// Actix-web extractor that validates the JWT and provides `Claims` to handlers.
///
/// Usage in a handler:
/// ```ignore
/// async fn my_handler(claims: Claims) -> Result<HttpResponse, AppError> {
///     let org_id = claims.org_object_id()?;
///     // ...
/// }
/// ```
impl FromRequest for Claims {
    type Error = AppError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let result = (|| {
            let token = extract_bearer_token(req)?;

            // Get the JWT secret from app data
            let config = req
                .app_data::<actix_web::web::Data<crate::config::AppConfig>>()
                .ok_or_else(|| AppError::Internal("App config not found".into()))?;

            verify_token(&token, &config.jwt_secret)
        })();

        ready(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_verify_token() {
        let secret = "test-secret-key";
        let token = create_token(
            "507f1f77bcf86cd799439011",
            "user@example.com",
            Role::Admin,
            "507f1f77bcf86cd799439012",
            secret,
            3600,
        )
        .expect("token creation should succeed");

        let claims = verify_token(&token, secret).expect("token verification should succeed");

        assert_eq!(claims.sub, "507f1f77bcf86cd799439011");
        assert_eq!(claims.email, "user@example.com");
        assert_eq!(claims.role, Role::Admin);
        assert_eq!(claims.org_id, "507f1f77bcf86cd799439012");
    }

    #[test]
    fn test_verify_token_wrong_secret() {
        let token = create_token(
            "507f1f77bcf86cd799439011",
            "user@example.com",
            Role::Viewer,
            "507f1f77bcf86cd799439012",
            "correct-secret",
            3600,
        )
        .expect("token creation should succeed");

        let result = verify_token(&token, "wrong-secret");
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_expired_token() {
        let secret = "test-secret";
        // Manually create a token that expired 2 minutes ago (past the 60s leeway)
        let now = chrono::Utc::now().timestamp() as usize;
        let claims = Claims {
            sub: "507f1f77bcf86cd799439011".to_string(),
            email: "user@example.com".to_string(),
            role: Role::Viewer,
            org_id: "507f1f77bcf86cd799439012".to_string(),
            exp: now - 120, // expired 2 minutes ago
            iat: now - 3720,
        };

        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("encoding should succeed");

        let result = verify_token(&token, secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_expires_in() {
        assert_eq!(parse_expires_in("24h"), 86400);
        assert_eq!(parse_expires_in("1h"), 3600);
        assert_eq!(parse_expires_in("7d"), 604800);
        assert_eq!(parse_expires_in("30m"), 1800);
        assert_eq!(parse_expires_in("3600"), 3600);
    }

    #[test]
    fn test_claims_object_id_parsing() {
        let claims = Claims {
            sub: "507f1f77bcf86cd799439011".to_string(),
            email: "test@test.com".to_string(),
            role: Role::Admin,
            org_id: "507f1f77bcf86cd799439012".to_string(),
            exp: 9999999999,
            iat: 1000000000,
        };

        assert!(claims.user_object_id().is_ok());
        assert!(claims.org_object_id().is_ok());

        let bad_claims = Claims {
            sub: "not-an-objectid".to_string(),
            email: "test@test.com".to_string(),
            role: Role::Admin,
            org_id: "also-bad".to_string(),
            exp: 9999999999,
            iat: 1000000000,
        };

        assert!(bad_claims.user_object_id().is_err());
        assert!(bad_claims.org_object_id().is_err());
    }
}
