use crate::errors::AppError;

/// Hash a plain-text password using bcrypt.
///
/// Cost factor is configurable (default 12, matching the legacy TypeScript backend).
pub fn hash_password(password: &str, cost: u32) -> Result<String, AppError> {
    bcrypt::hash(password, cost)
        .map_err(|e| AppError::Internal(format!("Password hashing failed: {}", e)))
}

/// Verify a plain-text password against a bcrypt hash.
///
/// Returns `Ok(())` if the password matches, or `Err(AppError::Unauthorized)` if not.
pub fn verify_password(password: &str, hash: &str) -> Result<(), AppError> {
    let valid = bcrypt::verify(password, hash)
        .map_err(|e| AppError::Internal(format!("Password verification failed: {}", e)))?;

    if valid {
        Ok(())
    } else {
        Err(AppError::Unauthorized("Invalid credentials".into()))
    }
}

/// Validate password strength.
/// Requirements (matching legacy TypeScript backend):
/// - Minimum 8 characters
pub fn validate_password(password: &str) -> Result<(), AppError> {
    if password.len() < 8 {
        return Err(AppError::BadRequest(
            "Password must be at least 8 characters".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_password() {
        let password = "secure-password-123";
        // Use cost 4 for fast tests (12 is production default)
        let hash = hash_password(password, 4).expect("hashing should succeed");

        assert!(verify_password(password, &hash).is_ok());
        assert!(verify_password("wrong-password", &hash).is_err());
    }

    #[test]
    fn test_validate_password_too_short() {
        assert!(validate_password("short").is_err());
        assert!(validate_password("1234567").is_err());
    }

    #[test]
    fn test_validate_password_valid() {
        assert!(validate_password("12345678").is_ok());
        assert!(validate_password("a-very-long-and-secure-password").is_ok());
    }

    #[test]
    fn test_hash_produces_different_hashes() {
        let password = "same-password";
        let hash1 = hash_password(password, 4).unwrap();
        let hash2 = hash_password(password, 4).unwrap();
        // bcrypt uses random salt, so hashes should differ
        assert_ne!(hash1, hash2);
        // But both should verify
        assert!(verify_password(password, &hash1).is_ok());
        assert!(verify_password(password, &hash2).is_ok());
    }
}
