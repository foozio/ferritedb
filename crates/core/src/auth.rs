use crate::config::AuthConfig;
use crate::models::{User, UserRole};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params,
};
use rand_core::OsRng;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

/// Authentication service for password hashing and JWT token management
#[derive(Clone)]
pub struct AuthService {
    config: AuthConfig,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    argon2: Argon2<'static>,
}

/// JWT token pair containing access and refresh tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

/// JWT claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,        // User ID
    pub email: String,      // User email
    pub role: UserRole,     // User role
    pub exp: i64,          // Expiration time
    pub iat: i64,          // Issued at
    pub jti: String,       // JWT ID
    pub token_type: TokenType,
}

/// Token type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TokenType {
    #[serde(rename = "access")]
    Access,
    #[serde(rename = "refresh")]
    Refresh,
}

impl fmt::Display for TokenType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenType::Access => write!(f, "access"),
            TokenType::Refresh => write!(f, "refresh"),
        }
    }
}

/// Authentication errors
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Token expired")]
    TokenExpired,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Password hashing failed: {0}")]
    PasswordHashError(String),
    #[error("Token generation failed: {0}")]
    TokenGenerationError(String),
    #[error("Token validation failed: {0}")]
    TokenValidationError(String),
    #[error("Weak password: {0}")]
    WeakPassword(String),
}

impl AuthService {
    /// Create a new authentication service with the given configuration
    pub fn new(config: AuthConfig) -> Result<Self, AuthError> {
        let encoding_key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(config.jwt_secret.as_bytes());

        // Configure Argon2 with secure parameters
        let params = Params::new(
            config.argon2_memory,
            config.argon2_iterations,
            config.argon2_parallelism,
            None,
        )
        .map_err(|e| AuthError::PasswordHashError(e.to_string()))?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

        Ok(Self {
            config,
            encoding_key,
            decoding_key,
            argon2,
        })
    }

    /// Hash a password using Argon2id with secure parameters
    pub fn hash_password(&self, password: &str) -> Result<String, AuthError> {
        // Validate password strength
        self.validate_password_strength(password)?;

        let salt = SaltString::generate(&mut OsRng);
        let password_hash = self
            .argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::PasswordHashError(e.to_string()))?;

        Ok(password_hash.to_string())
    }

    /// Verify a password against its hash
    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool, AuthError> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| AuthError::PasswordHashError(e.to_string()))?;

        match self.argon2.verify_password(password.as_bytes(), &parsed_hash) {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(AuthError::PasswordHashError(e.to_string())),
        }
    }

    /// Generate JWT token pair (access + refresh) for a user
    pub fn generate_tokens(&self, user: &User) -> Result<AuthToken, AuthError> {
        let now = Utc::now();
        let access_exp = now + Duration::seconds(self.config.token_ttl as i64);
        let refresh_exp = now + Duration::seconds(self.config.refresh_ttl as i64);

        // Generate access token
        let access_claims = Claims {
            sub: user.id.to_string(),
            email: user.email.clone(),
            role: user.role.clone(),
            exp: access_exp.timestamp(),
            iat: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            token_type: TokenType::Access,
        };

        let access_token = encode(&Header::default(), &access_claims, &self.encoding_key)
            .map_err(|e| AuthError::TokenGenerationError(e.to_string()))?;

        // Generate refresh token
        let refresh_claims = Claims {
            sub: user.id.to_string(),
            email: user.email.clone(),
            role: user.role.clone(),
            exp: refresh_exp.timestamp(),
            iat: now.timestamp(),
            jti: Uuid::new_v4().to_string(),
            token_type: TokenType::Refresh,
        };

        let refresh_token = encode(&Header::default(), &refresh_claims, &self.encoding_key)
            .map_err(|e| AuthError::TokenGenerationError(e.to_string()))?;

        Ok(AuthToken {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: self.config.token_ttl as i64,
        })
    }

    /// Validate and decode a JWT token
    pub fn validate_token(&self, token: &str) -> Result<Claims, AuthError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.validate_nbf = false;

        let token_data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                _ => AuthError::TokenValidationError(e.to_string()),
            })?;

        Ok(token_data.claims)
    }

    /// Refresh an access token using a valid refresh token
    pub fn refresh_token(&self, refresh_token: &str, user: &User) -> Result<AuthToken, AuthError> {
        let claims = self.validate_token(refresh_token)?;

        // Verify it's a refresh token
        if claims.token_type != TokenType::Refresh {
            return Err(AuthError::InvalidToken);
        }

        // Verify the token belongs to the user
        if claims.sub != user.id.to_string() {
            return Err(AuthError::InvalidToken);
        }

        // Generate new token pair
        self.generate_tokens(user)
    }

    /// Extract user ID from a token without full validation (for middleware)
    pub fn extract_user_id(&self, token: &str) -> Result<Uuid, AuthError> {
        let claims = self.validate_token(token)?;
        
        // Only allow access tokens for API requests
        if claims.token_type != TokenType::Access {
            return Err(AuthError::InvalidToken);
        }

        Uuid::parse_str(&claims.sub)
            .map_err(|_| AuthError::InvalidToken)
    }

    /// Validate password strength according to security requirements
    fn validate_password_strength(&self, password: &str) -> Result<(), AuthError> {
        if password.len() < self.config.password_min_length {
            return Err(AuthError::WeakPassword(format!(
                "Password must be at least {} characters long",
                self.config.password_min_length
            )));
        }

        // Check for at least one uppercase, lowercase, digit, and special character
        let has_upper = password.chars().any(|c| c.is_uppercase());
        let has_lower = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());

        if !has_upper {
            return Err(AuthError::WeakPassword(
                "Password must contain at least one uppercase letter".to_string(),
            ));
        }

        if !has_lower {
            return Err(AuthError::WeakPassword(
                "Password must contain at least one lowercase letter".to_string(),
            ));
        }

        if !has_digit {
            return Err(AuthError::WeakPassword(
                "Password must contain at least one digit".to_string(),
            ));
        }

        if !has_special {
            return Err(AuthError::WeakPassword(
                "Password must contain at least one special character".to_string(),
            ));
        }

        Ok(())
    }
}

/// Request structures for authentication endpoints
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub password_confirm: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

/// Response structures for authentication endpoints
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub user: UserResponse,
    pub token: AuthToken,
}

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub user: UserResponse,
    pub token: AuthToken,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub role: UserRole,
    pub verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            role: user.role,
            verified: user.verified,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}
#[
cfg(test)]
mod tests {
    use super::*;
    use crate::models::UserRole;

    fn create_test_auth_service() -> AuthService {
        let config = AuthConfig {
            jwt_secret: "test-secret-key-for-testing-only".to_string(),
            token_ttl: 900,
            refresh_ttl: 86400,
            password_min_length: 8,
            argon2_memory: 4096, // Reduced for testing
            argon2_iterations: 1, // Reduced for testing
            argon2_parallelism: 1,
        };
        AuthService::new(config).unwrap()
    }

    fn create_test_user() -> User {
        User::new(
            "test@example.com".to_string(),
            "hashed_password".to_string(),
            UserRole::User,
        )
    }

    #[test]
    fn test_auth_service_creation() {
        let auth_service = create_test_auth_service();
        assert_eq!(auth_service.config.token_ttl, 900);
        assert_eq!(auth_service.config.refresh_ttl, 86400);
    }

    #[test]
    fn test_password_hashing() {
        let auth_service = create_test_auth_service();
        let password = "TestPassword123!";
        
        let hash = auth_service.hash_password(password).unwrap();
        assert!(!hash.is_empty());
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn test_password_verification() {
        let auth_service = create_test_auth_service();
        let password = "TestPassword123!";
        
        let hash = auth_service.hash_password(password).unwrap();
        
        // Correct password should verify
        assert!(auth_service.verify_password(password, &hash).unwrap());
        
        // Wrong password should not verify
        assert!(!auth_service.verify_password("WrongPassword123!", &hash).unwrap());
    }

    #[test]
    fn test_password_strength_validation() {
        let auth_service = create_test_auth_service();
        
        // Too short
        assert!(auth_service.hash_password("Short1!").is_err());
        
        // Missing uppercase
        assert!(auth_service.hash_password("lowercase123!").is_err());
        
        // Missing lowercase
        assert!(auth_service.hash_password("UPPERCASE123!").is_err());
        
        // Missing digit
        assert!(auth_service.hash_password("NoDigits!").is_err());
        
        // Missing special character
        assert!(auth_service.hash_password("NoSpecial123").is_err());
        
        // Valid password
        assert!(auth_service.hash_password("ValidPass123!").is_ok());
    }

    #[test]
    fn test_token_generation() {
        let auth_service = create_test_auth_service();
        let user = create_test_user();
        
        let tokens = auth_service.generate_tokens(&user).unwrap();
        
        assert!(!tokens.access_token.is_empty());
        assert!(!tokens.refresh_token.is_empty());
        assert_eq!(tokens.token_type, "Bearer");
        assert_eq!(tokens.expires_in, 900);
    }

    #[test]
    fn test_token_validation() {
        let auth_service = create_test_auth_service();
        let user = create_test_user();
        
        let tokens = auth_service.generate_tokens(&user).unwrap();
        
        // Validate access token
        let claims = auth_service.validate_token(&tokens.access_token).unwrap();
        assert_eq!(claims.sub, user.id.to_string());
        assert_eq!(claims.email, user.email);
        assert_eq!(claims.role, user.role);
        assert_eq!(claims.token_type, TokenType::Access);
        
        // Validate refresh token
        let refresh_claims = auth_service.validate_token(&tokens.refresh_token).unwrap();
        assert_eq!(refresh_claims.token_type, TokenType::Refresh);
    }

    #[test]
    fn test_invalid_token_validation() {
        let auth_service = create_test_auth_service();
        
        // Invalid token format
        assert!(auth_service.validate_token("invalid.token.format").is_err());
        
        // Empty token
        assert!(auth_service.validate_token("").is_err());
    }

    #[test]
    fn test_user_id_extraction() {
        let auth_service = create_test_auth_service();
        let user = create_test_user();
        
        let tokens = auth_service.generate_tokens(&user).unwrap();
        
        // Extract from access token should work
        let extracted_id = auth_service.extract_user_id(&tokens.access_token).unwrap();
        assert_eq!(extracted_id, user.id);
        
        // Extract from refresh token should fail (wrong token type)
        assert!(auth_service.extract_user_id(&tokens.refresh_token).is_err());
    }

    #[test]
    fn test_token_refresh() {
        let auth_service = create_test_auth_service();
        let user = create_test_user();
        
        let original_tokens = auth_service.generate_tokens(&user).unwrap();
        
        // Refresh using valid refresh token
        let new_tokens = auth_service
            .refresh_token(&original_tokens.refresh_token, &user)
            .unwrap();
        
        assert!(!new_tokens.access_token.is_empty());
        assert!(!new_tokens.refresh_token.is_empty());
        assert_ne!(new_tokens.access_token, original_tokens.access_token);
        assert_ne!(new_tokens.refresh_token, original_tokens.refresh_token);
    }

    #[test]
    fn test_refresh_with_access_token_fails() {
        let auth_service = create_test_auth_service();
        let user = create_test_user();
        
        let tokens = auth_service.generate_tokens(&user).unwrap();
        
        // Try to refresh using access token (should fail)
        assert!(auth_service
            .refresh_token(&tokens.access_token, &user)
            .is_err());
    }

    #[test]
    fn test_refresh_with_wrong_user_fails() {
        let auth_service = create_test_auth_service();
        let user1 = create_test_user();
        let mut user2 = create_test_user();
        user2.id = Uuid::new_v4(); // Different user
        
        let tokens = auth_service.generate_tokens(&user1).unwrap();
        
        // Try to refresh with different user (should fail)
        assert!(auth_service
            .refresh_token(&tokens.refresh_token, &user2)
            .is_err());
    }

    #[test]
    fn test_token_type_display() {
        assert_eq!(TokenType::Access.to_string(), "access");
        assert_eq!(TokenType::Refresh.to_string(), "refresh");
    }

    #[test]
    fn test_user_response_conversion() {
        let user = create_test_user();
        let user_response = UserResponse::from(user.clone());
        
        assert_eq!(user_response.id, user.id);
        assert_eq!(user_response.email, user.email);
        assert_eq!(user_response.role, user.role);
        assert_eq!(user_response.verified, user.verified);
        assert_eq!(user_response.created_at, user.created_at);
        assert_eq!(user_response.updated_at, user.updated_at);
    }

    #[test]
    fn test_auth_error_display() {
        let error = AuthError::InvalidCredentials;
        assert_eq!(error.to_string(), "Invalid credentials");
        
        let error = AuthError::TokenExpired;
        assert_eq!(error.to_string(), "Token expired");
        
        let error = AuthError::WeakPassword("Too short".to_string());
        assert_eq!(error.to_string(), "Weak password: Too short");
    }
}