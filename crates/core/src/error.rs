use thiserror::Error;

pub type CoreResult<T> = Result<T, CoreError>;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    #[error("UUID error: {0}")]
    Uuid(#[from] uuid::Error),

    #[error("Authentication failed: {0}")]
    Authentication(String),

    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    #[error("Authorization failed: {0}")]
    Authorization(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Collection not found: {0}")]
    CollectionNotFound(String),

    #[error("Collection already exists: {0}")]
    CollectionAlreadyExists(String),

    #[error("Field not found: {0}")]
    FieldNotFound(String),

    #[error("Field already exists: {0}")]
    FieldAlreadyExists(String),

    #[error("Record not found: {0}")]
    RecordNotFound(String),

    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("Configuration error: {0}")]
    Configuration(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Password hashing error: {0}")]
    PasswordHash(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl CoreError {
    pub fn authentication<S: Into<String>>(msg: S) -> Self {
        Self::Authentication(msg.into())
    }

    pub fn authentication_error<S: Into<String>>(msg: S) -> Self {
        Self::AuthenticationError(msg.into())
    }

    pub fn authorization<S: Into<String>>(msg: S) -> Self {
        Self::Authorization(msg.into())
    }

    pub fn validation<S: Into<String>>(msg: S) -> Self {
        Self::Validation(msg.into())
    }

    pub fn configuration<S: Into<String>>(msg: S) -> Self {
        Self::Configuration(msg.into())
    }

    pub fn password_hash<S: Into<String>>(msg: S) -> Self {
        Self::PasswordHash(msg.into())
    }

    pub fn internal<S: Into<String>>(msg: S) -> Self {
        Self::Internal(msg.into())
    }
}
