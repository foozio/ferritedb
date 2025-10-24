use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

pub type ServerResult<T> = Result<T, ServerError>;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("Core error: {0}")]
    Core(#[from] ferritedb_core::CoreError),

    #[error("Authentication error: {0}")]
    Auth(#[from] ferritedb_core::auth::AuthError),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("WebSocket error: {0}")]
    WebSocket(String),

    #[error("Middleware error: {0}")]
    Middleware(String),
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ServerError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ServerError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            ServerError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            ServerError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            ServerError::Auth(auth_err) => match auth_err {
                ferritedb_core::auth::AuthError::InvalidCredentials => {
                    (StatusCode::UNAUTHORIZED, "Invalid credentials".to_string())
                }
                ferritedb_core::auth::AuthError::TokenExpired => {
                    (StatusCode::UNAUTHORIZED, "Token expired".to_string())
                }
                ferritedb_core::auth::AuthError::InvalidToken => {
                    (StatusCode::UNAUTHORIZED, "Invalid token".to_string())
                }
                ferritedb_core::auth::AuthError::WeakPassword(msg) => {
                    (StatusCode::BAD_REQUEST, format!("Weak password: {}", msg))
                }
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Authentication error".to_string(),
                ),
            },
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        };

        let body = Json(json!({
            "error": error_message,
            "status": status.as_u16()
        }));

        (status, body).into_response()
    }
}
