use axum::{
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::Response,
};
use ferritedb_core::{
    auth::{AuthService, Claims},
    models::{User, UserRole},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

// Re-export security modules
pub use crate::csrf::{CsrfConfig, CsrfTokenStore, csrf_protection_middleware, create_csrf_cookie, CsrfTokenResponse};
pub use crate::security::{SecurityConfig, CookieSecurityConfig, security_headers_middleware, request_size_limit_middleware, CookieSecurityUtils, IpSecurityConfig, extract_real_ip, is_ip_blocked};
pub use crate::validation::{ValidationConfig, input_validation_middleware, RequestSanitizer};

/// Authentication state that gets added to request extensions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
    pub role: UserRole,
    pub verified: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<&User> for AuthUser {
    fn from(user: &User) -> Self {
        Self {
            id: user.id,
            email: user.email.clone(),
            role: user.role.clone(),
            verified: user.verified,
            created_at: user.created_at,
            updated_at: user.updated_at,
        }
    }
}

impl From<&Claims> for AuthUser {
    fn from(claims: &Claims) -> Self {
        Self {
            id: Uuid::parse_str(&claims.sub).unwrap_or_default(),
            email: claims.email.clone(),
            role: claims.role.clone(),
            verified: true, // Assume verified if they have a valid JWT
            created_at: chrono::DateTime::from_timestamp(claims.iat, 0).unwrap_or_default(),
            updated_at: chrono::DateTime::from_timestamp(claims.iat, 0).unwrap_or_default(),
        }
    }
}

/// Authentication middleware that validates JWT tokens
pub async fn auth_middleware(
    State(auth_service): State<Arc<AuthService>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    let token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            header.strip_prefix("Bearer ").unwrap_or("")
        }
        _ => return Err(StatusCode::UNAUTHORIZED),
    };

    // Validate token
    let claims = match auth_service.validate_token(token) {
        Ok(claims) => claims,
        Err(_) => return Err(StatusCode::UNAUTHORIZED),
    };

    // Add user info to request extensions
    let auth_user = AuthUser::from(&claims);
    request.extensions_mut().insert(auth_user);

    Ok(next.run(request).await)
}

/// Optional authentication middleware that doesn't fail if no token is provided
pub async fn optional_auth_middleware(
    State(auth_service): State<Arc<AuthService>>,
    mut request: Request,
    next: Next,
) -> Response {
    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    if let Some(header) = auth_header {
        if let Some(token) = header.strip_prefix("Bearer ") {
            // Try to validate token, but don't fail if invalid
            if let Ok(claims) = auth_service.validate_token(token) {
                let auth_user = AuthUser::from(&claims);
                request.extensions_mut().insert(auth_user);
            }
        }
    }

    next.run(request).await
}

/// Admin-only middleware that requires admin role
pub async fn admin_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check if user is authenticated and is admin
    let auth_user = request
        .extensions()
        .get::<AuthUser>()
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !matches!(auth_user.role, UserRole::Admin) {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(request).await)
}

/// Request ID middleware that adds correlation IDs to requests
pub async fn request_id_middleware(
    mut request: Request,
    next: Next,
) -> Response {
    use axum::http::HeaderName;
    
    // Generate a unique request ID
    let request_id = Uuid::new_v4().to_string();
    
    // Add request ID to request extensions for use in handlers
    request.extensions_mut().insert(RequestId(request_id.clone()));
    
    // Run the request
    let mut response = next.run(request).await;
    
    // Add request ID to response headers
    let header_name = HeaderName::from_static("x-request-id");
    if let Ok(header_value) = request_id.parse() {
        response.headers_mut().insert(header_name, header_value);
    }
    
    response
}

/// Simple rate limiting middleware (basic implementation)
pub async fn rate_limit_middleware(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // TODO: Implement proper rate limiting with tower-governor when axum version conflict is resolved
    // For now, just pass through all requests
    Ok(next.run(request).await)
}

/// Request ID wrapper for extensions
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

impl RequestId {
    pub fn get(&self) -> &str {
        &self.0
    }
}

/// Simple metrics middleware for request counting
#[cfg(feature = "metrics")]
pub async fn metrics_middleware(
    request: Request,
    next: Next,
) -> Response {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;
    
    static REQUEST_COUNTER: OnceLock<AtomicU64> = OnceLock::new();
    
    let counter = REQUEST_COUNTER.get_or_init(|| AtomicU64::new(0));
    counter.fetch_add(1, Ordering::Relaxed);
    
    let start = std::time::Instant::now();
    let response = next.run(request).await;
    let duration = start.elapsed();
    
    // Log request metrics
    tracing::info!(
        method = %response.status(),
        duration_ms = duration.as_millis(),
        "Request completed"
    );
    
    response
}
