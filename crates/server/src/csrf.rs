use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, Method, StatusCode},
    middleware::Next,
    response::Response,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// CSRF token configuration
#[derive(Debug, Clone)]
pub struct CsrfConfig {
    /// Token lifetime in seconds
    pub token_lifetime: u64,
    /// Cookie name for CSRF token
    pub cookie_name: String,
    /// Header name for CSRF token
    pub header_name: String,
    /// Whether to use secure cookies (HTTPS only)
    pub secure_cookies: bool,
    /// SameSite cookie attribute
    pub same_site: SameSite,
    /// Paths that are exempt from CSRF protection
    pub exempt_paths: Vec<String>,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self {
            token_lifetime: 3600, // 1 hour
            cookie_name: "csrf_token".to_string(),
            header_name: "x-csrf-token".to_string(),
            secure_cookies: true,
            same_site: SameSite::Strict,
            exempt_paths: vec![
                "/api/auth/login".to_string(),
                "/api/auth/register".to_string(),
                "/api/health".to_string(),
                "/api/healthz".to_string(),
                "/api/readyz".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl SameSite {
    fn as_str(&self) -> &'static str {
        match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        }
    }
}

/// CSRF token store entry
#[derive(Debug, Clone)]
struct CsrfToken {
    created_at: u64,
    session_id: Option<String>,
}

/// In-memory CSRF token store
#[derive(Debug)]
pub struct CsrfTokenStore {
    tokens: RwLock<HashMap<String, CsrfToken>>,
    config: CsrfConfig,
}

impl CsrfTokenStore {
    pub fn new(config: CsrfConfig) -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            config,
        }
    }

    /// Generate a new CSRF token
    pub async fn generate_token(&self, session_id: Option<String>) -> String {
        let token = generate_secure_token();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let csrf_token = CsrfToken {
            created_at: now,
            session_id,
        };

        let mut tokens = self.tokens.write().await;
        tokens.insert(token.clone(), csrf_token);

        // Clean up expired tokens
        self.cleanup_expired_tokens(&mut tokens, now).await;

        token
    }

    /// Validate a CSRF token
    pub async fn validate_token(&self, token: &str, session_id: Option<&str>) -> bool {
        let tokens = self.tokens.read().await;

        if let Some(csrf_token) = tokens.get(token) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Check if token is expired
            if now - csrf_token.created_at > self.config.token_lifetime {
                return false;
            }

            // Check session ID if provided
            if let (Some(stored_session), Some(provided_session)) =
                (&csrf_token.session_id, session_id)
            {
                return stored_session == provided_session;
            }

            true
        } else {
            false
        }
    }

    /// Remove a token after use (single-use tokens)
    pub async fn consume_token(&self, token: &str) -> bool {
        let mut tokens = self.tokens.write().await;
        tokens.remove(token).is_some()
    }

    /// Clean up expired tokens
    async fn cleanup_expired_tokens(&self, tokens: &mut HashMap<String, CsrfToken>, now: u64) {
        tokens.retain(|_, csrf_token| now - csrf_token.created_at <= self.config.token_lifetime);
    }

    /// Periodic cleanup task
    pub async fn cleanup_task(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes

        loop {
            interval.tick().await;

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let mut tokens = self.tokens.write().await;
            let initial_count = tokens.len();
            self.cleanup_expired_tokens(&mut tokens, now).await;
            let final_count = tokens.len();

            if initial_count != final_count {
                debug!(
                    "Cleaned up {} expired CSRF tokens",
                    initial_count - final_count
                );
            }
        }
    }
}

/// CSRF protection middleware
pub async fn csrf_protection_middleware(
    State(csrf_store): State<Arc<CsrfTokenStore>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = request.method().clone();
    let path = request.uri().path();

    // Skip CSRF protection for safe methods and exempt paths
    if matches!(method, Method::GET | Method::HEAD | Method::OPTIONS)
        || csrf_store
            .config
            .exempt_paths
            .iter()
            .any(|exempt_path| path.starts_with(exempt_path))
    {
        return Ok(next.run(request).await);
    }

    // Extract CSRF token from header
    let csrf_token = headers
        .get(&csrf_store.config.header_name)
        .and_then(|value| value.to_str().ok())
        .or_else(|| {
            // Fallback: try to get token from cookie
            headers
                .get(header::COOKIE)
                .and_then(|cookie_header| cookie_header.to_str().ok())
                .and_then(|cookies| {
                    extract_csrf_token_from_cookies(cookies, &csrf_store.config.cookie_name)
                })
        });

    let csrf_token = match csrf_token {
        Some(token) => token,
        None => {
            warn!(
                "CSRF protection: No CSRF token provided for {} {}",
                method, path
            );
            return Err(StatusCode::FORBIDDEN);
        }
    };

    // Extract session ID from request (could be from JWT, session cookie, etc.)
    let session_id = extract_session_id(&headers);

    // Validate CSRF token
    if !csrf_store
        .validate_token(csrf_token, session_id.as_deref())
        .await
    {
        warn!(
            "CSRF protection: Invalid CSRF token for {} {}",
            method, path
        );
        return Err(StatusCode::FORBIDDEN);
    }

    // For single-use tokens, consume the token after validation
    // csrf_store.consume_token(csrf_token).await;

    debug!("CSRF protection: Token validated for {} {}", method, path);
    Ok(next.run(request).await)
}

/// Generate a cryptographically secure token
fn generate_secure_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    use base64::{engine::general_purpose, Engine as _};
    general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Extract CSRF token from cookies
fn extract_csrf_token_from_cookies<'a>(cookies: &'a str, cookie_name: &str) -> Option<&'a str> {
    cookies.split(';').find_map(|cookie| {
        let cookie = cookie.trim();
        if let Some(eq_pos) = cookie.find('=') {
            let (name, value) = cookie.split_at(eq_pos);
            if name.trim() == cookie_name {
                return Some(value[1..].trim()); // Skip the '=' character
            }
        }
        None
    })
}

/// Extract session ID from request headers (implementation depends on auth system)
fn extract_session_id(headers: &HeaderMap) -> Option<String> {
    // Try to extract from Authorization header (JWT sub claim)
    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                // In a real implementation, you'd decode the JWT and extract the sub claim
                // For now, we'll use a simple approach
                return Some(token.chars().take(16).collect());
            }
        }
    }

    // Try to extract from session cookie
    if let Some(cookie_header) = headers.get(header::COOKIE) {
        if let Ok(cookies) = cookie_header.to_str() {
            return extract_csrf_token_from_cookies(cookies, "session_id").map(|s| s.to_string());
        }
    }

    None
}

/// Utility to create CSRF cookie
pub fn create_csrf_cookie(token: &str, config: &CsrfConfig) -> String {
    let mut cookie = format!("{}={}", config.cookie_name, token);

    // Add HttpOnly flag
    cookie.push_str("; HttpOnly");

    // Add Secure flag if configured
    if config.secure_cookies {
        cookie.push_str("; Secure");
    }

    // Add SameSite attribute
    cookie.push_str(&format!("; SameSite={}", config.same_site.as_str()));

    // Add Path
    cookie.push_str("; Path=/");

    // Add Max-Age
    cookie.push_str(&format!("; Max-Age={}", config.token_lifetime));

    cookie
}

/// CSRF token response for API endpoints
#[derive(Debug, Serialize, Deserialize)]
pub struct CsrfTokenResponse {
    pub csrf_token: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_csrf_token_generation_and_validation() {
        let config = CsrfConfig::default();
        let store = CsrfTokenStore::new(config);

        let token = store.generate_token(Some("session123".to_string())).await;
        assert!(!token.is_empty());

        // Valid token should pass
        assert!(store.validate_token(&token, Some("session123")).await);

        // Wrong session should fail
        assert!(!store.validate_token(&token, Some("wrong_session")).await);

        // Non-existent token should fail
        assert!(
            !store
                .validate_token("invalid_token", Some("session123"))
                .await
        );
    }

    #[tokio::test]
    async fn test_token_expiration() {
        let mut config = CsrfConfig::default();
        config.token_lifetime = 1; // 1 second
        let store = CsrfTokenStore::new(config);

        let token = store.generate_token(None).await;
        assert!(store.validate_token(&token, None).await);

        // Wait for token to expire
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(!store.validate_token(&token, None).await);
    }

    #[test]
    fn test_cookie_extraction() {
        let cookies = "session_id=abc123; csrf_token=def456; other=value";
        assert_eq!(
            extract_csrf_token_from_cookies(cookies, "csrf_token"),
            Some("def456")
        );
        assert_eq!(
            extract_csrf_token_from_cookies(cookies, "session_id"),
            Some("abc123")
        );
        assert_eq!(
            extract_csrf_token_from_cookies(cookies, "nonexistent"),
            None
        );
    }

    #[test]
    fn test_secure_token_generation() {
        let token1 = generate_secure_token();
        let token2 = generate_secure_token();

        assert_ne!(token1, token2);
        assert!(!token1.is_empty());
        assert!(!token2.is_empty());
    }
}
