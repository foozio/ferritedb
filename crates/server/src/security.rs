use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tracing::{debug, warn};

/// Security configuration for headers and cookies
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Security headers to add to all responses
    pub security_headers: HashMap<String, String>,
    /// Content Security Policy
    pub csp: Option<String>,
    /// HTTP Strict Transport Security max age
    pub hsts_max_age: Option<u64>,
    /// Whether to include subdomains in HSTS
    pub hsts_include_subdomains: bool,
    /// Whether to preload HSTS
    pub hsts_preload: bool,
    /// Referrer Policy
    pub referrer_policy: Option<String>,
    /// Permissions Policy
    pub permissions_policy: Option<String>,
    /// Cookie security settings
    pub cookie_security: CookieSecurityConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        let mut security_headers = HashMap::new();
        
        // Prevent MIME type sniffing
        security_headers.insert("X-Content-Type-Options".to_string(), "nosniff".to_string());
        
        // Prevent clickjacking
        security_headers.insert("X-Frame-Options".to_string(), "DENY".to_string());
        
        // XSS protection (legacy, but still useful for older browsers)
        security_headers.insert("X-XSS-Protection".to_string(), "1; mode=block".to_string());
        
        // Prevent Adobe Flash and PDF from loading
        security_headers.insert("X-Permitted-Cross-Domain-Policies".to_string(), "none".to_string());
        
        // Remove server information
        security_headers.insert("Server".to_string(), "RustBase".to_string());

        Self {
            security_headers,
            csp: Some(
                "default-src 'self'; \
                 script-src 'self' 'unsafe-inline' 'unsafe-eval'; \
                 style-src 'self' 'unsafe-inline'; \
                 img-src 'self' data: https:; \
                 font-src 'self' data:; \
                 connect-src 'self' ws: wss:; \
                 frame-ancestors 'none'; \
                 base-uri 'self'; \
                 form-action 'self'"
                .to_string()
            ),
            hsts_max_age: Some(31536000), // 1 year
            hsts_include_subdomains: true,
            hsts_preload: false,
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            permissions_policy: Some(
                "camera=(), microphone=(), geolocation=(), payment=(), usb=()".to_string()
            ),
            cookie_security: CookieSecurityConfig::default(),
        }
    }
}

/// Cookie security configuration
#[derive(Debug, Clone)]
pub struct CookieSecurityConfig {
    /// Default SameSite attribute for cookies
    pub default_same_site: SameSite,
    /// Whether cookies should be secure by default
    pub secure_by_default: bool,
    /// Whether cookies should be HttpOnly by default
    pub http_only_by_default: bool,
    /// Default max age for cookies (in seconds)
    pub default_max_age: Option<u64>,
    /// Cookie name prefix for secure cookies
    pub secure_prefix: String,
}

impl Default for CookieSecurityConfig {
    fn default() -> Self {
        Self {
            default_same_site: SameSite::Strict,
            secure_by_default: true,
            http_only_by_default: true,
            default_max_age: Some(86400), // 24 hours
            secure_prefix: "__Secure-".to_string(),
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

/// Security headers middleware
pub async fn security_headers_middleware(
    State(config): State<Arc<SecurityConfig>>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // Add security headers
    for (name, value) in &config.security_headers {
        if let (Ok(header_name), Ok(header_value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.insert(header_name, header_value);
        }
    }

    // Add Content Security Policy
    if let Some(csp) = &config.csp {
        if let Ok(csp_value) = HeaderValue::from_str(csp) {
            headers.insert(header::HeaderName::from_static("content-security-policy"), csp_value);
        }
    }

    // Add HSTS header
    if let Some(max_age) = config.hsts_max_age {
        let mut hsts_value = format!("max-age={}", max_age);
        if config.hsts_include_subdomains {
            hsts_value.push_str("; includeSubDomains");
        }
        if config.hsts_preload {
            hsts_value.push_str("; preload");
        }
        
        if let Ok(hsts_header) = HeaderValue::from_str(&hsts_value) {
            headers.insert(header::HeaderName::from_static("strict-transport-security"), hsts_header);
        }
    }

    // Add Referrer Policy
    if let Some(referrer_policy) = &config.referrer_policy {
        if let Ok(referrer_value) = HeaderValue::from_str(referrer_policy) {
            headers.insert(header::HeaderName::from_static("referrer-policy"), referrer_value);
        }
    }

    // Add Permissions Policy
    if let Some(permissions_policy) = &config.permissions_policy {
        if let Ok(permissions_value) = HeaderValue::from_str(permissions_policy) {
            headers.insert(header::HeaderName::from_static("permissions-policy"), permissions_value);
        }
    }

    response
}

/// Request size limiting middleware
pub async fn request_size_limit_middleware(
    State(max_size): State<usize>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check Content-Length header
    if let Some(content_length) = request.headers().get(header::CONTENT_LENGTH) {
        if let Ok(length_str) = content_length.to_str() {
            if let Ok(length) = length_str.parse::<usize>() {
                if length > max_size {
                    warn!("Request rejected: body too large ({} bytes, max: {})", length, max_size);
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
            }
        }
    }

    Ok(next.run(request).await)
}

/// Request timeout middleware configuration
#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    /// Request timeout duration
    pub timeout: Duration,
    /// Paths that should have longer timeouts
    pub long_timeout_paths: Vec<String>,
    /// Long timeout duration
    pub long_timeout: Duration,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            long_timeout_paths: vec![
                "/api/files/".to_string(),
                "/api/import".to_string(),
                "/api/export".to_string(),
            ],
            long_timeout: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// Cookie security utilities
pub struct CookieSecurityUtils;

impl CookieSecurityUtils {
    /// Create a secure cookie string
    pub fn create_secure_cookie(
        name: &str,
        value: &str,
        config: &CookieSecurityConfig,
        max_age: Option<u64>,
    ) -> String {
        let mut cookie = format!("{}={}", name, value);

        // Add HttpOnly flag
        if config.http_only_by_default {
            cookie.push_str("; HttpOnly");
        }

        // Add Secure flag
        if config.secure_by_default {
            cookie.push_str("; Secure");
        }

        // Add SameSite attribute
        cookie.push_str(&format!("; SameSite={}", config.default_same_site.as_str()));

        // Add Path
        cookie.push_str("; Path=/");

        // Add Max-Age
        let age = max_age.or(config.default_max_age);
        if let Some(max_age_value) = age {
            cookie.push_str(&format!("; Max-Age={}", max_age_value));
        }

        cookie
    }

    /// Validate cookie name for security
    pub fn is_secure_cookie_name(name: &str, config: &CookieSecurityConfig) -> bool {
        // Check for secure prefix
        if config.secure_by_default && !name.starts_with(&config.secure_prefix) {
            return false;
        }

        // Check for valid characters (RFC 6265)
        name.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '!')
        })
    }

    /// Sanitize cookie value
    pub fn sanitize_cookie_value(value: &str) -> String {
        value
            .chars()
            .filter(|c| {
                // Allow printable ASCII except control characters, whitespace, and special chars
                c.is_ascii() && !c.is_control() && !matches!(*c, ' ' | '"' | ',' | ';' | '\\')
            })
            .collect()
    }
}

/// IP-based rate limiting and blocking
#[derive(Debug, Clone)]
pub struct IpSecurityConfig {
    /// Blocked IP addresses
    pub blocked_ips: Vec<String>,
    /// Blocked IP ranges (CIDR notation)
    pub blocked_ranges: Vec<String>,
    /// Trusted proxy IPs for X-Forwarded-For header
    pub trusted_proxies: Vec<String>,
}

impl Default for IpSecurityConfig {
    fn default() -> Self {
        Self {
            blocked_ips: vec![
                // Common malicious IPs can be added here
            ],
            blocked_ranges: vec![
                // Private ranges that shouldn't access from internet
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
            ],
            trusted_proxies: vec![
                // Common load balancer IPs
                "127.0.0.1".to_string(),
                "::1".to_string(),
            ],
        }
    }
}

/// Extract real IP address from request
pub fn extract_real_ip(headers: &HeaderMap, config: &IpSecurityConfig) -> Option<String> {
    // Check X-Forwarded-For header (if from trusted proxy)
    if let Some(forwarded_for) = headers.get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            // Take the first IP in the chain
            if let Some(first_ip) = forwarded_str.split(',').next() {
                return Some(first_ip.trim().to_string());
            }
        }
    }

    // Check X-Real-IP header
    if let Some(real_ip) = headers.get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            return Some(ip_str.to_string());
        }
    }

    // Fallback to connection IP (would need to be passed from connection info)
    None
}

/// Check if IP is blocked
pub fn is_ip_blocked(ip: &str, config: &IpSecurityConfig) -> bool {
    // Check exact IP matches
    if config.blocked_ips.contains(&ip.to_string()) {
        return true;
    }

    // Check CIDR ranges (simplified check - in production use proper CIDR library)
    for range in &config.blocked_ranges {
        if ip_in_range(ip, range) {
            return true;
        }
    }

    false
}

/// Simple CIDR range check (for production, use a proper CIDR library)
fn ip_in_range(ip: &str, cidr: &str) -> bool {
    // This is a simplified implementation
    // In production, use a proper CIDR parsing library like `ipnet`
    if let Some((network, prefix)) = cidr.split_once('/') {
        if ip.starts_with(network.split('.').take(prefix.parse::<usize>().unwrap_or(0) / 8).collect::<Vec<_>>().join(".").as_str()) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_cookie_creation() {
        let config = CookieSecurityConfig::default();
        let cookie = CookieSecurityUtils::create_secure_cookie("session", "abc123", &config, Some(3600));
        
        assert!(cookie.contains("session=abc123"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));
        assert!(cookie.contains("Max-Age=3600"));
    }

    #[test]
    fn test_cookie_name_validation() {
        let config = CookieSecurityConfig::default();
        
        assert!(CookieSecurityUtils::is_secure_cookie_name("__Secure-session", &config));
        assert!(!CookieSecurityUtils::is_secure_cookie_name("session", &config));
        assert!(!CookieSecurityUtils::is_secure_cookie_name("invalid name", &config));
    }

    #[test]
    fn test_cookie_value_sanitization() {
        assert_eq!(CookieSecurityUtils::sanitize_cookie_value("abc123"), "abc123");
        assert_eq!(CookieSecurityUtils::sanitize_cookie_value("abc;123"), "abc123");
        assert_eq!(CookieSecurityUtils::sanitize_cookie_value("abc\"123"), "abc123");
        assert_eq!(CookieSecurityUtils::sanitize_cookie_value("abc 123"), "abc123");
    }

    #[test]
    fn test_ip_blocking() {
        let config = IpSecurityConfig::default();
        
        // Test blocked ranges
        assert!(is_ip_blocked("192.168.1.1", &config));
        assert!(is_ip_blocked("10.0.0.1", &config));
        assert!(!is_ip_blocked("8.8.8.8", &config));
    }
}