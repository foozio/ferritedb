use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, Method, StatusCode},
    middleware::Next,
    response::Response,
};
use std::{collections::HashSet, sync::Arc};
use tracing::{debug, warn};

/// Configuration for input validation middleware
#[derive(Debug, Clone)]
pub struct ValidationConfig {
    /// Maximum request body size in bytes
    pub max_body_size: usize,
    /// Maximum header value length
    pub max_header_length: usize,
    /// Maximum number of headers
    pub max_headers: usize,
    /// Maximum URL path length
    pub max_path_length: usize,
    /// Maximum query string length
    pub max_query_length: usize,
    /// Blocked user agents (case-insensitive)
    pub blocked_user_agents: HashSet<String>,
    /// Blocked IP addresses
    pub blocked_ips: HashSet<String>,
    /// Allowed content types for POST/PATCH requests
    pub allowed_content_types: HashSet<String>,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        let mut allowed_content_types = HashSet::new();
        allowed_content_types.insert("application/json".to_string());
        allowed_content_types.insert("multipart/form-data".to_string());
        allowed_content_types.insert("application/x-www-form-urlencoded".to_string());

        let mut blocked_user_agents = HashSet::new();
        // Common malicious user agents
        blocked_user_agents.insert("sqlmap".to_string());
        blocked_user_agents.insert("nikto".to_string());
        blocked_user_agents.insert("nmap".to_string());
        blocked_user_agents.insert("masscan".to_string());
        blocked_user_agents.insert("zap".to_string());

        Self {
            max_body_size: 10 * 1024 * 1024, // 10MB
            max_header_length: 8192,          // 8KB
            max_headers: 100,
            max_path_length: 2048,
            max_query_length: 4096,
            blocked_user_agents,
            blocked_ips: HashSet::new(),
            allowed_content_types,
        }
    }
}

/// Input validation middleware that sanitizes and validates incoming requests
pub async fn input_validation_middleware(
    State(config): State<Arc<ValidationConfig>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Validate request path length
    if request.uri().path().len() > config.max_path_length {
        warn!("Request rejected: path too long ({})", request.uri().path().len());
        return Err(StatusCode::URI_TOO_LONG);
    }

    // Validate query string length
    if let Some(query) = request.uri().query() {
        if query.len() > config.max_query_length {
            warn!("Request rejected: query string too long ({})", query.len());
            return Err(StatusCode::URI_TOO_LONG);
        }
    }

    // Validate headers
    validate_headers(request.headers(), &config)?;

    // Validate content type for body-containing methods
    if matches!(request.method(), &Method::POST | &Method::PATCH | &Method::PUT) {
        validate_content_type(request.headers(), &config)?;
    }

    // Check for suspicious patterns in path
    if contains_suspicious_patterns(request.uri().path()) {
        warn!("Request rejected: suspicious patterns in path: {}", request.uri().path());
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check for SQL injection patterns in query parameters
    if let Some(query) = request.uri().query() {
        if contains_sql_injection_patterns(query) {
            warn!("Request rejected: potential SQL injection in query: {}", query);
            return Err(StatusCode::BAD_REQUEST);
        }
    }

    debug!("Request passed input validation");
    Ok(next.run(request).await)
}

/// Validate request headers
fn validate_headers(headers: &HeaderMap, config: &ValidationConfig) -> Result<(), StatusCode> {
    // Check number of headers
    if headers.len() > config.max_headers {
        warn!("Request rejected: too many headers ({})", headers.len());
        return Err(StatusCode::BAD_REQUEST);
    }

    // Check header lengths and values
    for (name, value) in headers.iter() {
        // Check header value length
        if value.len() > config.max_header_length {
            warn!("Request rejected: header value too long: {}", name);
            return Err(StatusCode::BAD_REQUEST);
        }

        // Check for null bytes in headers
        if value.as_bytes().contains(&0) {
            warn!("Request rejected: null byte in header: {}", name);
            return Err(StatusCode::BAD_REQUEST);
        }

        // Check User-Agent against blocked list
        if name == header::USER_AGENT {
            if let Ok(user_agent) = value.to_str() {
                let user_agent_lower = user_agent.to_lowercase();
                for blocked_agent in &config.blocked_user_agents {
                    if user_agent_lower.contains(&blocked_agent.to_lowercase()) {
                        warn!("Request rejected: blocked user agent: {}", user_agent);
                        return Err(StatusCode::FORBIDDEN);
                    }
                }
            }
        }

        // Check for suspicious header patterns
        if let Ok(header_str) = value.to_str() {
            if contains_suspicious_patterns(header_str) {
                warn!("Request rejected: suspicious patterns in header {}: {}", name, header_str);
                return Err(StatusCode::BAD_REQUEST);
            }
        }
    }

    Ok(())
}

/// Validate content type for requests with bodies
fn validate_content_type(headers: &HeaderMap, config: &ValidationConfig) -> Result<(), StatusCode> {
    if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
        if let Ok(content_type_str) = content_type.to_str() {
            // Extract the main content type (before semicolon)
            let main_type = content_type_str.split(';').next().unwrap_or("").trim();
            
            // Check if content type is allowed
            let is_allowed = config.allowed_content_types.iter()
                .any(|allowed| main_type.starts_with(allowed));
            
            if !is_allowed {
                warn!("Request rejected: unsupported content type: {}", content_type_str);
                return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE);
            }
        }
    }
    
    Ok(())
}

/// Check for suspicious patterns that might indicate attacks
fn contains_suspicious_patterns(input: &str) -> bool {
    let suspicious_patterns = [
        // Path traversal
        "../", "..\\", "%2e%2e%2f", "%2e%2e%5c",
        // Script injection
        "<script", "</script>", "javascript:", "vbscript:",
        // Command injection
        "; rm ", "; del ", "| rm ", "| del ", "&& rm ", "&& del ",
        // Null bytes
        "%00", "\0",
        // LDAP injection
        ")(cn=", ")(uid=", ")(mail=",
        // XPath injection
        "' or '1'='1", "\" or \"1\"=\"1",
        // Template injection
        "{{", "}}", "${", "<%", "%>",
    ];

    let input_lower = input.to_lowercase();
    suspicious_patterns.iter().any(|pattern| input_lower.contains(pattern))
}

/// Check for SQL injection patterns
fn contains_sql_injection_patterns(input: &str) -> bool {
    let sql_patterns = [
        // Classic SQL injection
        "' or '1'='1", "\" or \"1\"=\"1", "' or 1=1", "\" or 1=1",
        "' union select", "\" union select", "' drop table", "\" drop table",
        "' delete from", "\" delete from", "' insert into", "\" insert into",
        "' update ", "\" update ", "' alter table", "\" alter table",
        // Blind SQL injection
        "' and sleep(", "\" and sleep(", "' waitfor delay", "\" waitfor delay",
        "' benchmark(", "\" benchmark(", "' pg_sleep(", "\" pg_sleep(",
        // Boolean-based blind SQL injection
        "' and '1'='1", "\" and \"1\"=\"1", "' and '1'='2", "\" and \"1\"=\"2",
        // Time-based blind SQL injection
        "' and (select", "\" and (select", "' or (select", "\" or (select",
        // Comment-based injection
        "';--", "\";--", "'/*", "\"/*", "'#", "\"#",
    ];

    let input_lower = input.to_lowercase();
    sql_patterns.iter().any(|pattern| input_lower.contains(pattern))
}

/// Request sanitization utilities
pub struct RequestSanitizer;

impl RequestSanitizer {
    /// Sanitize a string by removing potentially dangerous characters
    pub fn sanitize_string(input: &str) -> String {
        input
            .chars()
            .filter(|c| {
                // Allow alphanumeric, common punctuation, and Unicode letters
                c.is_alphanumeric() 
                    || c.is_whitespace()
                    || matches!(*c, '.' | ',' | '!' | '?' | '-' | '_' | '@' | '#' | '$' | '%' | '&' | '*' | '+' | '=' | ':' | ';' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\' | '/' | '\'' | '"')
                    || (*c as u32) > 127 // Allow Unicode characters
            })
            .collect()
    }

    /// Sanitize HTML by escaping dangerous characters
    pub fn escape_html(input: &str) -> String {
        input
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;")
            .replace('/', "&#x2F;")
    }

    /// Validate email format
    pub fn is_valid_email(email: &str) -> bool {
        // Basic email validation regex
        let email_regex = regex::Regex::new(
            r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        ).unwrap();
        
        email_regex.is_match(email) && email.len() <= 254
    }

    /// Validate UUID format
    pub fn is_valid_uuid(uuid_str: &str) -> bool {
        uuid::Uuid::parse_str(uuid_str).is_ok()
    }

    /// Sanitize filename for safe storage
    pub fn sanitize_filename(filename: &str) -> String {
        filename
            .chars()
            .filter(|c| c.is_alphanumeric() || matches!(*c, '.' | '-' | '_'))
            .collect::<String>()
            .trim_matches('.')
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suspicious_patterns() {
        assert!(contains_suspicious_patterns("../etc/passwd"));
        assert!(contains_suspicious_patterns("<script>alert('xss')</script>"));
        assert!(contains_suspicious_patterns("javascript:alert(1)"));
        assert!(!contains_suspicious_patterns("normal/path/to/resource"));
    }

    #[test]
    fn test_sql_injection_patterns() {
        assert!(contains_sql_injection_patterns("' or '1'='1"));
        assert!(contains_sql_injection_patterns("' union select * from users"));
        assert!(contains_sql_injection_patterns("'; drop table users;--"));
        assert!(!contains_sql_injection_patterns("normal query string"));
    }

    #[test]
    fn test_sanitize_string() {
        let input = "Hello <script>alert('xss')</script> World!";
        let sanitized = RequestSanitizer::sanitize_string(input);
        assert!(!sanitized.contains("<script>"));
    }

    #[test]
    fn test_escape_html() {
        let input = "<script>alert('xss')</script>";
        let escaped = RequestSanitizer::escape_html(input);
        assert_eq!(escaped, "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;&#x2F;script&gt;");
    }

    #[test]
    fn test_email_validation() {
        assert!(RequestSanitizer::is_valid_email("user@example.com"));
        assert!(RequestSanitizer::is_valid_email("test.email+tag@domain.co.uk"));
        assert!(!RequestSanitizer::is_valid_email("invalid.email"));
        assert!(!RequestSanitizer::is_valid_email("@domain.com"));
    }

    #[test]
    fn test_filename_sanitization() {
        assert_eq!(RequestSanitizer::sanitize_filename("../../../etc/passwd"), "etcpasswd");
        assert_eq!(RequestSanitizer::sanitize_filename("file<>name.txt"), "filename.txt");
        assert_eq!(RequestSanitizer::sanitize_filename("normal_file-name.pdf"), "normal_file-name.pdf");
    }
}
