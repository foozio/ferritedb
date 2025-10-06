use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{from_fn_with_state, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use rustbase_core::{
    audit::{AuditAction, AuditLogger},
    pii::{PiiRedactionConfig, PiiRedactor},
};
use rustbase_server::{
    csrf::{CsrfConfig, CsrfTokenStore, csrf_protection_middleware},
    security::{SecurityConfig, security_headers_middleware, request_size_limit_middleware},
    validation::{ValidationConfig, input_validation_middleware},
};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};
use tempfile::tempdir;
use tokio::sync::RwLock;
use tower::ServiceExt;
use uuid::Uuid;

/// Test handler that returns success
async fn test_handler() -> &'static str {
    "OK"
}

/// Test handler that accepts JSON
async fn json_handler(body: String) -> String {
    format!("Received: {}", body)
}

/// Create a test router with security middleware
fn create_test_router() -> Router {
    let security_config = Arc::new(SecurityConfig::default());
    let validation_config = Arc::new(ValidationConfig::default());
    let max_request_size = 1024 * 1024; // 1MB

    Router::new()
        .route("/test", get(test_handler).post(json_handler))
        .route("/protected", post(test_handler))
        .layer(from_fn_with_state(security_config, security_headers_middleware))
        .layer(from_fn_with_state(validation_config, input_validation_middleware))
        .layer(from_fn_with_state(max_request_size, request_size_limit_middleware))
}

/// Create a test router with CSRF protection
async fn create_csrf_test_router() -> Router {
    let csrf_config = CsrfConfig::default();
    let csrf_store = Arc::new(CsrfTokenStore::new(csrf_config));

    Router::new()
        .route("/test", get(test_handler))
        .route("/protected", post(test_handler))
        .layer(from_fn_with_state(csrf_store, csrf_protection_middleware))
}

#[tokio::test]
async fn test_security_headers() {
    let app = create_test_router();
    
    let request = Request::builder()
        .uri("/test")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let headers = response.headers();
    
    // Check security headers
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
    assert_eq!(headers.get("x-xss-protection").unwrap(), "1; mode=block");
    assert!(headers.contains_key("content-security-policy"));
    assert!(headers.contains_key("strict-transport-security"));
}

#[tokio::test]
async fn test_input_validation_malicious_user_agent() {
    let app = create_test_router();
    
    let request = Request::builder()
        .uri("/test")
        .method(Method::GET)
        .header("user-agent", "sqlmap/1.0")
        .body(Body::empty())
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    
    // Should be blocked due to malicious user agent
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_input_validation_path_traversal() {
    let app = create_test_router();
    
    let request = Request::builder()
        .uri("/test/../../../etc/passwd")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    
    // Should be blocked due to path traversal attempt
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_input_validation_sql_injection() {
    let app = create_test_router();
    
    let request = Request::builder()
        .uri("/test?id=' OR '1'='1")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    
    // Should be blocked due to SQL injection pattern
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_input_validation_xss_attempt() {
    let app = create_test_router();
    
    let request = Request::builder()
        .uri("/test")
        .method(Method::GET)
        .header("x-custom-header", "<script>alert('xss')</script>")
        .body(Body::empty())
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    
    // Should be blocked due to XSS pattern in header
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_request_size_limit() {
    let app = create_test_router();
    
    // Create a large request body (larger than 1MB limit)
    let large_body = "x".repeat(2 * 1024 * 1024); // 2MB
    
    let request = Request::builder()
        .uri("/test")
        .method(Method::POST)
        .header("content-type", "application/json")
        .header("content-length", large_body.len().to_string())
        .body(Body::from(large_body))
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    
    // Should be blocked due to size limit
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn test_unsupported_content_type() {
    let app = create_test_router();
    
    let request = Request::builder()
        .uri("/test")
        .method(Method::POST)
        .header("content-type", "application/xml")
        .body(Body::from("<?xml version='1.0'?><root></root>"))
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    
    // Should be blocked due to unsupported content type
    assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn test_null_byte_in_header() {
    let app = create_test_router();
    
    // Create header value with null byte
    let header_value = HeaderValue::from_bytes(b"value\x00with\x00nulls").unwrap();
    
    let request = Request::builder()
        .uri("/test")
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    
    // Manually insert the problematic header
    let (mut parts, body) = request.into_parts();
    parts.headers.insert("x-test-header", header_value);
    let request = Request::from_parts(parts, body);
    
    let response = app.oneshot(request).await.unwrap();
    
    // Should be blocked due to null bytes in header
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_csrf_protection_missing_token() {
    let app = create_csrf_test_router().await;
    
    let request = Request::builder()
        .uri("/protected")
        .method(Method::POST)
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    
    // Should be blocked due to missing CSRF token
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_csrf_protection_invalid_token() {
    let app = create_csrf_test_router().await;
    
    let request = Request::builder()
        .uri("/protected")
        .method(Method::POST)
        .header("content-type", "application/json")
        .header("x-csrf-token", "invalid_token")
        .body(Body::from("{}"))
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    
    // Should be blocked due to invalid CSRF token
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_csrf_protection_valid_token() {
    let csrf_config = CsrfConfig::default();
    let csrf_store = Arc::new(CsrfTokenStore::new(csrf_config.clone()));
    
    // Generate a valid token
    let token = csrf_store.generate_token(None).await;
    
    let app = Router::new()
        .route("/protected", post(test_handler))
        .layer(from_fn_with_state(csrf_store, csrf_protection_middleware));
    
    let request = Request::builder()
        .uri("/protected")
        .method(Method::POST)
        .header("content-type", "application/json")
        .header(&csrf_config.header_name, &token)
        .body(Body::from("{}"))
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    
    // Should succeed with valid CSRF token
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_pii_redaction() {
    let config = PiiRedactionConfig::default();
    let redactor = PiiRedactor::new(config).unwrap();
    
    // Test JSON redaction
    let mut data = json!({
        "username": "john_doe",
        "password": "secret123",
        "email": "john@example.com",
        "phone": "555-123-4567",
        "ssn": "123-45-6789",
        "credit_card": "4111-1111-1111-1111",
        "safe_data": "This is safe information"
    });
    
    redactor.redact_json(&mut data);
    
    // Sensitive fields should be redacted
    assert_eq!(data["password"], "[REDACTED]");
    
    // PII patterns should be redacted
    assert_ne!(data["email"], "john@example.com");
    assert_ne!(data["phone"], "555-123-4567");
    assert_ne!(data["ssn"], "123-45-6789");
    assert_ne!(data["credit_card"], "4111-1111-1111-1111");
    
    // Safe data should remain unchanged
    assert_eq!(data["username"], "john_doe");
    assert_eq!(data["safe_data"], "This is safe information");
}

#[tokio::test]
async fn test_pii_text_redaction() {
    let config = PiiRedactionConfig::default();
    let redactor = PiiRedactor::new(config).unwrap();
    
    let text = "Contact me at john@example.com or call 555-123-4567. My SSN is 123-45-6789.";
    let redacted = redactor.redact_text(text);
    
    // Should not contain original PII
    assert!(!redacted.contains("john@example.com"));
    assert!(!redacted.contains("555-123-4567"));
    assert!(!redacted.contains("123-45-6789"));
    
    // Should contain redaction markers
    assert!(redacted.contains("[REDACTED]"));
}

#[tokio::test]
async fn test_pii_analysis() {
    let config = PiiRedactionConfig::default();
    let redactor = PiiRedactor::new(config).unwrap();
    
    let text_with_pii = "Email: john@example.com, Phone: 555-123-4567";
    let analysis = redactor.analyze_text(text_with_pii);
    
    assert!(analysis.contains_pii);
    assert_eq!(analysis.total_matches, 2);
    assert_eq!(analysis.detected_patterns.len(), 2);
    
    let text_without_pii = "This is just normal text without any sensitive information.";
    let analysis = redactor.analyze_text(text_without_pii);
    
    assert!(!analysis.contains_pii);
    assert_eq!(analysis.total_matches, 0);
    assert_eq!(analysis.detected_patterns.len(), 0);
}

#[tokio::test]
async fn test_audit_logging() {
    // Create temporary database
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let database_url = format!("sqlite:{}", db_path.display());
    
    let pool = sqlx::SqlitePool::connect(&database_url).await.unwrap();
    
    // Create audit_log table
    sqlx::query!(
        r#"
        CREATE TABLE audit_log (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT,
            details_json TEXT,
            ip_address TEXT,
            user_agent TEXT,
            request_id TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#
    )
    .execute(&pool)
    .await
    .unwrap();
    
    let audit_logger = AuditLogger::new(pool, true);
    
    let user_id = Uuid::new_v4();
    
    // Test audit logging
    audit_logger.log(
        AuditAction::UserLogin,
        "user",
        Some("user-123"),
        Some(user_id),
        Some(json!({"success": true})),
        Some("127.0.0.1"),
        Some("test-agent"),
        Some("req-123"),
    ).await.unwrap();
    
    // Retrieve audit logs
    let logs = audit_logger.get_audit_logs(
        Some(user_id),
        None,
        None,
        None,
        None,
        10,
        0,
    ).await.unwrap();
    
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].action.as_str(), "user_login");
    assert_eq!(logs[0].user_id, Some(user_id));
    assert_eq!(logs[0].resource_type, "user");
    assert_eq!(logs[0].resource_id, Some("user-123".to_string()));
    assert_eq!(logs[0].ip_address, Some("127.0.0.1".to_string()));
}

#[tokio::test]
async fn test_cookie_security() {
    use rustbase_server::security::{CookieSecurityConfig, CookieSecurityUtils};
    
    let config = CookieSecurityConfig::default();
    
    // Test secure cookie creation
    let cookie = CookieSecurityUtils::create_secure_cookie("session", "abc123", &config, Some(3600));
    
    assert!(cookie.contains("session=abc123"));
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("Secure"));
    assert!(cookie.contains("SameSite=Strict"));
    assert!(cookie.contains("Max-Age=3600"));
    
    // Test cookie name validation
    assert!(CookieSecurityUtils::is_secure_cookie_name("__Secure-session", &config));
    assert!(!CookieSecurityUtils::is_secure_cookie_name("session", &config));
    
    // Test cookie value sanitization
    let sanitized = CookieSecurityUtils::sanitize_cookie_value("abc;123\"test");
    assert_eq!(sanitized, "abc123test");
}

#[tokio::test]
async fn test_request_sanitization() {
    use rustbase_server::validation::RequestSanitizer;
    
    // Test string sanitization
    let malicious_input = "Hello <script>alert('xss')</script> World!";
    let sanitized = RequestSanitizer::sanitize_string(malicious_input);
    assert!(!sanitized.contains("<script>"));
    
    // Test HTML escaping
    let html_input = "<script>alert('xss')</script>";
    let escaped = RequestSanitizer::escape_html(html_input);
    assert_eq!(escaped, "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;&#x2F;script&gt;");
    
    // Test email validation
    assert!(RequestSanitizer::is_valid_email("user@example.com"));
    assert!(!RequestSanitizer::is_valid_email("invalid.email"));
    
    // Test UUID validation
    let valid_uuid = Uuid::new_v4().to_string();
    assert!(RequestSanitizer::is_valid_uuid(&valid_uuid));
    assert!(!RequestSanitizer::is_valid_uuid("not-a-uuid"));
    
    // Test filename sanitization
    let dangerous_filename = "../../../etc/passwd";
    let safe_filename = RequestSanitizer::sanitize_filename(dangerous_filename);
    assert_eq!(safe_filename, "etcpasswd");
}

#[tokio::test]
async fn test_ip_blocking() {
    use rustbase_server::security::{IpSecurityConfig, is_ip_blocked};
    
    let mut config = IpSecurityConfig::default();
    config.blocked_ips.push("192.168.1.100".to_string());
    
    // Test blocked IP
    assert!(is_ip_blocked("192.168.1.100", &config));
    
    // Test allowed IP
    assert!(!is_ip_blocked("8.8.8.8", &config));
    
    // Test blocked range (simplified check)
    assert!(is_ip_blocked("192.168.1.1", &config));
    assert!(is_ip_blocked("10.0.0.1", &config));
}

/// Integration test for multiple security layers
#[tokio::test]
async fn test_security_integration() {
    let app = create_test_router();
    
    // Test that a normal request passes through all security layers
    let request = Request::builder()
        .uri("/test")
        .method(Method::GET)
        .header("user-agent", "Mozilla/5.0 (compatible)")
        .body(Body::empty())
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    // Verify security headers are present
    let headers = response.headers();
    assert!(headers.contains_key("x-content-type-options"));
    assert!(headers.contains_key("x-frame-options"));
    assert!(headers.contains_key("content-security-policy"));
}

/// Test malicious payload combinations
#[tokio::test]
async fn test_malicious_payload_combinations() {
    let app = create_test_router();
    
    // Combine multiple attack vectors
    let request = Request::builder()
        .uri("/test?id=' OR 1=1--&redirect=../../../etc/passwd")
        .method(Method::GET)
        .header("user-agent", "sqlmap/1.0 <script>alert('xss')</script>")
        .header("x-forwarded-for", "'; DROP TABLE users; --")
        .body(Body::empty())
        .unwrap();
    
    let response = app.oneshot(request).await.unwrap();
    
    // Should be blocked by input validation
    assert!(response.status().is_client_error());
}