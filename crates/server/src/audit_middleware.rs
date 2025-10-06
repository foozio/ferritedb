use axum::{
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode},
    middleware::Next,
    response::Response,
};
use ferritedb_core::{
    audit::{AuditAction, AuditContext, AuditLogger},
    pii::{PiiRedactor, redact_log_message},
};
use serde_json::Value;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::{
    middleware::{AuthUser, RequestId, extract_real_ip, IpSecurityConfig},
    ServerError,
};

/// Audit middleware configuration
#[derive(Debug, Clone)]
pub struct AuditMiddlewareConfig {
    /// Whether audit logging is enabled
    pub enabled: bool,
    /// Paths that should be audited
    pub audit_paths: Vec<String>,
    /// Paths that should be excluded from auditing
    pub exclude_paths: Vec<String>,
    /// Whether to audit successful requests only
    pub audit_success_only: bool,
    /// Whether to include request/response bodies in audit logs
    pub include_request_body: bool,
    /// Whether to include response bodies in audit logs
    pub include_response_body: bool,
    /// Maximum size of request/response body to log
    pub max_body_size: usize,
}

impl Default for AuditMiddlewareConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            audit_paths: vec![
                "/api/collections/".to_string(),
                "/api/auth/".to_string(),
                "/api/files/".to_string(),
                "/admin/".to_string(),
            ],
            exclude_paths: vec![
                "/api/health".to_string(),
                "/api/healthz".to_string(),
                "/api/readyz".to_string(),
                "/api/auth/refresh".to_string(), // Too frequent
            ],
            audit_success_only: false,
            include_request_body: true,
            include_response_body: false, // Usually too large and not needed
            max_body_size: 1024 * 1024, // 1MB
        }
    }
}

/// Audit middleware state
#[derive(Debug, Clone)]
pub struct AuditMiddlewareState {
    pub audit_logger: Arc<AuditLogger>,
    pub pii_redactor: Arc<PiiRedactor>,
    pub config: AuditMiddlewareConfig,
    pub ip_config: IpSecurityConfig,
}

/// Audit logging middleware
pub async fn audit_logging_middleware(
    State(state): State<Arc<AuditMiddlewareState>>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Response {
    if !state.config.enabled {
        return next.run(request).await;
    }

    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let query = request.uri().query().map(|q| q.to_string());

    // Check if this path should be audited
    if !should_audit_path(&path, &state.config) {
        return next.run(request).await;
    }

    // Extract audit context
    let audit_context = extract_audit_context(&headers, &state.ip_config, &request);
    
    // Extract request ID for correlation
    let request_id = request.extensions()
        .get::<RequestId>()
        .map(|rid| rid.get().to_string());

    // Determine audit action based on method and path
    let audit_action = determine_audit_action(&method, &path);

    // Log the request start
    debug!(
        request_id = ?request_id,
        method = %method,
        path = %path,
        user_id = ?audit_context.user_id,
        ip_address = ?audit_context.ip_address,
        "Audit: Request started"
    );

    // Process the request
    let response = next.run(request).await;
    let status = response.status();

    // Determine if we should log this response
    let should_log = if state.config.audit_success_only {
        status.is_success()
    } else {
        true
    };

    if should_log {
        // Extract resource information from path
        let (resource_type, resource_id) = extract_resource_info(&path);

        // Create audit details
        let mut details = serde_json::Map::new();
        details.insert("method".to_string(), Value::String(method.to_string()));
        details.insert("path".to_string(), Value::String(path.clone()));
        details.insert("status_code".to_string(), Value::Number(status.as_u16().into()));
        
        if let Some(query) = query {
            let redacted_query = state.pii_redactor.redact_for_logging(&query);
            details.insert("query".to_string(), Value::String(redacted_query));
        }

        // Log the audit event
        if let Err(e) = state.audit_logger.log(
            audit_action,
            resource_type,
            resource_id,
            audit_context.user_id,
            Some(Value::Object(details.clone())),
            audit_context.ip_address.clone(),
            audit_context.user_agent.clone(),
            request_id.clone(),
        ).await {
            error!("Failed to log audit event: {}", e);
        }

        // Log security events for failed authentication/authorization
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            let security_action = if status == StatusCode::UNAUTHORIZED {
                AuditAction::AuthenticationFailure
            } else {
                AuditAction::AuthorizationFailure
            };

            if let Err(e) = state.audit_logger.log(
                security_action,
                "security",
                None::<String>,
                audit_context.user_id,
                Some(Value::Object(details)),
                audit_context.ip_address,
                audit_context.user_agent,
                request_id,
            ).await {
                error!("Failed to log security event: {}", e);
            }
        }
    }

    response
}

/// Extract audit context from request
fn extract_audit_context(
    headers: &HeaderMap,
    ip_config: &IpSecurityConfig,
    request: &Request,
) -> AuditContext {
    let mut context = AuditContext::new();

    // Extract user ID from authenticated user
    if let Some(auth_user) = request.extensions().get::<AuthUser>() {
        context = context.with_user_id(auth_user.id);
    }

    // Extract IP address
    if let Some(ip) = extract_real_ip(headers, ip_config) {
        context = context.with_ip_address(ip);
    }

    // Extract User-Agent
    if let Some(user_agent) = headers.get("user-agent") {
        if let Ok(ua_str) = user_agent.to_str() {
            context = context.with_user_agent(ua_str.to_string());
        }
    }

    // Extract request ID
    if let Some(request_id) = request.extensions().get::<RequestId>() {
        context = context.with_request_id(request_id.get().to_string());
    }

    context
}

/// Determine if a path should be audited
fn should_audit_path(path: &str, config: &AuditMiddlewareConfig) -> bool {
    // Check exclude paths first
    for exclude_path in &config.exclude_paths {
        if path.starts_with(exclude_path) {
            return false;
        }
    }

    // Check if path matches audit patterns
    for audit_path in &config.audit_paths {
        if path.starts_with(audit_path) {
            return true;
        }
    }

    false
}

/// Determine audit action based on HTTP method and path
fn determine_audit_action(method: &Method, path: &str) -> AuditAction {
    match (method, path) {
        // Authentication endpoints
        (&Method::POST, path) if path.contains("/auth/login") => AuditAction::UserLogin,
        (&Method::POST, path) if path.contains("/auth/register") => AuditAction::UserRegistration,
        (&Method::POST, path) if path.contains("/auth/logout") => AuditAction::UserLogout,
        (&Method::POST, path) if path.contains("/auth/refresh") => AuditAction::TokenRefresh,
        
        // Collection management
        (&Method::POST, path) if path.contains("/collections") && !path.contains("/records") => AuditAction::CollectionCreate,
        (&Method::PATCH, path) if path.contains("/collections") && !path.contains("/records") => AuditAction::CollectionUpdate,
        (&Method::DELETE, path) if path.contains("/collections") && !path.contains("/records") => AuditAction::CollectionDelete,
        
        // Record operations
        (&Method::POST, path) if path.contains("/records") => AuditAction::RecordCreate,
        (&Method::GET, path) if path.contains("/records") => AuditAction::RecordView,
        (&Method::PATCH, path) if path.contains("/records") => AuditAction::RecordUpdate,
        (&Method::DELETE, path) if path.contains("/records") => AuditAction::RecordDelete,
        
        // File operations
        (&Method::POST, path) if path.contains("/files") => AuditAction::FileUpload,
        (&Method::GET, path) if path.contains("/files") => AuditAction::FileAccess,
        (&Method::DELETE, path) if path.contains("/files") => AuditAction::FileDelete,
        
        // User management
        (&Method::POST, path) if path.contains("/users") => AuditAction::UserCreate,
        (&Method::PATCH, path) if path.contains("/users") => AuditAction::UserUpdate,
        (&Method::DELETE, path) if path.contains("/users") => AuditAction::UserDelete,
        
        // Admin interface
        (_, path) if path.starts_with("/admin") => AuditAction::Custom("admin_access".to_string()),
        
        // Default for other operations
        _ => AuditAction::Custom(format!("{}_request", method.as_str().to_lowercase())),
    }
}

/// Extract resource type and ID from path
fn extract_resource_info(path: &str) -> (String, Option<String>) {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    
    match parts.as_slice() {
        ["api", "collections", collection_name, "records", record_id] => {
            ("record".to_string(), Some(record_id.to_string()))
        }
        ["api", "collections", collection_name, "records"] => {
            ("record".to_string(), None)
        }
        ["api", "collections", collection_name] => {
            ("collection".to_string(), Some(collection_name.to_string()))
        }
        ["api", "collections"] => {
            ("collection".to_string(), None)
        }
        ["api", "files", collection, record, field] => {
            ("file".to_string(), Some(format!("{}/{}/{}", collection, record, field)))
        }
        ["api", "users", user_id] => {
            ("user".to_string(), Some(user_id.to_string()))
        }
        ["api", "users"] => {
            ("user".to_string(), None)
        }
        ["api", "auth", _] => {
            ("auth".to_string(), None)
        }
        ["admin", ..] => {
            ("admin".to_string(), None)
        }
        _ => {
            ("unknown".to_string(), None)
        }
    }
}

/// Middleware for logging suspicious activity
pub async fn suspicious_activity_middleware(
    State(state): State<Arc<AuditMiddlewareState>>,
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let path = request.uri().path();
    let method = request.method();
    
    // Check for suspicious patterns
    let mut suspicious_indicators = Vec::new();
    
    // Check for path traversal attempts
    if path.contains("../") || path.contains("..\\") {
        suspicious_indicators.push("path_traversal");
    }
    
    // Check for SQL injection patterns in path
    if path.to_lowercase().contains("union select") || 
       path.to_lowercase().contains("drop table") ||
       path.contains("'") && path.contains("or") {
        suspicious_indicators.push("sql_injection");
    }
    
    // Check for script injection in path
    if path.contains("<script") || path.contains("javascript:") {
        suspicious_indicators.push("script_injection");
    }
    
    // Check for suspicious user agents
    if let Some(user_agent) = headers.get("user-agent") {
        if let Ok(ua_str) = user_agent.to_str() {
            let ua_lower = ua_str.to_lowercase();
            if ua_lower.contains("sqlmap") || 
               ua_lower.contains("nikto") || 
               ua_lower.contains("nmap") {
                suspicious_indicators.push("malicious_user_agent");
            }
        }
    }
    
    // Log suspicious activity if detected
    if !suspicious_indicators.is_empty() {
        let audit_context = extract_audit_context(&headers, &state.ip_config, &request);
        
        let details = serde_json::json!({
            "indicators": suspicious_indicators,
            "method": method.to_string(),
            "path": path,
            "user_agent": headers.get("user-agent")
                .and_then(|ua| ua.to_str().ok())
                .unwrap_or("unknown")
        });
        
        warn!(
            user_id = ?audit_context.user_id,
            ip_address = ?audit_context.ip_address,
            indicators = ?suspicious_indicators,
            "Suspicious activity detected"
        );
        
        if let Err(e) = state.audit_logger.log(
            AuditAction::SuspiciousActivity,
            "security",
            None::<String>,
            audit_context.user_id,
            Some(details),
            audit_context.ip_address,
            audit_context.user_agent,
            audit_context.request_id,
        ).await {
            error!("Failed to log suspicious activity: {}", e);
        }
        
        // Block the request for severe indicators
        if suspicious_indicators.contains(&"sql_injection") || 
           suspicious_indicators.contains(&"script_injection") {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    #[test]
    fn test_should_audit_path() {
        let config = AuditMiddlewareConfig::default();
        
        assert!(should_audit_path("/api/collections/users", &config));
        assert!(should_audit_path("/api/auth/login", &config));
        assert!(!should_audit_path("/api/health", &config));
        assert!(!should_audit_path("/api/healthz", &config));
    }

    #[test]
    fn test_determine_audit_action() {
        assert!(matches!(
            determine_audit_action(&Method::POST, "/api/auth/login"),
            AuditAction::UserLogin
        ));
        
        assert!(matches!(
            determine_audit_action(&Method::POST, "/api/collections/users/records"),
            AuditAction::RecordCreate
        ));
        
        assert!(matches!(
            determine_audit_action(&Method::DELETE, "/api/collections/posts"),
            AuditAction::CollectionDelete
        ));
    }

    #[test]
    fn test_extract_resource_info() {
        let (resource_type, resource_id) = extract_resource_info("/api/collections/users/records/123");
        assert_eq!(resource_type, "record");
        assert_eq!(resource_id, Some("123".to_string()));
        
        let (resource_type, resource_id) = extract_resource_info("/api/collections/posts");
        assert_eq!(resource_type, "collection");
        assert_eq!(resource_id, Some("posts".to_string()));
        
        let (resource_type, resource_id) = extract_resource_info("/api/files/posts/123/image");
        assert_eq!(resource_type, "file");
        assert_eq!(resource_id, Some("posts/123/image".to_string()));
    }
}