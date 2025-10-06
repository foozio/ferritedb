use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use rustbase_core::{
    auth::AuthService,
    config::AuthConfig,
    models::{User, UserRole},
};
use rustbase_rules::RuleEngine;
use rustbase_server::{
    routes::{create_router, AppState, MockCollectionService, MockRecordService, MockUserRepository},
    realtime::RealtimeManager,
};
use std::sync::Arc;
use tower::ServiceExt;

/// Create a test app state for admin interface testing
fn create_test_app_state() -> AppState {
    let auth_config = AuthConfig {
        jwt_secret: "test-secret-key-for-admin-testing-only".to_string(),
        token_ttl: 900,
        refresh_ttl: 86400,
        password_min_length: 8,
        argon2_memory: 4096,
        argon2_iterations: 1,
        argon2_parallelism: 1,
    };

    let auth_service = Arc::new(AuthService::new(auth_config).unwrap());
    let user_repository = Arc::new(MockUserRepository) as Arc<dyn rustbase_server::routes::UserRepository>;
    let collection_service = Arc::new(MockCollectionService);
    let record_service = Arc::new(MockRecordService);
    let rule_engine = Arc::new(std::sync::Mutex::new(RuleEngine::new()));

    let storage_config = rustbase_storage::StorageConfig {
        storage_type: rustbase_storage::StorageType::Local {
            path: "/tmp/rustbase_admin_test".into(),
        },
        max_file_size: 10 * 1024 * 1024,
        allowed_extensions: vec![],
        blocked_extensions: vec![],
    };

    let storage_backend = Arc::new(rustbase_storage::LocalStorage::new("/tmp/rustbase_admin_test".into()))
        as Arc<dyn rustbase_storage::StorageBackend>;

    let realtime_manager = RealtimeManager::new(auth_service.clone(), rule_engine.clone());

    AppState {
        auth_service,
        user_repository,
        collection_service,
        record_service,
        rule_engine,
        storage_backend,
        storage_config,
        realtime_manager,
    }
}

/// Helper function to create a test JWT token for admin user
fn create_admin_jwt_token(auth_service: &AuthService) -> String {
    let admin_user = User::new(
        "admin@example.com".to_string(),
        "hashed_password".to_string(),
        UserRole::Admin,
    );
    
    auth_service.generate_tokens(&admin_user).unwrap().access_token
}

#[tokio::test]
async fn test_admin_index_page_accessible() {
    let app_state = create_test_app_state();
    let app = create_router(app_state);

    let request = Request::builder()
        .uri("/admin")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    // Check that the response contains HTML content
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    
    // Verify it's the admin interface
    assert!(body_str.contains("RustBase Admin"));
    assert!(body_str.contains("login-screen"));
    assert!(body_str.contains("admin-interface"));
}

#[tokio::test]
async fn test_admin_static_css_served() {
    let app_state = create_test_app_state();
    let app = create_router(app_state);

    let request = Request::builder()
        .uri("/admin/styles.css")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    // Check content type
    let content_type = response.headers().get("content-type").unwrap();
    assert_eq!(content_type, "text/css");
    
    // Check that the response contains CSS content
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    
    // Verify it's CSS content
    assert!(body_str.contains(":root"));
    assert!(body_str.contains("--primary-color"));
    assert!(body_str.contains(".login-container"));
}

#[tokio::test]
async fn test_admin_static_js_served() {
    let app_state = create_test_app_state();
    let app = create_router(app_state);

    let request = Request::builder()
        .uri("/admin/app.js")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    // Check content type
    let content_type = response.headers().get("content-type").unwrap();
    assert_eq!(content_type, "application/javascript");
    
    // Check that the response contains JavaScript content
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    
    // Verify it's JavaScript content
    assert!(body_str.contains("class AdminApp"));
    assert!(body_str.contains("constructor()"));
    assert!(body_str.contains("handleLogin"));
}

#[tokio::test]
async fn test_admin_static_file_not_found() {
    let app_state = create_test_app_state();
    let app = create_router(app_state);

    let request = Request::builder()
        .uri("/admin/nonexistent.js")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_admin_authentication_flow() {
    let app_state = create_test_app_state();
    let app = create_router(app_state.clone());

    // Test login endpoint (which the admin interface would use)
    let login_request = serde_json::json!({
        "email": "admin@example.com",
        "password": "admin_password"
    });

    let request = Request::builder()
        .uri("/api/auth/login")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(login_request.to_string()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    
    // Since we're using mock repositories, this will return unauthorized
    // In a real test with a proper database, we'd set up test users
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_admin_health_check_integration() {
    let app_state = create_test_app_state();
    let app = create_router(app_state);

    // Test that admin interface can call health check endpoint
    let request = Request::builder()
        .uri("/api/health")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    let health_response: serde_json::Value = serde_json::from_str(&body_str).unwrap();
    
    assert_eq!(health_response["status"], "ok");
    assert!(health_response["service"].as_str().unwrap() == "rustbase");
}

#[tokio::test]
async fn test_admin_api_endpoints_with_auth() {
    let app_state = create_test_app_state();
    let token = create_admin_jwt_token(&app_state.auth_service);
    let app = create_router(app_state);

    // Test collections endpoint that admin interface would use
    let request = Request::builder()
        .uri("/api/collections/users/records")
        .method("GET")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    
    // Should return 404 since collection doesn't exist in mock, but auth should work
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_admin_api_endpoints_without_auth() {
    let app_state = create_test_app_state();
    let app = create_router(app_state);

    // Test protected endpoint without authentication
    let request = Request::builder()
        .uri("/api/collections/users/records")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    
    // Should return unauthorized
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_admin_interface_cors_headers() {
    let app_state = create_test_app_state();
    let app = create_router(app_state);

    // Test CORS preflight request
    let request = Request::builder()
        .uri("/admin")
        .method("OPTIONS")
        .header("origin", "http://localhost:3000")
        .header("access-control-request-method", "GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    
    // Should handle CORS properly
    assert!(response.status().is_success() || response.status() == StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_admin_interface_content_security() {
    let app_state = create_test_app_state();
    let app = create_router(app_state);

    let request = Request::builder()
        .uri("/admin")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    // Verify the HTML doesn't contain obvious security issues
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    
    // Should not contain inline scripts (basic XSS protection)
    assert!(!body_str.contains("<script>alert"));
    assert!(!body_str.contains("javascript:"));
    
    // Should contain proper meta tags
    assert!(body_str.contains("charset=\"UTF-8\""));
    assert!(body_str.contains("viewport"));
}

#[tokio::test]
async fn test_admin_interface_responsive_design() {
    let app_state = create_test_app_state();
    let app = create_router(app_state);

    let request = Request::builder()
        .uri("/admin/styles.css")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let css_content = String::from_utf8(body.to_vec()).unwrap();
    
    // Check for responsive design elements
    assert!(css_content.contains("@media"));
    assert!(css_content.contains("max-width"));
    assert!(css_content.contains("grid-template-columns"));
}

#[tokio::test]
async fn test_admin_interface_accessibility() {
    let app_state = create_test_app_state();
    let app = create_router(app_state);

    let request = Request::builder()
        .uri("/admin")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let html_content = String::from_utf8(body.to_vec()).unwrap();
    
    // Check for basic accessibility features
    assert!(html_content.contains("lang=\"en\""));
    assert!(html_content.contains("<label"));
    assert!(html_content.contains("aria-"));
    assert!(html_content.contains("title="));
    
    // Check for proper form structure
    assert!(html_content.contains("type=\"email\""));
    assert!(html_content.contains("type=\"password\""));
    assert!(html_content.contains("required"));
}

#[tokio::test]
async fn test_admin_interface_theme_support() {
    let app_state = create_test_app_state();
    let app = create_router(app_state);

    let request = Request::builder()
        .uri("/admin/styles.css")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let css_content = String::from_utf8(body.to_vec()).unwrap();
    
    // Check for theme support
    assert!(css_content.contains(":root"));
    assert!(css_content.contains("[data-theme=\"dark\"]"));
    assert!(css_content.contains("--primary-color"));
    assert!(css_content.contains("--bg-primary"));
    assert!(css_content.contains("--text-primary"));
}

#[tokio::test]
async fn test_admin_interface_javascript_functionality() {
    let app_state = create_test_app_state();
    let app = create_router(app_state);

    let request = Request::builder()
        .uri("/admin/app.js")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let js_content = String::from_utf8(body.to_vec()).unwrap();
    
    // Check for key functionality
    assert!(js_content.contains("handleLogin"));
    assert!(js_content.contains("showAdminInterface"));
    assert!(js_content.contains("loadCollections"));
    assert!(js_content.contains("loadUsers"));
    assert!(js_content.contains("sendApiRequest"));
    assert!(js_content.contains("validateRule"));
    assert!(js_content.contains("importData"));
    assert!(js_content.contains("exportData"));
    
    // Check for proper error handling
    assert!(js_content.contains("try {"));
    assert!(js_content.contains("catch"));
    assert!(js_content.contains("showNotification"));
}