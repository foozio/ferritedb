use axum::{
    http::{header, HeaderValue, Method},
    middleware,
    Router,
};
use rustbase_core::{
    auth::AuthService,
    config::{CoreConfig, ServerConfig},
    database::Database,
};
use rustbase_rules::RuleEngine;

use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::signal;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer},
    compression::CompressionLayer,
    timeout::TimeoutLayer,
};
use tracing::{info, Level};

use crate::{
    middleware::{rate_limit_middleware, request_id_middleware, SecurityConfig, ValidationConfig, security_headers_middleware, input_validation_middleware, request_size_limit_middleware},
    realtime::RealtimeManager,
    routes::{create_router, AppState, MockCollectionService, MockRecordService, MockUserRepository},
    ServerError, ServerResult,
};

/// Main server struct that manages the HTTP server and all services
pub struct Server {
    router: Router,
    addr: SocketAddr,
}

impl Server {
    /// Create a new server instance with the provided configuration
    pub async fn new(config: CoreConfig) -> ServerResult<Self> {
        info!("Initializing RustBase server...");

        // Initialize database connection
        let database = Database::new(
            &config.database.url,
            config.database.max_connections,
            config.database.connection_timeout,
        )
        .await
        .map_err(|e| ServerError::Internal(format!("Database initialization failed: {}", e)))?;

        // Initialize services
        let auth_service = Arc::new(
            AuthService::new(config.auth.clone())
                .map_err(|e| ServerError::Internal(format!("Auth service initialization failed: {}", e)))?
        );
        let user_repository = Arc::new(MockUserRepository) as Arc<dyn crate::routes::UserRepository>;
        let collection_service = Arc::new(MockCollectionService);
        let record_service = Arc::new(MockRecordService);
        let rule_engine = Arc::new(std::sync::Mutex::new(RuleEngine::new()));

        // Convert core storage config to storage crate config
        let storage_config = rustbase_storage::StorageConfig {
            storage_type: match &config.storage.backend {
                rustbase_core::config::StorageBackend::Local => {
                    rustbase_storage::StorageType::Local {
                        path: config.storage.local.base_path.clone(),
                    }
                }
                #[cfg(feature = "s3")]
                rustbase_core::config::StorageBackend::S3 => {
                    rustbase_storage::StorageType::S3 {
                        bucket: config.storage.s3.bucket.clone(),
                        region: config.storage.s3.region.clone(),
                        access_key_id: config.storage.s3.access_key_id.clone(),
                        secret_access_key: config.storage.s3.secret_access_key.clone(),
                        endpoint: config.storage.s3.endpoint.clone(),
                    }
                }
            },
            max_file_size: config.storage.local.max_file_size,
            allowed_extensions: vec![],
            blocked_extensions: vec![
                "exe".to_string(),
                "bat".to_string(),
                "cmd".to_string(),
                "com".to_string(),
                "pif".to_string(),
                "scr".to_string(),
                "vbs".to_string(),
                "js".to_string(),
                "jar".to_string(),
            ],
        };

        // Initialize storage backend
        let storage_backend = storage_config
            .create_backend()
            .await
            .map_err(|e| ServerError::Internal(format!("Storage initialization failed: {}", e)))?;

        // Initialize realtime manager
        let realtime_manager = RealtimeManager::new(auth_service.clone(), rule_engine.clone());

        // Create application state
        let app_state = AppState {
            auth_service: auth_service.clone(),
            user_repository,
            collection_service,
            record_service,
            rule_engine,
            storage_backend,
            storage_config: storage_config.clone(),
            realtime_manager,
        };

        // Create the main router with middleware stack
        let router = create_app_router(app_state, &config.server)?;

        // Parse server address
        let addr = format!("{}:{}", config.server.host, config.server.port)
            .parse()
            .map_err(|e| ServerError::Internal(format!("Invalid server address: {}", e)))?;

        Ok(Self { router, addr })
    }

    /// Start the server and listen for incoming connections
    pub async fn serve(self) -> ServerResult<()> {
        info!("Starting server on {}", self.addr);

        let listener = tokio::net::TcpListener::bind(self.addr)
            .await
            .map_err(|e| ServerError::Internal(format!("Failed to bind to address: {}", e)))?;

        info!("Server listening on http://{}", self.addr);
        info!("Health check available at http://{}/api/health", self.addr);
        info!("WebSocket endpoint available at ws://{}/realtime", self.addr);

        // Start the server with graceful shutdown
        axum::serve(listener, self.router)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .map_err(|e| ServerError::Internal(format!("Server error: {}", e)))?;

        info!("Server shutdown complete");
        Ok(())
    }
}

/// Create the main application router with full middleware stack
fn create_app_router(state: AppState, config: &ServerConfig) -> ServerResult<Router> {
    // Create CORS layer with configurable origins
    let cors_layer = if config.cors_origins.contains(&"*".to_string()) {
        CorsLayer::new()
            .allow_origin(tower_http::cors::Any)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                header::ACCEPT,
                header::USER_AGENT,
            ])
            .max_age(Duration::from_secs(3600))
    } else {
        CorsLayer::new()
            .allow_origin(
                config
                    .cors_origins
                    .iter()
                    .filter_map(|origin| origin.parse::<HeaderValue>().ok())
                    .collect::<Vec<_>>(),
            )
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                header::ACCEPT,
                header::USER_AGENT,
            ])
            .allow_credentials(true)
            .max_age(Duration::from_secs(3600))
    };

    // Create tracing layer for request logging
    let trace_layer = TraceLayer::new_for_http()
        .make_span_with(DefaultMakeSpan::new().level(Level::INFO))
        .on_request(DefaultOnRequest::new().level(Level::INFO))
        .on_response(DefaultOnResponse::new().level(Level::INFO));

    // Create compression layer
    let compression_layer = CompressionLayer::new()
        .br(true)
        .gzip(true);

    // Create timeout layer
    let timeout_layer = TimeoutLayer::new(Duration::from_secs(30));

    // Create security configuration
    let security_config = Arc::new(SecurityConfig::default());
    let validation_config = Arc::new(ValidationConfig::default());
    let max_request_size = config.max_request_size;

    // Build the middleware stack
    let middleware_stack = ServiceBuilder::new()
        .layer(middleware::from_fn(request_id_middleware))
        .layer(middleware::from_fn_with_state(security_config.clone(), security_headers_middleware))
        .layer(middleware::from_fn_with_state(validation_config, input_validation_middleware))
        .layer(middleware::from_fn_with_state(max_request_size, request_size_limit_middleware))
        .layer(trace_layer)
        .layer(cors_layer)
        .layer(compression_layer)
        .layer(timeout_layer)
        .layer(middleware::from_fn(rate_limit_middleware));
    
    // Add metrics middleware if feature is enabled
    #[cfg(feature = "metrics")]
    let middleware_stack = {
        use crate::middleware::metrics_middleware;
        middleware_stack.layer(middleware::from_fn(metrics_middleware))
    };

    // Create the main router
    let app_router = create_router(state)
        .layer(middleware_stack);

    Ok(app_router)
}

/// Graceful shutdown signal handler
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, starting graceful shutdown...");
        },
        _ = terminate => {
            info!("Received SIGTERM, starting graceful shutdown...");
        },
    }
    
    // Give some time for in-flight requests to complete
    info!("Waiting for in-flight requests to complete...");
    tokio::time::sleep(Duration::from_secs(1)).await;
    info!("Graceful shutdown complete");
}