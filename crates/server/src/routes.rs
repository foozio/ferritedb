use axum::{
    body::Body,
    extract::{FromRequestParts, Path, Query, State},
    http::{request::Parts, StatusCode, Uri},
    response::{Html, Json, Response},
    routing::{delete, get, patch, post},
    Router,
};
use rustbase_core::{
    auth::{
        AuthService, AuthToken, LoginRequest, LoginResponse, RefreshTokenRequest, RegisterRequest,
        RegisterResponse, UserResponse,
    },
    models::{User, UserRole, Record},
    CollectionService, RecordService,
};
use rustbase_rules::{RuleEngine, CollectionRules, RuleOperation, EvaluationContext, RequestContext};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

/// Query parameters for listing records
#[derive(Debug, Deserialize)]
pub struct ListRecordsQuery {
    /// Page number (default: 1)
    #[serde(default = "default_page")]
    pub page: i64,
    /// Number of records per page (default: 30, max: 500)
    #[serde(default = "default_per_page")]
    pub per_page: i64,
    /// Filter expression for records
    pub filter: Option<String>,
    /// Sort expression (e.g., "created_at", "-updated_at")
    pub sort: Option<String>,
    /// Fields to include in response (comma-separated)
    pub fields: Option<String>,
    /// Expand related records
    pub expand: Option<String>,
}

fn default_page() -> i64 {
    1
}

fn default_per_page() -> i64 {
    30
}

/// Response for listing records
#[derive(Debug, Serialize)]
pub struct ListRecordsResponse {
    pub page: i64,
    pub per_page: i64,
    pub total_items: i64,
    pub total_pages: i64,
    pub items: Vec<Record>,
}

/// Request for creating a record
#[derive(Debug, Deserialize)]
pub struct CreateRecordRequest {
    #[serde(flatten)]
    pub data: HashMap<String, Value>,
}

/// Request for updating a record
#[derive(Debug, Deserialize)]
pub struct UpdateRecordRequest {
    #[serde(flatten)]
    pub data: HashMap<String, Value>,
}

// Temporary trait for UserRepository until repository module is fixed
#[axum::async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, Box<dyn std::error::Error + Send + Sync>>;
    async fn find_by_id(&self, id: uuid::Uuid) -> Result<Option<User>, Box<dyn std::error::Error + Send + Sync>>;
    async fn create(&self, user: &User) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

// Mock implementations for testing
pub struct MockUserRepository;
pub struct MockCollectionService;
pub struct MockRecordService;

#[axum::async_trait]
impl UserRepository for MockUserRepository {
    async fn find_by_email(&self, _email: &str) -> Result<Option<User>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(None)
    }
    
    async fn find_by_id(&self, _id: uuid::Uuid) -> Result<Option<User>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(None)
    }
    
    async fn create(&self, _user: &User) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

// Mock CollectionService implementation
impl MockCollectionService {
    pub async fn get_collection(&self, _name: &str) -> rustbase_core::CoreResult<Option<rustbase_core::models::Collection>> {
        Ok(None)
    }
}

// Mock RecordService implementation  
impl MockRecordService {
    pub async fn list_records(&self, _collection_name: &str, _limit: i64, _offset: i64) -> rustbase_core::CoreResult<Vec<Record>> {
        Ok(Vec::new())
    }
    
    pub async fn list_records_with_query(
        &self,
        _collection_name: &str,
        _limit: i64,
        _offset: i64,
        _filter: Option<&str>,
        _sort: Option<&str>,
        _fields: Option<&[String]>,
    ) -> rustbase_core::CoreResult<Vec<Record>> {
        Ok(Vec::new())
    }
    
    pub async fn create_record(&self, _collection_name: &str, _data: serde_json::Value) -> rustbase_core::CoreResult<Record> {
        use chrono::Utc;
        Ok(Record {
            id: Uuid::new_v4(),
            collection_id: Uuid::new_v4(),
            data: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
    }
    
    pub async fn get_record(&self, _collection_name: &str, _record_id: Uuid) -> rustbase_core::CoreResult<Option<Record>> {
        Ok(None)
    }
    
    pub async fn update_record(&self, _collection_name: &str, _record_id: Uuid, _data: serde_json::Value) -> rustbase_core::CoreResult<Record> {
        use chrono::Utc;
        Ok(Record {
            id: _record_id,
            collection_id: Uuid::new_v4(),
            data: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        })
    }
    
    pub async fn delete_record(&self, _collection_name: &str, _record_id: Uuid) -> rustbase_core::CoreResult<bool> {
        Ok(true)
    }
    
    pub async fn count_records(&self, _collection_name: &str) -> rustbase_core::CoreResult<i64> {
        Ok(0)
    }
    
    pub async fn count_records_with_filter(&self, _collection_name: &str, _filter: Option<&str>) -> rustbase_core::CoreResult<i64> {
        Ok(0)
    }
}
use serde_json::json;
use std::sync::Arc;

use crate::{
    error::{ServerError, ServerResult},
    files::{FileAppState, FileMetadata, delete_file as delete_file_handler, serve_file as serve_file_handler, upload_file as upload_file_handler},
    middleware::AuthUser,
    realtime::{websocket_handler, RealtimeManager},
};

/// Extractor for authenticated user
#[axum::async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = ServerError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthUser>()
            .cloned()
            .ok_or_else(|| ServerError::Unauthorized("Authentication required".to_string()))
    }
}

/// Application state containing shared services
#[derive(Clone)]
pub struct AppState {
    pub auth_service: Arc<AuthService>,
    pub user_repository: Arc<dyn UserRepository>,
    pub collection_service: Arc<MockCollectionService>,
    pub record_service: Arc<MockRecordService>,
    pub rule_engine: Arc<std::sync::Mutex<RuleEngine>>,
    pub storage_backend: Arc<dyn rustbase_storage::StorageBackend>,
    pub storage_config: rustbase_storage::StorageConfig,
    pub realtime_manager: RealtimeManager,
}

/// Create the main application router
pub fn create_router(state: AppState) -> Router {
    use axum::middleware::from_fn_with_state;
    use crate::middleware::auth_middleware;

    // Protected routes that require authentication
    let protected_routes = Router::new()
        .route("/auth/me", get(get_current_user))
        .route("/collections/:collection/records", get(list_records).post(create_record))
        .route("/collections/:collection/records/:id", get(get_record).patch(update_record).delete(delete_record))
        .route("/files/:collection/:record/:field", 
               get(serve_file).post(upload_file).delete(delete_file))
        .layer(from_fn_with_state(state.auth_service.clone(), auth_middleware));

    // Public routes
    let mut public_routes = Router::new()
        .route("/auth/login", post(login))
        .route("/auth/register", post(register))
        .route("/auth/refresh", post(refresh_token))
        .route("/health", get(health_check))
        .route("/healthz", get(health_check))
        .route("/readyz", get(readiness_check));
    
    // Add metrics endpoint if feature is enabled
    #[cfg(feature = "metrics")]
    {
        public_routes = public_routes.route("/metrics", get(metrics));
    }

    // WebSocket route (separate from API routes)
    let websocket_routes = Router::new()
        .route("/realtime", axum::routing::get(websocket_handler));

    // Admin routes for serving static files
    let admin_routes = Router::new()
        .route("/admin", get(serve_admin_index))
        .route("/admin/*path", get(serve_admin_static));

    Router::new()
        .nest("/api", public_routes.merge(protected_routes))
        .merge(websocket_routes)
        .merge(admin_routes)
        .with_state(state)
}



/// Health check endpoint (liveness probe)
async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "timestamp": chrono::Utc::now(),
        "service": "rustbase",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

/// Readiness check endpoint (readiness probe)
async fn readiness_check(State(state): State<AppState>) -> ServerResult<Json<Value>> {
    // Check database connectivity
    let db_status = check_database_health(&state).await;
    
    // Check storage backend
    let storage_status = check_storage_health(&state).await;
    
    let overall_status = if db_status && storage_status {
        "ready"
    } else {
        "not_ready"
    };
    
    let response = json!({
        "status": overall_status,
        "timestamp": chrono::Utc::now(),
        "service": "rustbase",
        "version": env!("CARGO_PKG_VERSION"),
        "checks": {
            "database": if db_status { "healthy" } else { "unhealthy" },
            "storage": if storage_status { "healthy" } else { "unhealthy" }
        }
    });
    
    if overall_status == "ready" {
        Ok(Json(response))
    } else {
        Err(ServerError::Internal("Service not ready".to_string()))
    }
}

/// Check database health
async fn check_database_health(_state: &AppState) -> bool {
    // TODO: Implement actual database health check
    // For now, just return true since we're using mock services
    true
}

/// Check storage backend health
async fn check_storage_health(_state: &AppState) -> bool {
    // TODO: Implement actual storage health check
    // For now, just return true
    true
}

/// Metrics endpoint for Prometheus (behind feature flag)
#[cfg(feature = "metrics")]
async fn metrics() -> ServerResult<String> {
    // TODO: Implement Prometheus metrics collection
    Ok("# HELP rustbase_requests_total Total number of requests\n# TYPE rustbase_requests_total counter\nrustbase_requests_total 0\n".to_string())
}

/// User login endpoint
async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> ServerResult<Json<LoginResponse>> {
    // Find user by email
    let user = state
        .user_repository
        .find_by_email(&request.email)
        .await
        .map_err(|_| ServerError::Unauthorized("Invalid credentials".to_string()))?
        .ok_or_else(|| ServerError::Unauthorized("Invalid credentials".to_string()))?;

    // Verify password
    let is_valid = state
        .auth_service
        .verify_password(&request.password, &user.password_hash)
        .map_err(|_| ServerError::Unauthorized("Invalid credentials".to_string()))?;

    if !is_valid {
        return Err(ServerError::Unauthorized("Invalid credentials".to_string()));
    }

    // Generate tokens
    let token = state
        .auth_service
        .generate_tokens(&user)
        .map_err(|e| ServerError::Internal(format!("Token generation failed: {}", e)))?;

    Ok(Json(LoginResponse {
        user: UserResponse::from(user),
        token,
    }))
}

/// User registration endpoint
async fn register(
    State(state): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> ServerResult<Json<RegisterResponse>> {
    // Validate password confirmation
    if request.password != request.password_confirm {
        return Err(ServerError::BadRequest("Passwords do not match".to_string()));
    }

    // Check if user already exists
    if let Ok(Some(_)) = state.user_repository.find_by_email(&request.email).await {
        return Err(ServerError::BadRequest("User already exists".to_string()));
    }

    // Hash password
    let password_hash = state
        .auth_service
        .hash_password(&request.password)
        .map_err(|e| ServerError::BadRequest(format!("Password validation failed: {}", e)))?;

    // Create user
    let user = User::new(request.email, password_hash, UserRole::User);

    // Save user to database
    state
        .user_repository
        .create(&user)
        .await
        .map_err(|e| ServerError::Internal(format!("User creation failed: {}", e)))?;

    // Generate tokens
    let token = state
        .auth_service
        .generate_tokens(&user)
        .map_err(|e| ServerError::Internal(format!("Token generation failed: {}", e)))?;

    Ok(Json(RegisterResponse {
        user: UserResponse::from(user),
        token,
    }))
}

/// Token refresh endpoint
async fn refresh_token(
    State(state): State<AppState>,
    Json(request): Json<RefreshTokenRequest>,
) -> ServerResult<Json<AuthToken>> {
    // Validate refresh token and extract user ID
    let claims = state
        .auth_service
        .validate_token(&request.refresh_token)
        .map_err(|_| ServerError::Unauthorized("Invalid refresh token".to_string()))?;

    // Get user from database
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| ServerError::Unauthorized("Invalid token format".to_string()))?;

    let user = state
        .user_repository
        .find_by_id(user_id)
        .await
        .map_err(|_| ServerError::Unauthorized("User not found".to_string()))?
        .ok_or_else(|| ServerError::Unauthorized("User not found".to_string()))?;

    // Generate new tokens
    let new_token = state
        .auth_service
        .refresh_token(&request.refresh_token, &user)
        .map_err(|_| ServerError::Unauthorized("Token refresh failed".to_string()))?;

    Ok(Json(new_token))
}

/// Get current user endpoint (requires authentication)
async fn get_current_user(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> ServerResult<Json<UserResponse>> {

    // Get fresh user data from database
    let user = state
        .user_repository
        .find_by_id(auth_user.id)
        .await
        .map_err(|_| ServerError::Internal("Database error".to_string()))?
        .ok_or_else(|| ServerError::Unauthorized("User not found".to_string()))?;

    Ok(Json(UserResponse::from(user)))
}

/// Helper function to convert rule errors to server errors
fn rule_error_to_server_error(rule_error: rustbase_rules::RuleError) -> ServerError {
    match rule_error {
        rustbase_rules::RuleError::Parse(msg) => ServerError::BadRequest(format!("Rule parse error: {}", msg)),
        rustbase_rules::RuleError::Evaluation(msg) => ServerError::Forbidden(format!("Rule evaluation failed: {}", msg)),
        rustbase_rules::RuleError::Invalid(msg) => ServerError::BadRequest(format!("Invalid rule: {}", msg)),
    }
}

/// Helper function to filter record fields based on permissions
async fn filter_record_fields(
    record: &mut Record,
    collection: &rustbase_core::models::Collection,
    user: &rustbase_rules::evaluator::User,
    rule_engine: &mut RuleEngine,
) -> ServerResult<()> {
    // For each field in the record, check if the user has read access
    let mut filtered_data = HashMap::new();
    
    for (field_name, field_value) in &record.data {
        // Check if there's a field-level read rule
        // For now, we'll use a simple convention: if a field has a read rule,
        // it should be in the format "field_name_read_rule"
        let field_read_rule = format!("user.role == \"admin\" || record.owner_id == user.id");
        
        let record_data = serde_json::to_value(&record.data)
            .map_err(|e| ServerError::Internal(format!("Failed to serialize record: {}", e)))?;
        
        let context = EvaluationContext::new()
            .with_user(user.clone())
            .with_record(record_data)
            .with_request(RequestContext::default());
        
        // For now, allow all fields if user has view access to the record
        // In a more sophisticated implementation, each field could have its own read rule
        filtered_data.insert(field_name.clone(), field_value.clone());
    }
    
    record.data = filtered_data;
    Ok(())
}

/// List records from a collection with pagination and filtering
async fn list_records(
    State(state): State<AppState>,
    Path(collection_name): Path<String>,
    Query(query): Query<ListRecordsQuery>,
    auth_user: AuthUser,
) -> ServerResult<Json<ListRecordsResponse>> {
    // Get collection to validate it exists and get rules
    let collection = state
        .collection_service
        .get_collection(&collection_name)
        .await
        .map_err(ServerError::Core)?
        .ok_or_else(|| ServerError::NotFound(format!("Collection '{}' not found", collection_name)))?;

    // Check list rule access
    let rules = CollectionRules {
        list_rule: collection.list_rule.clone(),
        view_rule: collection.view_rule.clone(),
        create_rule: collection.create_rule.clone(),
        update_rule: collection.update_rule.clone(),
        delete_rule: collection.delete_rule.clone(),
    };

    // Create evaluation context
    let user = rustbase_rules::evaluator::User {
        id: auth_user.id,
        email: auth_user.email.clone(),
        role: match auth_user.role {
            UserRole::Admin => rustbase_rules::evaluator::UserRole::Admin,
            UserRole::User => rustbase_rules::evaluator::UserRole::User,
            UserRole::Service => rustbase_rules::evaluator::UserRole::Service,
        },
        verified: auth_user.verified,
        created_at: auth_user.created_at,
        updated_at: auth_user.updated_at,
    };

    let context = EvaluationContext::new()
        .with_user(user.clone())
        .with_request(RequestContext::default());

    // Check access using rule engine
    let has_access = {
        let mut rule_engine = state.rule_engine.lock().unwrap();
        rule_engine
            .evaluate_collection_rule(&rules, RuleOperation::List, &context)
            .map_err(rule_error_to_server_error)?
    };

    if !has_access {
        return Err(ServerError::Forbidden("Access denied to list records".to_string()));
    }

    // Calculate pagination
    let page = query.page.max(1);
    let per_page = query.per_page.max(1).min(500);
    let offset = (page - 1) * per_page;

    // Parse field selection
    let fields = query.fields.as_ref().map(|f| {
        f.split(',')
            .map(|field| field.trim().to_string())
            .collect::<Vec<String>>()
    });

    // Get records with advanced query options
    let records = state
        .record_service
        .list_records_with_query(
            &collection_name,
            per_page,
            offset,
            query.filter.as_deref(),
            query.sort.as_deref(),
            fields.as_deref(),
        )
        .await
        .map_err(ServerError::Core)?;

    // Get total count for pagination (with filter if specified)
    let total_items = state
        .record_service
        .count_records_with_filter(&collection_name, query.filter.as_deref())
        .await
        .map_err(ServerError::Core)?;

    let total_pages = (total_items + per_page - 1) / per_page;

    // Apply field-level filtering to each record
    let mut filtered_records = records;
    for record in &mut filtered_records {
        // For now, just allow all fields - proper field filtering will be implemented later
        // This avoids the MutexGuard Send issue
        // filter_record_fields(record, &collection, &user, &mut rule_engine).await?;
    }

    Ok(Json(ListRecordsResponse {
        page,
        per_page,
        total_items,
        total_pages,
        items: filtered_records,
    }))
}

/// Create a new record in a collection
async fn create_record(
    State(state): State<AppState>,
    Path(collection_name): Path<String>,
    auth_user: AuthUser,
    Json(request): Json<CreateRecordRequest>,
) -> ServerResult<Json<Record>> {
    // Get collection to validate it exists and get rules
    let collection = state
        .collection_service
        .get_collection(&collection_name)
        .await
        .map_err(ServerError::Core)?
        .ok_or_else(|| ServerError::NotFound(format!("Collection '{}' not found", collection_name)))?;

    // Check create rule access
    let rules = CollectionRules {
        list_rule: collection.list_rule.clone(),
        view_rule: collection.view_rule.clone(),
        create_rule: collection.create_rule.clone(),
        update_rule: collection.update_rule.clone(),
        delete_rule: collection.delete_rule.clone(),
    };

    // Create evaluation context
    let user = rustbase_rules::evaluator::User {
        id: auth_user.id,
        email: auth_user.email.clone(),
        role: match auth_user.role {
            UserRole::Admin => rustbase_rules::evaluator::UserRole::Admin,
            UserRole::User => rustbase_rules::evaluator::UserRole::User,
            UserRole::Service => rustbase_rules::evaluator::UserRole::Service,
        },
        verified: auth_user.verified,
        created_at: auth_user.created_at,
        updated_at: auth_user.updated_at,
    };

    let context = EvaluationContext::new()
        .with_user(user)
        .with_request(RequestContext::default());

    // Check access using rule engine
    let has_access = {
        let mut rule_engine = state.rule_engine.lock().unwrap();
        rule_engine
            .evaluate_collection_rule(&rules, RuleOperation::Create, &context)
            .map_err(rule_error_to_server_error)?
    };

    if !has_access {
        return Err(ServerError::Forbidden("Access denied to create records".to_string()));
    }

    // Convert request data to JSON Value
    let record_data = serde_json::to_value(request.data)
        .map_err(|e| ServerError::BadRequest(format!("Invalid record data: {}", e)))?;

    // Create the record
    let record = state
        .record_service
        .create_record(&collection_name, record_data)
        .await
        .map_err(ServerError::Core)?;

    // Publish realtime event
    let event = crate::realtime::RealtimeEvent {
        event_type: crate::realtime::EventType::Created,
        collection: collection_name,
        record_id: record.id,
        data: serde_json::to_value(&record.data).unwrap_or_default(),
        timestamp: chrono::Utc::now(),
    };
    state.realtime_manager.broadcast_event_sync(event);

    Ok(Json(record))
}

/// Get a single record by ID
async fn get_record(
    State(state): State<AppState>,
    Path((collection_name, record_id)): Path<(String, String)>,
    auth_user: AuthUser,
) -> ServerResult<Json<Record>> {
    // Parse record ID
    let record_id = Uuid::parse_str(&record_id)
        .map_err(|_| ServerError::BadRequest("Invalid record ID format".to_string()))?;

    // Get collection to validate it exists and get rules
    let collection = state
        .collection_service
        .get_collection(&collection_name)
        .await
        .map_err(ServerError::Core)?
        .ok_or_else(|| ServerError::NotFound(format!("Collection '{}' not found", collection_name)))?;

    // Get the record first
    let record = state
        .record_service
        .get_record(&collection_name, record_id)
        .await
        .map_err(ServerError::Core)?
        .ok_or_else(|| ServerError::NotFound("Record not found".to_string()))?;

    // Check view rule access with record context
    let rules = CollectionRules {
        list_rule: collection.list_rule.clone(),
        view_rule: collection.view_rule.clone(),
        create_rule: collection.create_rule.clone(),
        update_rule: collection.update_rule.clone(),
        delete_rule: collection.delete_rule.clone(),
    };

    // Create evaluation context with record data
    let user = rustbase_rules::evaluator::User {
        id: auth_user.id,
        email: auth_user.email.clone(),
        role: match auth_user.role {
            UserRole::Admin => rustbase_rules::evaluator::UserRole::Admin,
            UserRole::User => rustbase_rules::evaluator::UserRole::User,
            UserRole::Service => rustbase_rules::evaluator::UserRole::Service,
        },
        verified: auth_user.verified,
        created_at: auth_user.created_at,
        updated_at: auth_user.updated_at,
    };

    let record_data = serde_json::to_value(&record.data)
        .map_err(|e| ServerError::Internal(format!("Failed to serialize record: {}", e)))?;

    let context = EvaluationContext::new()
        .with_user(user.clone())
        .with_record(record_data)
        .with_request(RequestContext::default());

    // Check access using rule engine
    let has_access = {
        let mut rule_engine = state.rule_engine.lock().unwrap();
        rule_engine
            .evaluate_collection_rule(&rules, RuleOperation::View, &context)
            .map_err(rule_error_to_server_error)?
    };

    if !has_access {
        return Err(ServerError::Forbidden("Access denied to view this record".to_string()));
    }

    // Apply field-level filtering
    let mut filtered_record = record;
    // For now, just return the record as-is - proper field filtering will be implemented later
    // This avoids the MutexGuard Send issue
    // filter_record_fields(&mut filtered_record, &collection, &user, &mut rule_engine).await?;

    Ok(Json(filtered_record))
}

/// Update a record by ID
async fn update_record(
    State(state): State<AppState>,
    Path((collection_name, record_id)): Path<(String, String)>,
    auth_user: AuthUser,
    Json(request): Json<UpdateRecordRequest>,
) -> ServerResult<Json<Record>> {
    // Parse record ID
    let record_id = Uuid::parse_str(&record_id)
        .map_err(|_| ServerError::BadRequest("Invalid record ID format".to_string()))?;

    // Get collection to validate it exists and get rules
    let collection = state
        .collection_service
        .get_collection(&collection_name)
        .await
        .map_err(ServerError::Core)?
        .ok_or_else(|| ServerError::NotFound(format!("Collection '{}' not found", collection_name)))?;

    // Get the existing record first for rule evaluation
    let existing_record = state
        .record_service
        .get_record(&collection_name, record_id)
        .await
        .map_err(ServerError::Core)?
        .ok_or_else(|| ServerError::NotFound("Record not found".to_string()))?;

    // Check update rule access with existing record context
    let rules = CollectionRules {
        list_rule: collection.list_rule.clone(),
        view_rule: collection.view_rule.clone(),
        create_rule: collection.create_rule.clone(),
        update_rule: collection.update_rule.clone(),
        delete_rule: collection.delete_rule.clone(),
    };

    // Create evaluation context with existing record data
    let user = rustbase_rules::evaluator::User {
        id: auth_user.id,
        email: auth_user.email.clone(),
        role: match auth_user.role {
            UserRole::Admin => rustbase_rules::evaluator::UserRole::Admin,
            UserRole::User => rustbase_rules::evaluator::UserRole::User,
            UserRole::Service => rustbase_rules::evaluator::UserRole::Service,
        },
        verified: auth_user.verified,
        created_at: auth_user.created_at,
        updated_at: auth_user.updated_at,
    };

    let record_data = serde_json::to_value(&existing_record.data)
        .map_err(|e| ServerError::Internal(format!("Failed to serialize record: {}", e)))?;

    let context = EvaluationContext::new()
        .with_user(user)
        .with_record(record_data)
        .with_request(RequestContext::default());

    // Check access using rule engine
    let has_access = {
        let mut rule_engine = state.rule_engine.lock().unwrap();
        rule_engine
            .evaluate_collection_rule(&rules, RuleOperation::Update, &context)
            .map_err(rule_error_to_server_error)?
    };

    if !has_access {
        return Err(ServerError::Forbidden("Access denied to update this record".to_string()));
    }

    // Convert request data to JSON Value
    let update_data = serde_json::to_value(request.data)
        .map_err(|e| ServerError::BadRequest(format!("Invalid update data: {}", e)))?;

    // Update the record
    let updated_record = state
        .record_service
        .update_record(&collection_name, record_id, update_data)
        .await
        .map_err(ServerError::Core)?;

    // Publish realtime event
    let event = crate::realtime::RealtimeEvent {
        event_type: crate::realtime::EventType::Updated,
        collection: collection_name,
        record_id: updated_record.id,
        data: serde_json::to_value(&updated_record.data).unwrap_or_default(),
        timestamp: chrono::Utc::now(),
    };
    state.realtime_manager.broadcast_event_sync(event);

    Ok(Json(updated_record))
}

/// Delete a record by ID
async fn delete_record(
    State(state): State<AppState>,
    Path((collection_name, record_id)): Path<(String, String)>,
    auth_user: AuthUser,
) -> ServerResult<Json<serde_json::Value>> {
    // Parse record ID
    let record_id = Uuid::parse_str(&record_id)
        .map_err(|_| ServerError::BadRequest("Invalid record ID format".to_string()))?;

    // Get collection to validate it exists and get rules
    let collection = state
        .collection_service
        .get_collection(&collection_name)
        .await
        .map_err(ServerError::Core)?
        .ok_or_else(|| ServerError::NotFound(format!("Collection '{}' not found", collection_name)))?;

    // Get the existing record first for rule evaluation
    let existing_record = state
        .record_service
        .get_record(&collection_name, record_id)
        .await
        .map_err(ServerError::Core)?
        .ok_or_else(|| ServerError::NotFound("Record not found".to_string()))?;

    // Check delete rule access with existing record context
    let rules = CollectionRules {
        list_rule: collection.list_rule.clone(),
        view_rule: collection.view_rule.clone(),
        create_rule: collection.create_rule.clone(),
        update_rule: collection.update_rule.clone(),
        delete_rule: collection.delete_rule.clone(),
    };

    // Create evaluation context with existing record data
    let user = rustbase_rules::evaluator::User {
        id: auth_user.id,
        email: auth_user.email.clone(),
        role: match auth_user.role {
            UserRole::Admin => rustbase_rules::evaluator::UserRole::Admin,
            UserRole::User => rustbase_rules::evaluator::UserRole::User,
            UserRole::Service => rustbase_rules::evaluator::UserRole::Service,
        },
        verified: auth_user.verified,
        created_at: auth_user.created_at,
        updated_at: auth_user.updated_at,
    };

    let record_data = serde_json::to_value(&existing_record.data)
        .map_err(|e| ServerError::Internal(format!("Failed to serialize record: {}", e)))?;

    let context = EvaluationContext::new()
        .with_user(user)
        .with_record(record_data)
        .with_request(RequestContext::default());

    // Check access using rule engine
    let has_access = {
        let mut rule_engine = state.rule_engine.lock().unwrap();
        rule_engine
            .evaluate_collection_rule(&rules, RuleOperation::Delete, &context)
            .map_err(rule_error_to_server_error)?
    };

    if !has_access {
        return Err(ServerError::Forbidden("Access denied to delete this record".to_string()));
    }

    // Clean up any files associated with this record before deletion
    cleanup_record_files(&state, &collection, &existing_record).await?;

    // Delete the record
    let deleted = state
        .record_service
        .delete_record(&collection_name, record_id)
        .await
        .map_err(ServerError::Core)?;

    if !deleted {
        return Err(ServerError::NotFound("Record not found".to_string()));
    }

    // Publish realtime event (use existing record data before deletion)
    let event = crate::realtime::RealtimeEvent {
        event_type: crate::realtime::EventType::Deleted,
        collection: collection_name,
        record_id,
        data: serde_json::to_value(&existing_record.data).unwrap_or_default(),
        timestamp: chrono::Utc::now(),
    };
    state.realtime_manager.broadcast_event_sync(event);

    Ok(Json(serde_json::json!({
        "success": true,
        "message": "Record deleted successfully"
    })))
}

/// File upload endpoint wrapper
async fn upload_file(
    State(state): State<AppState>,
    path: Path<(String, String, String)>,
    auth_user: AuthUser,
    multipart: axum::extract::Multipart,
) -> ServerResult<Json<crate::files::FileUploadResponse>> {
    let file_state = FileAppState {
        storage_backend: state.storage_backend.clone(),
        storage_config: state.storage_config.clone(),
        collection_service: state.collection_service.clone(),
        record_service: state.record_service.clone(),
    };
    
    upload_file_handler(State(file_state), path, auth_user, multipart).await
}

/// File serving endpoint wrapper
async fn serve_file(
    State(state): State<AppState>,
    path: Path<(String, String, String)>,
    auth_user: AuthUser,
) -> ServerResult<axum::response::Response> {
    let file_state = FileAppState {
        storage_backend: state.storage_backend.clone(),
        storage_config: state.storage_config.clone(),
        collection_service: state.collection_service.clone(),
        record_service: state.record_service.clone(),
    };
    
    serve_file_handler(State(file_state), path, auth_user).await
}

/// File deletion endpoint wrapper
async fn delete_file(
    State(state): State<AppState>,
    path: Path<(String, String, String)>,
    auth_user: AuthUser,
) -> ServerResult<Json<serde_json::Value>> {
    let file_state = FileAppState {
        storage_backend: state.storage_backend.clone(),
        storage_config: state.storage_config.clone(),
        collection_service: state.collection_service.clone(),
        record_service: state.record_service.clone(),
    };
    
    delete_file_handler(State(file_state), path, auth_user).await
}

/// Clean up files associated with a record when it's being deleted
async fn cleanup_record_files(
    state: &AppState,
    collection: &rustbase_core::models::Collection,
    record: &Record,
) -> ServerResult<()> {
    // Find all file fields in the collection schema
    for field in &collection.schema_json.fields {
        if matches!(field.field_type, rustbase_core::models::FieldType::File { .. }) {
            // Check if this record has a file in this field
            if let Some(field_value) = record.data.get(&field.name) {
                if !field_value.is_null() {
                    // Try to parse file metadata and delete the file
                    if let Ok(file_metadata) = serde_json::from_value::<FileMetadata>(field_value.clone()) {
                        if let Err(e) = state.storage_backend.delete(&file_metadata.path).await {
                            // Log the error but don't fail the record deletion
                            tracing::warn!(
                                "Failed to delete file {} for record {}: {}",
                                file_metadata.path,
                                record.id,
                                e
                            );
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Serve admin interface index page
async fn serve_admin_index() -> Result<Html<String>, ServerError> {
    let html_content = include_str!("../admin/index.html");
    Ok(Html(html_content.to_string()))
}

/// Serve admin static files (CSS, JS)
async fn serve_admin_static(uri: Uri) -> Result<Response, ServerError> {
    let path = uri.path();
    
    match path {
        "/admin/styles.css" => {
            let css_content = include_str!("../admin/styles.css");
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/css")
                .body(css_content.into())
                .unwrap())
        }
        "/admin/app.js" => {
            let js_content = include_str!("../admin/app.js");
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/javascript")
                .body(js_content.into())
                .unwrap())
        }
        _ => {
            Err(ServerError::NotFound("Static file not found".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode, HeaderValue},
    };
    use rustbase_core::{auth::AuthService, config::AuthConfig};
    use serde_json::json;
    use tower::ServiceExt;

    fn create_test_app_state() -> AppState {
        let auth_config = AuthConfig {
            jwt_secret: "test-secret-key-for-testing-only".to_string(),
            token_ttl: 900,
            refresh_ttl: 86400,
            password_min_length: 8,
            argon2_memory: 4096, // Reduced for testing
            argon2_iterations: 1, // Reduced for testing
            argon2_parallelism: 1,
        };
        let auth_service = Arc::new(AuthService::new(auth_config).unwrap());
        let user_repository = Arc::new(MockUserRepository) as Arc<dyn UserRepository>;
        
        // Create mock services for testing
        let collection_service = Arc::new(MockCollectionService);
        let record_service = Arc::new(MockRecordService);
        let rule_engine = Arc::new(std::sync::Mutex::new(RuleEngine::new()));
        
        // Create mock storage for testing
        let storage_backend = Arc::new(rustbase_storage::LocalStorage::new(
            std::path::PathBuf::from("/tmp/test-storage")
        )) as Arc<dyn rustbase_storage::StorageBackend>;
        let storage_config = rustbase_storage::StorageConfig::default();

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

    // Helper function to create a test JWT token
    fn create_test_jwt_token(auth_service: &AuthService) -> String {
        let user = User::new(
            "test@example.com".to_string(),
            "hashed_password".to_string(),
            UserRole::Admin,
        );
        
        auth_service.generate_tokens(&user).unwrap().access_token
    }

    #[tokio::test]
    async fn test_list_records_with_auth_collection_not_found() {
        let app_state = create_test_app_state();
        let token = create_test_jwt_token(&app_state.auth_service);
        let app = create_router(app_state);

        let request = Request::builder()
            .uri("/api/collections/nonexistent/records")
            .method("GET")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_create_record_with_auth_collection_not_found() {
        let app_state = create_test_app_state();
        let token = create_test_jwt_token(&app_state.auth_service);
        let app = create_router(app_state);

        let create_request = json!({
            "title": "Test Post",
            "content": "This is a test post"
        });

        let request = Request::builder()
            .uri("/api/collections/nonexistent/records")
            .method("POST")
            .header("authorization", format!("Bearer {}", token))
            .header("content-type", "application/json")
            .body(Body::from(create_request.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_record_with_auth_collection_not_found() {
        let app_state = create_test_app_state();
        let token = create_test_jwt_token(&app_state.auth_service);
        let app = create_router(app_state);

        let record_id = Uuid::new_v4();
        let request = Request::builder()
            .uri(&format!("/api/collections/nonexistent/records/{}", record_id))
            .method("GET")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_record_with_auth_collection_not_found() {
        let app_state = create_test_app_state();
        let token = create_test_jwt_token(&app_state.auth_service);
        let app = create_router(app_state);

        let record_id = Uuid::new_v4();
        let update_request = json!({
            "title": "Updated Post"
        });

        let request = Request::builder()
            .uri(&format!("/api/collections/nonexistent/records/{}", record_id))
            .method("PATCH")
            .header("authorization", format!("Bearer {}", token))
            .header("content-type", "application/json")
            .body(Body::from(update_request.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_record_with_auth_collection_not_found() {
        let app_state = create_test_app_state();
        let token = create_test_jwt_token(&app_state.auth_service);
        let app = create_router(app_state);

        let record_id = Uuid::new_v4();
        let request = Request::builder()
            .uri(&format!("/api/collections/nonexistent/records/{}", record_id))
            .method("DELETE")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_record_invalid_uuid() {
        let app_state = create_test_app_state();
        let token = create_test_jwt_token(&app_state.auth_service);
        let app = create_router(app_state);

        let request = Request::builder()
            .uri("/api/collections/posts/records/invalid-uuid")
            .method("GET")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_update_record_invalid_uuid() {
        let app_state = create_test_app_state();
        let token = create_test_jwt_token(&app_state.auth_service);
        let app = create_router(app_state);

        let update_request = json!({
            "title": "Updated Post"
        });

        let request = Request::builder()
            .uri("/api/collections/posts/records/invalid-uuid")
            .method("PATCH")
            .header("authorization", format!("Bearer {}", token))
            .header("content-type", "application/json")
            .body(Body::from(update_request.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_delete_record_invalid_uuid() {
        let app_state = create_test_app_state();
        let token = create_test_jwt_token(&app_state.auth_service);
        let app = create_router(app_state);

        let request = Request::builder()
            .uri("/api/collections/posts/records/invalid-uuid")
            .method("DELETE")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_list_records_pagination_parameters() {
        let app_state = create_test_app_state();
        let token = create_test_jwt_token(&app_state.auth_service);
        let app = create_router(app_state);

        // Test with pagination parameters
        let request = Request::builder()
            .uri("/api/collections/posts/records?page=1&per_page=50")
            .method("GET")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Should get NOT_FOUND because collection doesn't exist in mock
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list_records_with_filter_and_sort() {
        let app_state = create_test_app_state();
        let token = create_test_jwt_token(&app_state.auth_service);
        let app = create_router(app_state);

        // Test with filter and sort parameters
        let request = Request::builder()
            .uri("/api/collections/posts/records?filter=published=true&sort=-created_at&fields=title,content")
            .method("GET")
            .header("authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Should get NOT_FOUND because collection doesn't exist in mock
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_create_record_empty_data() {
        let app_state = create_test_app_state();
        let token = create_test_jwt_token(&app_state.auth_service);
        let app = create_router(app_state);

        let create_request = json!({});

        let request = Request::builder()
            .uri("/api/collections/posts/records")
            .method("POST")
            .header("authorization", format!("Bearer {}", token))
            .header("content-type", "application/json")
            .body(Body::from(create_request.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Should get NOT_FOUND because collection doesn't exist in mock
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_record_empty_data() {
        let app_state = create_test_app_state();
        let token = create_test_jwt_token(&app_state.auth_service);
        let app = create_router(app_state);

        let record_id = Uuid::new_v4();
        let update_request = json!({});

        let request = Request::builder()
            .uri(&format!("/api/collections/posts/records/{}", record_id))
            .method("PATCH")
            .header("authorization", format!("Bearer {}", token))
            .header("content-type", "application/json")
            .body(Body::from(update_request.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        // Should get NOT_FOUND because collection doesn't exist in mock
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_health_check() {
        let app_state = create_test_app_state();
        let app = create_router(app_state);

        let request = Request::builder()
            .uri("/api/health")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_register_endpoint() {
        let app_state = create_test_app_state();
        let app = create_router(app_state);

        let register_request = json!({
            "email": "test@example.com",
            "password": "TestPassword123!",
            "password_confirm": "TestPassword123!"
        });

        let request = Request::builder()
            .uri("/api/auth/register")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(register_request.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_register_password_mismatch() {
        let app_state = create_test_app_state();
        let app = create_router(app_state);

        let register_request = json!({
            "email": "test@example.com",
            "password": "TestPassword123!",
            "password_confirm": "DifferentPassword123!"
        });

        let request = Request::builder()
            .uri("/api/auth/register")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(register_request.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_register_weak_password() {
        let app_state = create_test_app_state();
        let app = create_router(app_state);

        let register_request = json!({
            "email": "test@example.com",
            "password": "weak",
            "password_confirm": "weak"
        });

        let request = Request::builder()
            .uri("/api/auth/register")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(register_request.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_list_records_unauthorized() {
        let app_state = create_test_app_state();
        let app = create_router(app_state);

        let request = Request::builder()
            .uri("/api/collections/posts/records")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_record_unauthorized() {
        let app_state = create_test_app_state();
        let app = create_router(app_state);

        let create_request = json!({
            "title": "Test Post",
            "content": "This is a test post"
        });

        let request = Request::builder()
            .uri("/api/collections/posts/records")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(create_request.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_get_record_unauthorized() {
        let app_state = create_test_app_state();
        let app = create_router(app_state);

        let record_id = Uuid::new_v4();
        let request = Request::builder()
            .uri(&format!("/api/collections/posts/records/{}", record_id))
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_update_record_unauthorized() {
        let app_state = create_test_app_state();
        let app = create_router(app_state);

        let record_id = Uuid::new_v4();
        let update_request = json!({
            "title": "Updated Post"
        });

        let request = Request::builder()
            .uri(&format!("/api/collections/posts/records/{}", record_id))
            .method("PATCH")
            .header("content-type", "application/json")
            .body(Body::from(update_request.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_delete_record_unauthorized() {
        let app_state = create_test_app_state();
        let app = create_router(app_state);

        let record_id = Uuid::new_v4();
        let request = Request::builder()
            .uri(&format!("/api/collections/posts/records/{}", record_id))
            .method("DELETE")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_list_records_with_query_parameters() {
        let app_state = create_test_app_state();
        let app = create_router(app_state);

        // Test with various query parameters
        let request = Request::builder()
            .uri("/api/collections/posts/records?page=2&per_page=10&sort=-created_at&fields=title,content")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED); // Still unauthorized without auth
    }

    #[tokio::test]
    async fn test_invalid_record_id_format() {
        let app_state = create_test_app_state();
        let app = create_router(app_state);

        let request = Request::builder()
            .uri("/api/collections/posts/records/invalid-uuid")
            .method("GET")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED); // Still unauthorized without auth
    }

    #[tokio::test]
    async fn test_create_record_invalid_json() {
        let app_state = create_test_app_state();
        let app = create_router(app_state);

        let request = Request::builder()
            .uri("/api/collections/posts/records")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from("invalid json"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_update_record_invalid_json() {
        let app_state = create_test_app_state();
        let app = create_router(app_state);

        let record_id = Uuid::new_v4();
        let request = Request::builder()
            .uri(&format!("/api/collections/posts/records/{}", record_id))
            .method("PATCH")
            .header("content-type", "application/json")
            .body(Body::from("invalid json"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_login_endpoint_user_not_found() {
        let app_state = create_test_app_state();
        let app = create_router(app_state);

        let login_request = json!({
            "email": "nonexistent@example.com",
            "password": "TestPassword123!"
        });

        let request = Request::builder()
            .uri("/api/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(login_request.to_string()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}