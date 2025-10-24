use axum::{
    body::Bytes,
    extract::{Multipart, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use ferritedb_core::models::{Collection, Record};
use ferritedb_storage::{StorageBackend, StorageConfig};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    error::{ServerError, ServerResult},
    middleware::AuthUser,
};

#[axum::async_trait]
pub trait FileCollectionService: Send + Sync {
    async fn get_collection(&self, name: &str) -> ferritedb_core::CoreResult<Option<Collection>>;
}

#[axum::async_trait]
pub trait FileRecordService: Send + Sync {
    async fn get_record(
        &self,
        collection_name: &str,
        record_id: Uuid,
    ) -> ferritedb_core::CoreResult<Option<Record>>;
    async fn update_record(
        &self,
        collection_name: &str,
        record_id: Uuid,
        data: Value,
    ) -> ferritedb_core::CoreResult<Record>;
    async fn delete_record(
        &self,
        collection_name: &str,
        record_id: Uuid,
    ) -> ferritedb_core::CoreResult<bool>;
}

/// File upload response
#[derive(Debug, Serialize)]
pub struct FileUploadResponse {
    pub filename: String,
    pub size: u64,
    pub content_type: Option<String>,
    pub url: String,
}

/// File metadata stored in record fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub filename: String,
    pub size: u64,
    pub content_type: Option<String>,
    pub path: String,
    pub uploaded_at: chrono::DateTime<chrono::Utc>,
}

impl FileMetadata {
    /// Generate a public URL for accessing this file
    pub fn generate_url(&self, collection: &str, record_id: &str, field: &str) -> String {
        format!("/api/files/{}/{}/{}", collection, record_id, field)
    }
}

/// Application state for file operations
#[derive(Clone)]
pub struct FileAppState {
    pub storage_backend: Arc<dyn StorageBackend>,
    pub storage_config: StorageConfig,
    pub collection_service: Arc<dyn FileCollectionService>,
    pub record_service: Arc<dyn FileRecordService>,
}

/// Upload a file to a specific collection record field
pub async fn upload_file(
    State(state): State<FileAppState>,
    Path((collection_name, record_id, field_name)): Path<(String, String, String)>,
    _auth_user: AuthUser,
    mut multipart: Multipart,
) -> ServerResult<Json<FileUploadResponse>> {
    // Parse record ID
    let record_id = Uuid::parse_str(&record_id)
        .map_err(|_| ServerError::BadRequest("Invalid record ID format".to_string()))?;

    // Validate collection exists
    let collection = state
        .collection_service
        .get_collection(&collection_name)
        .await
        .map_err(ServerError::Core)?
        .ok_or_else(|| {
            ServerError::NotFound(format!("Collection '{}' not found", collection_name))
        })?;

    // Validate record exists
    let _record = state
        .record_service
        .get_record(&collection_name, record_id)
        .await
        .map_err(ServerError::Core)?
        .ok_or_else(|| ServerError::NotFound("Record not found".to_string()))?;

    // TODO: Add rule-based access control for file uploads
    // For now, we'll allow authenticated users to upload files

    // Validate field exists and is a file field
    validate_file_field(&collection, &field_name)?;

    // Get the field definition for validation
    let field = collection
        .schema_json
        .get_field(&field_name)
        .ok_or_else(|| ServerError::BadRequest(format!("Field '{}' not found", field_name)))?;

    // Process multipart upload
    let mut file_data: Option<(String, Bytes, Option<String>)> = None;

    while let Some(multipart_field) = multipart
        .next_field()
        .await
        .map_err(|e| ServerError::BadRequest(format!("Invalid multipart data: {}", e)))?
    {
        if let Some(name) = multipart_field.name() {
            if name == "file" {
                let filename = multipart_field
                    .file_name()
                    .ok_or_else(|| ServerError::BadRequest("No filename provided".to_string()))?
                    .to_string();

                let content_type = multipart_field.content_type().map(|ct| ct.to_string());

                let data = multipart_field.bytes().await.map_err(|e| {
                    ServerError::BadRequest(format!("Failed to read file data: {}", e))
                })?;

                file_data = Some((filename, data, content_type));
                break;
            }
        }
    }

    let (filename, data, content_type) = file_data
        .ok_or_else(|| ServerError::BadRequest("No file provided in multipart data".to_string()))?;

    // Validate file against both global config and field constraints
    validate_file(
        &state.storage_config,
        field,
        &filename,
        data.len(),
        &content_type,
    )?;

    // Generate storage path
    let file_path = generate_file_path(
        &collection_name,
        &record_id.to_string(),
        &field_name,
        &filename,
    );

    // Store file
    let metadata = state
        .storage_backend
        .store(&file_path, &data)
        .await
        .map_err(|e| ServerError::Internal(format!("Failed to store file: {}", e)))?;

    // Create file metadata
    let file_metadata = FileMetadata {
        filename: filename.clone(),
        size: metadata.size,
        content_type: content_type.clone(),
        path: file_path.clone(),
        uploaded_at: chrono::Utc::now(),
    };

    // Update record with file metadata
    let mut update_data = serde_json::Map::new();
    update_data.insert(
        field_name.clone(),
        serde_json::to_value(&file_metadata).map_err(|e| {
            ServerError::Internal(format!("Failed to serialize file metadata: {}", e))
        })?,
    );

    state
        .record_service
        .update_record(&collection_name, record_id, Value::Object(update_data))
        .await
        .map_err(ServerError::Core)?;

    // Generate file URL
    let file_url = format!(
        "/api/files/{}/{}/{}",
        collection_name, record_id, field_name
    );

    Ok(Json(FileUploadResponse {
        filename,
        size: metadata.size,
        content_type,
        url: file_url,
    }))
}

/// Serve a file from a specific collection record field
pub async fn serve_file(
    State(state): State<FileAppState>,
    Path((collection_name, record_id, field_name)): Path<(String, String, String)>,
    _auth_user: AuthUser,
) -> ServerResult<Response> {
    // Parse record ID
    let record_id = Uuid::parse_str(&record_id)
        .map_err(|_| ServerError::BadRequest("Invalid record ID format".to_string()))?;

    // Validate collection exists
    let _collection = state
        .collection_service
        .get_collection(&collection_name)
        .await
        .map_err(ServerError::Core)?
        .ok_or_else(|| {
            ServerError::NotFound(format!("Collection '{}' not found", collection_name))
        })?;

    // Get record
    let record = state
        .record_service
        .get_record(&collection_name, record_id)
        .await
        .map_err(ServerError::Core)?
        .ok_or_else(|| ServerError::NotFound("Record not found".to_string()))?;

    // TODO: Add rule-based access control for file access
    // For now, we'll allow authenticated users to access files

    // Get file metadata from record
    let file_metadata = get_file_metadata_from_record(&record, &field_name)?;

    // Retrieve file from storage
    let file_data = state
        .storage_backend
        .retrieve(&file_metadata.path)
        .await
        .map_err(|e| match e {
            ferritedb_storage::StorageError::NotFound(_) => {
                ServerError::NotFound("File not found".to_string())
            }
            _ => ServerError::Internal(format!("Failed to retrieve file: {}", e)),
        })?;

    // Build response with appropriate headers
    let mut headers = HeaderMap::new();

    // Set content type
    if let Some(content_type) = &file_metadata.content_type {
        headers.insert(
            header::CONTENT_TYPE,
            content_type
                .parse()
                .unwrap_or_else(|_| "application/octet-stream".parse().unwrap()),
        );
    } else {
        headers.insert(
            header::CONTENT_TYPE,
            "application/octet-stream".parse().unwrap(),
        );
    }

    // Set content length
    headers.insert(
        header::CONTENT_LENGTH,
        file_data.len().to_string().parse().unwrap(),
    );

    // Set content disposition for download
    let disposition = format!("attachment; filename=\"{}\"", file_metadata.filename);
    headers.insert(header::CONTENT_DISPOSITION, disposition.parse().unwrap());

    // Set cache headers
    headers.insert(
        header::CACHE_CONTROL,
        "public, max-age=31536000".parse().unwrap(), // 1 year
    );

    Ok((StatusCode::OK, headers, file_data).into_response())
}

/// Delete a file from a specific collection record field
pub async fn delete_file(
    State(state): State<FileAppState>,
    Path((collection_name, record_id, field_name)): Path<(String, String, String)>,
    _auth_user: AuthUser,
) -> ServerResult<Json<Value>> {
    // Parse record ID
    let record_id = Uuid::parse_str(&record_id)
        .map_err(|_| ServerError::BadRequest("Invalid record ID format".to_string()))?;

    // Validate collection exists
    let _collection = state
        .collection_service
        .get_collection(&collection_name)
        .await
        .map_err(ServerError::Core)?
        .ok_or_else(|| {
            ServerError::NotFound(format!("Collection '{}' not found", collection_name))
        })?;

    // Get record
    let record = state
        .record_service
        .get_record(&collection_name, record_id)
        .await
        .map_err(ServerError::Core)?
        .ok_or_else(|| ServerError::NotFound("Record not found".to_string()))?;

    // TODO: Add rule-based access control for file deletion
    // For now, we'll allow authenticated users to delete files

    // Get file metadata from record
    let file_metadata = get_file_metadata_from_record(&record, &field_name)?;

    // Delete file from storage
    state
        .storage_backend
        .delete(&file_metadata.path)
        .await
        .map_err(|e| ServerError::Internal(format!("Failed to delete file: {}", e)))?;

    // Update record to remove file metadata
    let mut update_data = serde_json::Map::new();
    update_data.insert(field_name, Value::Null);

    state
        .record_service
        .update_record(&collection_name, record_id, Value::Object(update_data))
        .await
        .map_err(ServerError::Core)?;

    Ok(Json(json!({
        "success": true,
        "message": "File deleted successfully"
    })))
}

/// Validate that a field is a file field
fn validate_file_field(collection: &Collection, field_name: &str) -> ServerResult<()> {
    if field_name.is_empty() {
        return Err(ServerError::BadRequest(
            "Field name cannot be empty".to_string(),
        ));
    }

    // Check if field exists in collection schema
    let field = collection
        .schema_json
        .get_field(field_name)
        .ok_or_else(|| {
            ServerError::BadRequest(format!(
                "Field '{}' does not exist in collection",
                field_name
            ))
        })?;

    // Check if field is of type File
    match &field.field_type {
        ferritedb_core::models::FieldType::File { .. } => Ok(()),
        _ => Err(ServerError::BadRequest(format!(
            "Field '{}' is not a file field (type: {})",
            field_name, field.field_type
        ))),
    }
}

/// Validate file against storage configuration and field constraints
fn validate_file(
    config: &StorageConfig,
    field: &ferritedb_core::models::Field,
    filename: &str,
    size: usize,
    content_type: &Option<String>,
) -> ServerResult<()> {
    // Check global storage configuration
    if !config.is_size_allowed(size as u64) {
        return Err(ServerError::BadRequest(format!(
            "File size {} exceeds maximum allowed size of {} bytes",
            size, config.max_file_size
        )));
    }

    if !config.is_file_allowed(filename) {
        return Err(ServerError::BadRequest(format!(
            "File type not allowed: {}",
            filename
        )));
    }

    // Check field-specific constraints
    if let ferritedb_core::models::FieldType::File {
        max_size,
        allowed_types,
    } = &field.field_type
    {
        // Check field-specific size limit
        if let Some(field_max_size) = max_size {
            if size as u64 > *field_max_size {
                return Err(ServerError::BadRequest(format!(
                    "File size {} exceeds field maximum size of {} bytes",
                    size, field_max_size
                )));
            }
        }

        // Check field-specific allowed types
        if let Some(allowed_mime_types) = allowed_types {
            if let Some(ct) = content_type {
                if !allowed_mime_types.contains(ct) {
                    return Err(ServerError::BadRequest(format!(
                        "Content type '{}' not allowed for this field. Allowed types: {}",
                        ct,
                        allowed_mime_types.join(", ")
                    )));
                }
            } else {
                return Err(ServerError::BadRequest(
                    "Content type required for this field".to_string(),
                ));
            }
        }
    }

    Ok(())
}

/// Generate storage path for a file
fn generate_file_path(collection: &str, record_id: &str, field: &str, filename: &str) -> String {
    // Create a safe filename by removing any path separators
    let safe_filename = filename.replace(['/', '\\'], "_");
    format!("{}/{}/{}/{}", collection, record_id, field, safe_filename)
}

/// Extract file metadata from a record field
fn get_file_metadata_from_record(record: &Record, field_name: &str) -> ServerResult<FileMetadata> {
    let field_value = record.data.get(field_name).ok_or_else(|| {
        ServerError::NotFound(format!("Field '{}' not found in record", field_name))
    })?;

    if field_value.is_null() {
        return Err(ServerError::NotFound(
            "No file associated with this field".to_string(),
        ));
    }

    serde_json::from_value(field_value.clone())
        .map_err(|e| ServerError::BadRequest(format!("Invalid file metadata: {}", e)))
}

#[axum::async_trait]
impl FileCollectionService for crate::routes::MockCollectionService {
    async fn get_collection(&self, name: &str) -> ferritedb_core::CoreResult<Option<Collection>> {
        crate::routes::MockCollectionService::get_collection(self, name).await
    }
}

#[axum::async_trait]
impl FileRecordService for crate::routes::MockRecordService {
    async fn get_record(
        &self,
        collection_name: &str,
        record_id: Uuid,
    ) -> ferritedb_core::CoreResult<Option<Record>> {
        crate::routes::MockRecordService::get_record(self, collection_name, record_id).await
    }

    async fn update_record(
        &self,
        collection_name: &str,
        record_id: Uuid,
        data: Value,
    ) -> ferritedb_core::CoreResult<Record> {
        crate::routes::MockRecordService::update_record(self, collection_name, record_id, data)
            .await
    }

    async fn delete_record(
        &self,
        collection_name: &str,
        record_id: Uuid,
    ) -> ferritedb_core::CoreResult<bool> {
        crate::routes::MockRecordService::delete_record(self, collection_name, record_id).await
    }
}

#[cfg(test)]
#[path = "files_test.rs"]
mod tests;
