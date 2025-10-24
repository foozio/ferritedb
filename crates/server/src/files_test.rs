use super::*;
use crate::middleware::AuthUser;
use axum::{
    body::Body,
    extract::multipart::Field,
    http::{Request, StatusCode},
};
use ferritedb_core::{
    auth::AuthService,
    config::AuthConfig,
    models::{
        Collection, CollectionSchema, CollectionType, Field as CoreField, FieldType, Record, User,
        UserRole,
    },
    CollectionService, RecordService,
};
use ferritedb_storage::{LocalStorage, StorageBackend, StorageConfig, StorageType};
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::tempdir;
use tower::ServiceExt;
use uuid::Uuid;

// Mock implementations for testing
struct MockCollectionService {
    collections: std::sync::Mutex<HashMap<String, Collection>>,
}

impl MockCollectionService {
    fn new() -> Self {
        Self {
            collections: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn add_collection(&self, collection: Collection) {
        let mut collections = self.collections.lock().unwrap();
        collections.insert(collection.name.clone(), collection);
    }
}

#[axum::async_trait]
impl FileCollectionService for MockCollectionService {
    async fn get_collection(&self, name: &str) -> ferritedb_core::CoreResult<Option<Collection>> {
        let collections = self.collections.lock().unwrap();
        Ok(collections.get(name).cloned())
    }
}

struct MockRecordService {
    records: std::sync::Mutex<HashMap<(String, Uuid), Record>>,
}

impl MockRecordService {
    fn new() -> Self {
        Self {
            records: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn add_record(&self, collection_name: &str, record: Record) {
        let mut records = self.records.lock().unwrap();
        records.insert((collection_name.to_string(), record.id), record);
    }
}

#[axum::async_trait]
impl FileRecordService for MockRecordService {
    async fn get_record(
        &self,
        collection_name: &str,
        record_id: Uuid,
    ) -> ferritedb_core::CoreResult<Option<Record>> {
        let records = self.records.lock().unwrap();
        Ok(records
            .get(&(collection_name.to_string(), record_id))
            .cloned())
    }

    async fn update_record(
        &self,
        collection_name: &str,
        record_id: Uuid,
        data: serde_json::Value,
    ) -> ferritedb_core::CoreResult<Record> {
        let mut records = self.records.lock().unwrap();
        if let Some(record) = records.get_mut(&(collection_name.to_string(), record_id)) {
            if let Some(data_obj) = data.as_object() {
                for (key, value) in data_obj {
                    record.data.insert(key.clone(), value.clone());
                }
            }
            record.updated_at = chrono::Utc::now();
            Ok(record.clone())
        } else {
            Err(ferritedb_core::CoreError::RecordNotFound(
                record_id.to_string(),
            ))
        }
    }

    async fn delete_record(
        &self,
        collection_name: &str,
        record_id: Uuid,
    ) -> ferritedb_core::CoreResult<bool> {
        let mut records = self.records.lock().unwrap();
        Ok(records
            .remove(&(collection_name.to_string(), record_id))
            .is_some())
    }
}

fn create_test_file_app_state() -> (TempDir, FileAppState) {
    let temp_dir = tempdir().unwrap();
    let storage_backend =
        Arc::new(LocalStorage::new(temp_dir.path().to_path_buf())) as Arc<dyn StorageBackend>;
    let storage_config = StorageConfig {
        storage_type: StorageType::Local {
            path: temp_dir.path().to_path_buf(),
        },
        max_file_size: 1024 * 1024, // 1MB
        allowed_extensions: vec!["jpg".to_string(), "png".to_string(), "txt".to_string()],
        blocked_extensions: vec!["exe".to_string()],
    };

    let collection_service = Arc::new(MockCollectionService::new());
    let record_service = Arc::new(MockRecordService::new());

    // Create a test collection with file fields
    let mut schema = CollectionSchema::new();
    schema.add_field(CoreField::new(
        Uuid::new_v4(),
        "avatar".to_string(),
        FieldType::File {
            max_size: Some(512 * 1024), // 512KB
            allowed_types: Some(vec!["image/jpeg".to_string(), "image/png".to_string()]),
        },
    ));
    schema.add_field(CoreField::new(
        Uuid::new_v4(),
        "document".to_string(),
        FieldType::File {
            max_size: None,
            allowed_types: None,
        },
    ));

    let collection = Collection::new("users".to_string(), CollectionType::Base).with_schema(schema);

    collection_service.add_collection(collection);

    // Create a test record
    let record_id = Uuid::new_v4();
    let mut record_data = HashMap::new();
    record_data.insert("name".to_string(), json!("Test User"));

    let record = Record {
        id: record_id,
        collection_id: Uuid::new_v4(),
        data: record_data,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    record_service.add_record("users", record);

    let state = FileAppState {
        storage_backend,
        storage_config,
        collection_service: collection_service.clone() as Arc<dyn FileCollectionService>,
        record_service: record_service.clone() as Arc<dyn FileRecordService>,
    };

    (temp_dir, state)
}

fn create_test_user() -> AuthUser {
    AuthUser {
        id: Uuid::new_v4(),
        email: "test@example.com".to_string(),
        role: UserRole::User,
        verified: true,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn test_validate_file_field_success() {
    let (_temp_dir, state) = create_test_file_app_state();
    let collection = state
        .collection_service
        .get_collection("users")
        .await
        .unwrap()
        .unwrap();

    // Test valid file field
    let result = validate_file_field(&collection, "avatar");
    assert!(result.is_ok());

    let result = validate_file_field(&collection, "document");
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_validate_file_field_not_found() {
    let (_temp_dir, state) = create_test_file_app_state();
    let collection = state
        .collection_service
        .get_collection("users")
        .await
        .unwrap()
        .unwrap();

    let result = validate_file_field(&collection, "nonexistent");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("does not exist"));
}

#[tokio::test]
async fn test_validate_file_field_wrong_type() {
    let (_temp_dir, state) = create_test_file_app_state();
    let mut collection = state
        .collection_service
        .get_collection("users")
        .await
        .unwrap()
        .unwrap();

    // Add a non-file field
    collection.schema_json.add_field(CoreField::new(
        Uuid::new_v4(),
        "name".to_string(),
        FieldType::Text,
    ));

    let result = validate_file_field(&collection, "name");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not a file field"));
}

#[tokio::test]
async fn test_validate_file_success() {
    let (_temp_dir, state) = create_test_file_app_state();
    let collection = state
        .collection_service
        .get_collection("users")
        .await
        .unwrap()
        .unwrap();
    let field = collection.schema_json.get_field("avatar").unwrap();

    let result = validate_file(
        &state.storage_config,
        field,
        "test.jpg",
        1024,
        &Some("image/jpeg".to_string()),
    );
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_validate_file_size_too_large() {
    let (_temp_dir, state) = create_test_file_app_state();
    let collection = state
        .collection_service
        .get_collection("users")
        .await
        .unwrap()
        .unwrap();
    let field = collection.schema_json.get_field("avatar").unwrap();

    // Test field-specific size limit (512KB)
    let result = validate_file(
        &state.storage_config,
        field,
        "test.jpg",
        600 * 1024, // 600KB - exceeds field limit
        &Some("image/jpeg".to_string()),
    );
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("field maximum size"));
}

#[tokio::test]
async fn test_validate_file_wrong_content_type() {
    let (_temp_dir, state) = create_test_file_app_state();
    let collection = state
        .collection_service
        .get_collection("users")
        .await
        .unwrap()
        .unwrap();
    let field = collection.schema_json.get_field("avatar").unwrap();

    let result = validate_file(
        &state.storage_config,
        field,
        "test.pdf",
        1024,
        &Some("application/pdf".to_string()),
    );
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("not allowed for this field"));
}

#[tokio::test]
async fn test_validate_file_blocked_extension() {
    let (_temp_dir, state) = create_test_file_app_state();
    let collection = state
        .collection_service
        .get_collection("users")
        .await
        .unwrap()
        .unwrap();
    let field = collection.schema_json.get_field("document").unwrap();

    let result = validate_file(
        &state.storage_config,
        field,
        "malware.exe",
        1024,
        &Some("application/octet-stream".to_string()),
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not allowed"));
}

#[tokio::test]
async fn test_generate_file_path() {
    let path = generate_file_path(
        "users",
        "123e4567-e89b-12d3-a456-426614174000",
        "avatar",
        "profile.jpg",
    );
    assert_eq!(
        path,
        "users/123e4567-e89b-12d3-a456-426614174000/avatar/profile.jpg"
    );

    // Test path sanitization
    let path = generate_file_path("users", "record-id", "field", "file/with/slashes.jpg");
    assert_eq!(path, "users/record-id/field/file_with_slashes.jpg");
}

#[tokio::test]
async fn test_file_metadata_generate_url() {
    let metadata = FileMetadata {
        filename: "test.jpg".to_string(),
        size: 1024,
        content_type: Some("image/jpeg".to_string()),
        path: "users/123/avatar/test.jpg".to_string(),
        uploaded_at: chrono::Utc::now(),
    };

    let url = metadata.generate_url("users", "123", "avatar");
    assert_eq!(url, "/api/files/users/123/avatar");
}

#[tokio::test]
async fn test_get_file_metadata_from_record() {
    let mut record_data = HashMap::new();
    let file_metadata = FileMetadata {
        filename: "test.jpg".to_string(),
        size: 1024,
        content_type: Some("image/jpeg".to_string()),
        path: "users/123/avatar/test.jpg".to_string(),
        uploaded_at: chrono::Utc::now(),
    };

    record_data.insert(
        "avatar".to_string(),
        serde_json::to_value(&file_metadata).unwrap(),
    );

    let record = Record {
        id: Uuid::new_v4(),
        collection_id: Uuid::new_v4(),
        data: record_data,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let result = get_file_metadata_from_record(&record, "avatar");
    assert!(result.is_ok());

    let retrieved_metadata = result.unwrap();
    assert_eq!(retrieved_metadata.filename, "test.jpg");
    assert_eq!(retrieved_metadata.size, 1024);
}

#[tokio::test]
async fn test_get_file_metadata_from_record_field_not_found() {
    let record = Record {
        id: Uuid::new_v4(),
        collection_id: Uuid::new_v4(),
        data: HashMap::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let result = get_file_metadata_from_record(&record, "nonexistent");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));
}

#[tokio::test]
async fn test_get_file_metadata_from_record_null_field() {
    let mut record_data = HashMap::new();
    record_data.insert("avatar".to_string(), serde_json::Value::Null);

    let record = Record {
        id: Uuid::new_v4(),
        collection_id: Uuid::new_v4(),
        data: record_data,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let result = get_file_metadata_from_record(&record, "avatar");
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("No file associated"));
}

#[tokio::test]
async fn test_get_file_metadata_from_record_invalid_metadata() {
    let mut record_data = HashMap::new();
    record_data.insert("avatar".to_string(), json!("invalid metadata"));

    let record = Record {
        id: Uuid::new_v4(),
        collection_id: Uuid::new_v4(),
        data: record_data,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    let result = get_file_metadata_from_record(&record, "avatar");
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Invalid file metadata"));
}

// Integration tests would require setting up a full Axum app with multipart support
// These are more complex and would typically be done in a separate integration test file
// For now, we've covered the core logic with unit tests
