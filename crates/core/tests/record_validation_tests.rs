use ferritedb_core::{
    collections::CollectionService,
    models::{AccessRules, CollectionSchema, CollectionType, CreateCollectionRequest, Field, FieldType},
    repository::CollectionRepository,
    Database, RecordService,
};
use serde_json::json;
use tempfile::TempDir;
use uuid::Uuid;

async fn setup_services() -> (TempDir, Database, CollectionService, RecordService) {
    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("test.db");
    let database_url = format!("sqlite:{}", db_path.display());

    let db = Database::new(&database_url, 5, 30)
        .await
        .expect("db");
    db.migrate().await.expect("migrate");

    let repository = CollectionRepository::new(db.pool().clone());
    let collection_service = CollectionService::new(repository);
    let record_service = RecordService::new(db.pool().clone(), collection_service.clone());

    (temp_dir, db, collection_service, record_service)
}

async fn create_test_collection(collection_service: &CollectionService) {
    let mut schema = CollectionSchema::new();
    schema
        .add_field(Field::new(Uuid::new_v4(), "title".to_string(), FieldType::Text).required());

    let request = CreateCollectionRequest {
        name: "validation_posts".to_string(),
        collection_type: Some(CollectionType::Base),
        schema,
        rules: AccessRules::default(),
    };

    collection_service
        .create_collection(request)
        .await
        .expect("create collection");
}

#[tokio::test]
async fn test_validate_record_data_rejects_non_object() {
    let (_dir, db, collection_service, _record_service) = setup_services().await;
    create_test_collection(&collection_service).await;

    let result = collection_service
        .validate_record_data("validation_posts", &json!(true))
        .await;

    let err = result.expect_err("expected validation error");
    assert!(
        matches!(err, ferritedb_core::CoreError::ValidationError(_)),
        "expected ValidationError, got {err:?}"
    );

    db.close().await;
}

#[tokio::test]
async fn test_create_record_rejects_non_object() {
    let (_dir, db, collection_service, record_service) = setup_services().await;
    create_test_collection(&collection_service).await;
    let collection = collection_service
        .get_collection("validation_posts")
        .await
        .expect("get collection")
        .expect("collection exists");

    record_service
        .create_collection_table(&collection)
        .await
        .expect("create table");

    let result = record_service
        .create_record("validation_posts", json!("not an object"))
        .await;

    let err = result.expect_err("expected validation error");
    assert!(
        matches!(err, ferritedb_core::CoreError::ValidationError(_)),
        "expected ValidationError, got {err:?}"
    );

    db.close().await;
}

#[tokio::test]
async fn test_update_record_rejects_non_object() {
    let (_dir, db, collection_service, record_service) = setup_services().await;
    create_test_collection(&collection_service).await;
    let collection = collection_service
        .get_collection("validation_posts")
        .await
        .expect("get collection")
        .expect("collection exists");

    record_service
        .create_collection_table(&collection)
        .await
        .expect("create table");

    let record = record_service
        .create_record("validation_posts", json!({"title": "ok"}))
        .await
        .expect("create record");

    let result = record_service
        .update_record("validation_posts", record.id, json!(123))
        .await;

    let err = result.expect_err("expected validation error");
    assert!(
        matches!(err, ferritedb_core::CoreError::ValidationError(_)),
        "expected ValidationError, got {err:?}"
    );

    db.close().await;
}
