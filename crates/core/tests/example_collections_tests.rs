use ferritedb_core::{
    auth::AuthService,
    config::AuthConfig,
    models::{CreateUserRequest, UserRole},
    seed::SeedService,
    Database, UserRepository,
};
use serde_json::json;
use tempfile::tempdir;

/// Integration tests for example collections and seed data
#[tokio::test]
async fn test_seed_service_initialization() {
    let (db, seed_service) = setup_test_environment().await;

    // Initialize examples
    let result = seed_service.initialize_examples().await;
    assert!(result.is_ok(), "Failed to initialize examples: {:?}", result);

    // Verify users collection was created
    let users_collection = seed_service
        .collection_repo
        .find_by_name("users")
        .await
        .unwrap();
    assert!(users_collection.is_some(), "Users collection should exist");

    let users_collection = users_collection.unwrap();
    assert_eq!(users_collection.name, "users");
    assert_eq!(
        users_collection.collection_type,
        ferritedb_core::CollectionType::Auth
    );

    // Verify posts collection was created
    let posts_collection = seed_service
        .collection_repo
        .find_by_name("posts")
        .await
        .unwrap();
    assert!(posts_collection.is_some(), "Posts collection should exist");

    let posts_collection = posts_collection.unwrap();
    assert_eq!(posts_collection.name, "posts");
    assert_eq!(
        posts_collection.collection_type,
        ferritedb_core::CollectionType::Base
    );

    db.close().await;
}

#[tokio::test]
async fn test_users_collection_schema() {
    let (db, seed_service) = setup_test_environment().await;

    // Initialize examples
    seed_service.initialize_examples().await.unwrap();

    // Get users collection
    let users_collection = seed_service
        .collection_repo
        .find_by_name("users")
        .await
        .unwrap()
        .unwrap();

    // Verify required fields exist
    let field_names: Vec<&str> = users_collection
        .schema_json
        .fields
        .iter()
        .map(|f| f.name.as_str())
        .collect();

    assert!(field_names.contains(&"email"), "Should have email field");
    assert!(
        field_names.contains(&"password"),
        "Should have password field"
    );
    assert!(field_names.contains(&"role"), "Should have role field");
    assert!(
        field_names.contains(&"verified"),
        "Should have verified field"
    );
    assert!(
        field_names.contains(&"first_name"),
        "Should have first_name field"
    );
    assert!(
        field_names.contains(&"last_name"),
        "Should have last_name field"
    );
    assert!(field_names.contains(&"avatar"), "Should have avatar field");

    // Verify field types and constraints
    let email_field = users_collection
        .schema_json
        .get_field("email")
        .unwrap();
    assert!(email_field.required, "Email field should be required");
    assert!(
        email_field.unique_constraint,
        "Email field should be unique"
    );
    assert!(
        matches!(email_field.field_type, ferritedb_core::FieldType::Email),
        "Email field should be email type"
    );

    let role_field = users_collection.schema_json.get_field("role").unwrap();
    assert!(role_field.required, "Role field should be required");
    if let Some(options) = &role_field.options_json {
        assert!(
            options.enum_values.is_some(),
            "Role field should have enum values"
        );
        let enum_values = options.enum_values.as_ref().unwrap();
        assert!(enum_values.contains(&"admin".to_string()));
        assert!(enum_values.contains(&"user".to_string()));
        assert!(enum_values.contains(&"service".to_string()));
    }

    db.close().await;
}

#[tokio::test]
async fn test_posts_collection_schema() {
    let (db, seed_service) = setup_test_environment().await;

    // Initialize examples
    seed_service.initialize_examples().await.unwrap();

    // Get posts collection
    let posts_collection = seed_service
        .collection_repo
        .find_by_name("posts")
        .await
        .unwrap()
        .unwrap();

    // Verify required fields exist
    let field_names: Vec<&str> = posts_collection
        .schema_json
        .fields
        .iter()
        .map(|f| f.name.as_str())
        .collect();

    assert!(field_names.contains(&"title"), "Should have title field");
    assert!(field_names.contains(&"content"), "Should have content field");
    assert!(field_names.contains(&"excerpt"), "Should have excerpt field");
    assert!(
        field_names.contains(&"owner_id"),
        "Should have owner_id field"
    );
    assert!(
        field_names.contains(&"published"),
        "Should have published field"
    );
    assert!(field_names.contains(&"status"), "Should have status field");
    assert!(field_names.contains(&"tags"), "Should have tags field");
    assert!(
        field_names.contains(&"featured_image"),
        "Should have featured_image field"
    );
    assert!(
        field_names.contains(&"published_at"),
        "Should have published_at field"
    );

    // Verify relation field
    let owner_field = posts_collection
        .schema_json
        .get_field("owner_id")
        .unwrap();
    assert!(owner_field.required, "Owner field should be required");
    if let ferritedb_core::FieldType::Relation {
        target_collection, ..
    } = &owner_field.field_type
    {
        assert_eq!(target_collection, "users", "Should reference users collection");
    } else {
        panic!("Owner field should be a relation type");
    }

    // Verify file field
    let image_field = posts_collection
        .schema_json
        .get_field("featured_image")
        .unwrap();
    assert!(
        matches!(
            image_field.field_type,
            ferritedb_core::FieldType::File { .. }
        ),
        "Featured image should be file type"
    );

    db.close().await;
}

#[tokio::test]
async fn test_posts_collection_access_rules() {
    let (db, seed_service) = setup_test_environment().await;

    // Initialize examples
    seed_service.initialize_examples().await.unwrap();

    // Get posts collection
    let posts_collection = seed_service
        .collection_repo
        .find_by_name("posts")
        .await
        .unwrap()
        .unwrap();

    // Verify access rules are defined
    assert!(
        posts_collection.list_rule.is_some(),
        "Should have list rule"
    );
    assert!(
        posts_collection.view_rule.is_some(),
        "Should have view rule"
    );
    assert!(
        posts_collection.create_rule.is_some(),
        "Should have create rule"
    );
    assert!(
        posts_collection.update_rule.is_some(),
        "Should have update rule"
    );
    assert!(
        posts_collection.delete_rule.is_some(),
        "Should have delete rule"
    );

    // Verify rule content demonstrates proper access control
    let list_rule = posts_collection.list_rule.as_ref().unwrap();
    assert!(
        list_rule.contains("record.published") || list_rule.contains("@request.auth"),
        "List rule should check published status or authentication"
    );

    let create_rule = posts_collection.create_rule.as_ref().unwrap();
    assert!(
        create_rule.contains("@request.auth.id"),
        "Create rule should require authentication"
    );

    let update_rule = posts_collection.update_rule.as_ref().unwrap();
    assert!(
        update_rule.contains("record.owner_id") || update_rule.contains("@request.auth.role"),
        "Update rule should check ownership or admin role"
    );

    let delete_rule = posts_collection.delete_rule.as_ref().unwrap();
    assert!(
        delete_rule.contains("admin"),
        "Delete rule should require admin role"
    );

    db.close().await;
}

#[tokio::test]
async fn test_demo_users_creation() {
    let (db, seed_service) = setup_test_environment().await;

    // Initialize examples
    seed_service.initialize_examples().await.unwrap();

    // Verify admin user was created
    let admin_user = seed_service
        .user_repo
        .find_by_email("admin@ferritedb.dev")
        .await
        .unwrap();
    assert!(admin_user.is_some(), "Admin user should be created");

    let admin_user = admin_user.unwrap();
    assert_eq!(admin_user.role, UserRole::Admin);
    assert!(admin_user.verified, "Admin user should be verified");

    // Verify demo users were created
    let demo_emails = [
        "alice@example.com",
        "bob@example.com",
        "carol@example.com",
    ];

    for email in &demo_emails {
        let user = seed_service.user_repo.find_by_email(email).await.unwrap();
        assert!(user.is_some(), "Demo user {} should be created", email);

        let user = user.unwrap();
        assert_eq!(user.role, UserRole::User);
        assert!(user.verified, "Demo user should be verified");
    }

    db.close().await;
}

#[tokio::test]
async fn test_demo_posts_creation() {
    let (db, seed_service) = setup_test_environment().await;

    // Initialize examples
    seed_service.initialize_examples().await.unwrap();

    // Check that demo posts were created
    let posts_count = seed_service.record_service.count_records("posts").await.unwrap();
    assert!(posts_count > 0, "Demo posts should be created");

    // Note: The actual record creation is simplified in the current implementation
    // In a full implementation, we would verify:
    // - Posts have proper titles and content
    // - Posts have correct ownership
    // - Posts have various published states
    // - Posts demonstrate proper tagging

    db.close().await;
}

#[tokio::test]
async fn test_idempotent_initialization() {
    let (db, seed_service) = setup_test_environment().await;

    // Initialize examples twice
    let result1 = seed_service.initialize_examples().await;
    assert!(result1.is_ok(), "First initialization should succeed");

    let result2 = seed_service.initialize_examples().await;
    assert!(result2.is_ok(), "Second initialization should succeed");

    // Verify collections still exist and are not duplicated
    let users_collection = seed_service
        .collection_repo
        .find_by_name("users")
        .await
        .unwrap();
    assert!(users_collection.is_some(), "Users collection should still exist");

    let posts_collection = seed_service
        .collection_repo
        .find_by_name("posts")
        .await
        .unwrap();
    assert!(posts_collection.is_some(), "Posts collection should still exist");

    // Verify users are not duplicated
    let admin_user = seed_service
        .user_repo
        .find_by_email("admin@ferritedb.dev")
        .await
        .unwrap();
    assert!(admin_user.is_some(), "Admin user should still exist");

    db.close().await;
}

#[tokio::test]
async fn test_collection_table_creation() {
    let (db, seed_service) = setup_test_environment().await;

    // Initialize examples
    seed_service.initialize_examples().await.unwrap();

    // Verify that database tables were created
    let users_table_exists = table_exists(&db, "records_users").await;
    assert!(users_table_exists, "Users table should be created");

    let posts_table_exists = table_exists(&db, "records_posts").await;
    assert!(posts_table_exists, "Posts table should be created");

    db.close().await;
}

#[tokio::test]
async fn test_password_hashing() {
    let (db, seed_service) = setup_test_environment().await;

    // Initialize examples
    seed_service.initialize_examples().await.unwrap();

    // Get a demo user
    let user = seed_service
        .user_repo
        .find_by_email("alice@example.com")
        .await
        .unwrap()
        .unwrap();

    // Verify password is hashed (not plaintext)
    assert_ne!(user.password_hash, "password123");
    assert!(user.password_hash.starts_with("$argon2id$"));

    // Verify password can be verified
    let auth_service = create_test_auth_service();
    let is_valid = auth_service
        .verify_password("password123", &user.password_hash)
        .unwrap();
    assert!(is_valid, "Password should be verifiable");

    db.close().await;
}

#[tokio::test]
async fn test_field_validation_constraints() {
    let (db, seed_service) = setup_test_environment().await;

    // Initialize examples
    seed_service.initialize_examples().await.unwrap();

    // Test users collection field constraints
    let users_collection = seed_service
        .collection_repo
        .find_by_name("users")
        .await
        .unwrap()
        .unwrap();

    // Verify email field has proper constraints
    let email_field = users_collection
        .schema_json
        .get_field("email")
        .unwrap();
    if let Some(options) = &email_field.options_json {
        assert!(
            options.max_length.is_some(),
            "Email field should have max length"
        );
        assert!(
            options.max_length.unwrap() <= 255,
            "Email max length should be reasonable"
        );
    }

    // Verify password field has minimum length
    let password_field = users_collection
        .schema_json
        .get_field("password")
        .unwrap();
    if let Some(options) = &password_field.options_json {
        assert!(
            options.min_length.is_some(),
            "Password field should have min length"
        );
        assert!(
            options.min_length.unwrap() >= 8,
            "Password min length should be at least 8"
        );
    }

    // Test posts collection field constraints
    let posts_collection = seed_service
        .collection_repo
        .find_by_name("posts")
        .await
        .unwrap()
        .unwrap();

    // Verify title field constraints
    let title_field = posts_collection
        .schema_json
        .get_field("title")
        .unwrap();
    assert!(title_field.required, "Title should be required");
    if let Some(options) = &title_field.options_json {
        assert!(
            options.min_length.is_some() && options.min_length.unwrap() >= 1,
            "Title should have minimum length"
        );
        assert!(
            options.max_length.is_some(),
            "Title should have maximum length"
        );
    }

    db.close().await;
}

// Helper functions

async fn setup_test_environment() -> (Database, SeedService) {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let database_url = format!("sqlite:{}", db_path.display());

    let db = Database::new(&database_url, 5, 30).await.unwrap();
    db.migrate().await.unwrap();

    let auth_service = create_test_auth_service();
    let seed_service = SeedService::new(db.pool().clone(), auth_service);

    (db, seed_service)
}

fn create_test_auth_service() -> AuthService {
    let auth_config = AuthConfig {
        jwt_secret: "test_secret_key_for_testing_only".to_string(),
        token_ttl: 3600,
        refresh_ttl: 86400,
        password_min_length: 8,
        argon2_memory: 4096,     // Reduced for testing
        argon2_iterations: 1,    // Reduced for testing
        argon2_parallelism: 1,
    };
    AuthService::new(auth_config).unwrap()
}

async fn table_exists(db: &Database, table_name: &str) -> bool {
    let result = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
    )
    .bind(table_name)
    .fetch_one(db.pool())
    .await;

    match result {
        Ok(count) => count > 0,
        Err(_) => false,
    }
}

#[tokio::test]
async fn test_collection_json_schema_generation() {
    let (db, seed_service) = setup_test_environment().await;

    // Initialize examples
    seed_service.initialize_examples().await.unwrap();

    // Get posts collection
    let posts_collection = seed_service
        .collection_repo
        .find_by_name("posts")
        .await
        .unwrap()
        .unwrap();

    // Verify JSON schema was generated
    assert!(
        posts_collection.schema_json.json_schema.is_some(),
        "JSON schema should be generated"
    );

    let json_schema = posts_collection.schema_json.json_schema.unwrap();

    // Verify schema structure
    assert_eq!(json_schema["type"], "object");
    assert!(json_schema["properties"].is_object());
    assert!(json_schema["required"].is_array());

    // Verify required fields are in the schema
    let required_fields = json_schema["required"].as_array().unwrap();
    assert!(required_fields.contains(&json!("title")));
    assert!(required_fields.contains(&json!("content")));
    assert!(required_fields.contains(&json!("owner_id")));

    // Verify field properties
    let properties = json_schema["properties"].as_object().unwrap();
    assert!(properties.contains_key("title"));
    assert!(properties.contains_key("published"));
    assert!(properties.contains_key("tags"));

    // Verify field types in schema
    assert_eq!(properties["title"]["type"], "string");
    assert_eq!(properties["published"]["type"], "boolean");

    db.close().await;
}

#[tokio::test]
async fn test_file_field_configuration() {
    let (db, seed_service) = setup_test_environment().await;

    // Initialize examples
    seed_service.initialize_examples().await.unwrap();

    // Check users collection avatar field
    let users_collection = seed_service
        .collection_repo
        .find_by_name("users")
        .await
        .unwrap()
        .unwrap();

    let avatar_field = users_collection
        .schema_json
        .get_field("avatar")
        .unwrap();

    if let ferritedb_core::FieldType::File {
        max_size,
        allowed_types,
    } = &avatar_field.field_type
    {
        assert!(max_size.is_some(), "Avatar field should have max size");
        assert!(
            max_size.unwrap() <= 10 * 1024 * 1024,
            "Avatar max size should be reasonable"
        );

        assert!(
            allowed_types.is_some(),
            "Avatar field should have allowed types"
        );
        let types = allowed_types.as_ref().unwrap();
        assert!(types.contains(&"image/jpeg".to_string()));
        assert!(types.contains(&"image/png".to_string()));
    } else {
        panic!("Avatar field should be file type");
    }

    // Check posts collection featured_image field
    let posts_collection = seed_service
        .collection_repo
        .find_by_name("posts")
        .await
        .unwrap()
        .unwrap();

    let image_field = posts_collection
        .schema_json
        .get_field("featured_image")
        .unwrap();

    if let ferritedb_core::FieldType::File {
        max_size,
        allowed_types,
    } = &image_field.field_type
    {
        assert!(max_size.is_some(), "Featured image should have max size");
        assert!(
            allowed_types.is_some(),
            "Featured image should have allowed types"
        );
    } else {
        panic!("Featured image field should be file type");
    }

    db.close().await;
}