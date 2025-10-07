use crate::{
    models::{
        AccessRules, CollectionSchema, CollectionType, CreateCollectionRequest,
        CreateUserRequest, Field, FieldOptions, FieldType, User, UserRole,
    },
    repository::{CollectionRepository, UserRepository},
    collections::CollectionService,
    records::RecordService,
    schema_manager::SchemaManager,
    auth::AuthService,
    CoreError, CoreResult, DatabasePool,
};
use serde_json::json;
use tracing::info;
use uuid::Uuid;

/// Service for creating example collections and seed data
#[derive(Clone)]
pub struct SeedService {
    pub collection_repo: CollectionRepository,
    pub user_repo: UserRepository,
    pub record_service: RecordService,
    pub schema_manager: SchemaManager,
    pub auth_service: AuthService,
}

impl SeedService {
    pub fn new(
        pool: DatabasePool,
        auth_service: AuthService,
    ) -> Self {
        let collection_repo = CollectionRepository::new(pool.clone());
        let user_repo = UserRepository::new(pool.clone());
        let collection_service = CollectionService::new(collection_repo.clone());
        let record_service = RecordService::new(pool.clone(), collection_service.clone());
        let schema_manager = SchemaManager::new(
            pool.clone(),
            collection_service.clone(),
            record_service.clone(),
        );

        Self {
            collection_repo,
            user_repo,
            record_service,
            schema_manager,
            auth_service,
        }
    }

    /// Initialize example collections and seed data
    pub async fn initialize_examples(&self) -> CoreResult<()> {
        info!("Initializing example collections and seed data...");

        // Create built-in users collection if it doesn't exist
        self.create_users_collection().await?;

        // Create example posts collection
        self.create_posts_collection().await?;

        // Create seed data
        self.create_seed_data().await?;

        info!("✅ Example collections and seed data initialized successfully");
        Ok(())
    }

    /// Create the built-in users collection with standard fields
    async fn create_users_collection(&self) -> CoreResult<()> {
        // Check if users collection already exists
        if self.collection_repo.find_by_name("users").await?.is_some() {
            info!("Users collection already exists, skipping creation");
            return Ok(());
        }

        info!("Creating built-in users collection...");

        let mut schema = CollectionSchema::new();

        // Add standard user fields
        schema.add_field(
            Field::new(Uuid::new_v4(), "email".to_string(), FieldType::Email)
                .required()
                .unique()
                .with_options(FieldOptions {
                    max_length: Some(255),
                    ..Default::default()
                }),
        );

        schema.add_field(
            Field::new(Uuid::new_v4(), "password".to_string(), FieldType::Text)
                .required()
                .with_options(FieldOptions {
                    min_length: Some(8),
                    max_length: Some(255),
                    ..Default::default()
                }),
        );

        schema.add_field(
            Field::new(Uuid::new_v4(), "role".to_string(), FieldType::Text)
                .required()
                .with_options(FieldOptions {
                    enum_values: Some(vec![
                        "admin".to_string(),
                        "user".to_string(),
                        "service".to_string(),
                    ]),
                    default_value: Some(json!("user")),
                    ..Default::default()
                }),
        );

        schema.add_field(
            Field::new(Uuid::new_v4(), "verified".to_string(), FieldType::Boolean)
                .with_options(FieldOptions {
                    default_value: Some(json!(false)),
                    ..Default::default()
                }),
        );

        schema.add_field(
            Field::new(Uuid::new_v4(), "first_name".to_string(), FieldType::Text)
                .with_options(FieldOptions {
                    max_length: Some(100),
                    ..Default::default()
                }),
        );

        schema.add_field(
            Field::new(Uuid::new_v4(), "last_name".to_string(), FieldType::Text)
                .with_options(FieldOptions {
                    max_length: Some(100),
                    ..Default::default()
                }),
        );

        schema.add_field(
            Field::new(Uuid::new_v4(), "avatar".to_string(), FieldType::File {
                max_size: Some(5 * 1024 * 1024), // 5MB
                allowed_types: Some(vec![
                    "image/jpeg".to_string(),
                    "image/png".to_string(),
                    "image/webp".to_string(),
                ]),
            }),
        );

        // Define access rules for users collection
        let rules = AccessRules {
            list_rule: Some("@request.auth.role = 'admin'".to_string()),
            view_rule: Some("@request.auth.id = record.id || @request.auth.role = 'admin'".to_string()),
            create_rule: Some("@request.auth.role = 'admin'".to_string()),
            update_rule: Some("@request.auth.id = record.id || @request.auth.role = 'admin'".to_string()),
            delete_rule: Some("@request.auth.role = 'admin'".to_string()),
        };

        let request = CreateCollectionRequest {
            name: "users".to_string(),
            collection_type: Some(CollectionType::Auth),
            schema,
            rules,
        };

        let collection = self.collection_repo.create(request).await?;

        // Create the actual database table
        self.schema_manager.create_collection_with_table(&collection).await?;

        info!("✅ Built-in users collection created successfully");
        Ok(())
    }

    /// Create example posts collection with proper relations and rules
    async fn create_posts_collection(&self) -> CoreResult<()> {
        // Check if posts collection already exists
        if self.collection_repo.find_by_name("posts").await?.is_some() {
            info!("Posts collection already exists, skipping creation");
            return Ok(());
        }

        info!("Creating example posts collection...");

        let mut schema = CollectionSchema::new();

        // Add post fields
        schema.add_field(
            Field::new(Uuid::new_v4(), "title".to_string(), FieldType::Text)
                .required()
                .with_options(FieldOptions {
                    min_length: Some(1),
                    max_length: Some(255),
                    ..Default::default()
                }),
        );

        schema.add_field(
            Field::new(Uuid::new_v4(), "content".to_string(), FieldType::Text)
                .required()
                .with_options(FieldOptions {
                    min_length: Some(1),
                    max_length: Some(10000),
                    ..Default::default()
                }),
        );

        schema.add_field(
            Field::new(Uuid::new_v4(), "excerpt".to_string(), FieldType::Text)
                .with_options(FieldOptions {
                    max_length: Some(500),
                    ..Default::default()
                }),
        );

        schema.add_field(
            Field::new(Uuid::new_v4(), "owner_id".to_string(), FieldType::Relation {
                target_collection: "users".to_string(),
                cascade_delete: false,
            })
            .required(),
        );

        schema.add_field(
            Field::new(Uuid::new_v4(), "published".to_string(), FieldType::Boolean)
                .with_options(FieldOptions {
                    default_value: Some(json!(false)),
                    ..Default::default()
                }),
        );

        schema.add_field(
            Field::new(Uuid::new_v4(), "status".to_string(), FieldType::Text)
                .required()
                .with_options(FieldOptions {
                    enum_values: Some(vec![
                        "draft".to_string(),
                        "published".to_string(),
                        "archived".to_string(),
                    ]),
                    default_value: Some(json!("draft")),
                    ..Default::default()
                }),
        );

        schema.add_field(
            Field::new(Uuid::new_v4(), "tags".to_string(), FieldType::Json)
                .with_options(FieldOptions {
                    default_value: Some(json!([])),
                    ..Default::default()
                }),
        );

        schema.add_field(
            Field::new(Uuid::new_v4(), "featured_image".to_string(), FieldType::File {
                max_size: Some(10 * 1024 * 1024), // 10MB
                allowed_types: Some(vec![
                    "image/jpeg".to_string(),
                    "image/png".to_string(),
                    "image/webp".to_string(),
                ]),
            }),
        );

        schema.add_field(
            Field::new(Uuid::new_v4(), "published_at".to_string(), FieldType::DateTime),
        );

        // Define access rules demonstrating different permission levels
        let rules = AccessRules {
            // Anyone can list published posts
            list_rule: Some("record.published = true || @request.auth.id != ''".to_string()),
            // Anyone can view published posts, authenticated users can view their own drafts
            view_rule: Some("record.published = true || record.owner_id = @request.auth.id || @request.auth.role = 'admin'".to_string()),
            // Only authenticated users can create posts
            create_rule: Some("@request.auth.id != ''".to_string()),
            // Only the owner or admin can update posts
            update_rule: Some("record.owner_id = @request.auth.id || @request.auth.role = 'admin'".to_string()),
            // Only admin can delete posts
            delete_rule: Some("@request.auth.role = 'admin'".to_string()),
        };

        let request = CreateCollectionRequest {
            name: "posts".to_string(),
            collection_type: Some(CollectionType::Base),
            schema,
            rules,
        };

        let collection = self.collection_repo.create(request).await?;

        // Create the actual database table
        self.schema_manager.create_collection_with_table(&collection).await?;

        info!("✅ Example posts collection created successfully");
        Ok(())
    }

    /// Create seed data including admin user and example posts
    async fn create_seed_data(&self) -> CoreResult<()> {
        info!("Creating seed data...");

        // Create admin user
        let admin_email = "admin@ferritedb.dev";
        if self.user_repo.find_by_email(admin_email).await?.is_none() {
            let admin_password = "Admin123!".to_string();
            let password_hash = self.auth_service.hash_password(&admin_password)
                .map_err(|e| CoreError::Authentication(e.to_string()))?;

            let admin_request = CreateUserRequest {
                email: admin_email.to_string(),
                password: admin_password,
                role: Some(UserRole::Admin),
                verified: true,
            };

            let _admin_user = self.user_repo.create(admin_request, password_hash).await?;
            info!("Created demo admin user: {}", admin_email);
        } else {
            info!("Admin user already exists, skipping creation");
        }

        // Create example users
        let example_users = vec![
            ("Alice Johnson", "alice@example.com"),
            ("Bob Smith", "bob@example.com"),
            ("Carol Davis", "carol@example.com"),
        ];

        for (name, email) in example_users {
            if self.user_repo.find_by_email(email).await?.is_none() {
                let user_password = "Password123!".to_string();
                let password_hash = self.auth_service.hash_password(&user_password)
                    .map_err(|e| CoreError::Authentication(e.to_string()))?;

                let user_request = CreateUserRequest {
                    email: email.to_string(),
                    password: user_password,
                    role: Some(UserRole::User),
                    verified: true,
                };

                let _user = self.user_repo.create(user_request, password_hash).await?;
                info!("Created demo user: {} ({})", email, name);
            }
        }

        // Get all users to create posts
        let users = self.user_repo.list(100, 0).await?;
        let admin_user = users.iter().find(|u| u.email == "admin@ferritedb.dev");
        let alice_user = users.iter().find(|u| u.email == "alice@example.com");

        // Only create posts if we have the required users
        if let (Some(admin), Some(alice)) = (admin_user, alice_user) {
            // Create example posts
            self.create_example_posts(admin, alice).await?;
        }

        info!("✅ Seed data created successfully");
        Ok(())
    }

    /// Create example posts for demonstration
    async fn create_example_posts(&self, admin: &User, alice: &User) -> CoreResult<()> {
        // Check if posts already exist
        let existing_posts = self.record_service.list_records("posts", 1, 0).await?;
        if !existing_posts.is_empty() {
            info!("Posts already exist, skipping creation");
            return Ok(());
        }

        info!("Creating example posts...");

        let example_posts = vec![
            (
                admin,
                json!({
                    "title": "Welcome to FerriteDB",
                    "content": "This is your first post in FerriteDB! FerriteDB is a production-ready, developer-friendly backend service that provides a complete backend-as-a-service solution in a single self-contained binary.",
                    "excerpt": "Welcome to FerriteDB - your new backend service",
                    "published": true,
                    "status": "published",
                    "tags": ["welcome", "ferritedb", "backend"],
                    "published_at": chrono::Utc::now().to_rfc3339()
                })
            ),
            (
                alice,
                json!({
                    "title": "Understanding Collections in FerriteDB",
                    "content": "Collections in FerriteDB are dynamic schemas that allow you to define your data structure without writing SQL. You can create fields of various types including text, numbers, booleans, relations, and files.",
                    "excerpt": "Learn how to work with dynamic collections in FerriteDB",
                    "published": true,
                    "status": "published",
                    "tags": ["collections", "schema", "data-modeling"],
                    "published_at": chrono::Utc::now().to_rfc3339()
                })
            ),
            (
                admin,
                json!({
                    "title": "Access Control Rules in FerriteDB",
                    "content": "FerriteDB uses a powerful rule-based access control system. You can define rules for listing, viewing, creating, updating, and deleting records using a CEL-like expression language.",
                    "excerpt": "Master the access control system in FerriteDB",
                    "published": true,
                    "status": "published",
                    "tags": ["security", "access-control", "rules"],
                    "published_at": chrono::Utc::now().to_rfc3339()
                })
            ),
            (
                alice,
                json!({
                    "title": "Advanced FerriteDB Features",
                    "content": "This post covers advanced FerriteDB features including realtime subscriptions, file storage, and custom validation rules. This is still a work in progress.",
                    "excerpt": "Exploring advanced FerriteDB capabilities",
                    "published": false,
                    "status": "draft",
                    "tags": ["advanced", "realtime", "files"],
                })
            ),
            (
                admin,
                json!({
                    "title": "REST API Guide for FerriteDB",
                    "content": "FerriteDB automatically generates REST APIs for your collections. Learn how to use query parameters for filtering, sorting, and pagination.",
                    "excerpt": "Complete guide to FerriteDB REST APIs",
                    "published": true,
                    "status": "published",
                    "tags": ["api", "rest", "documentation"],
                    "published_at": chrono::Utc::now().to_rfc3339()
                })
            ),
        ];

        let post_count = example_posts.len();
        for (owner, post_data) in example_posts {
            let mut post_with_owner = post_data.as_object().unwrap().clone();
            post_with_owner.insert("owner_id".to_string(), json!(owner.id.to_string()));
            
            self.record_service.create_record("posts", json!(post_with_owner)).await?;
        }

        info!("✅ Created {} example posts", post_count);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Database, config::AuthConfig};
    use tempfile::tempdir;

    async fn setup_test_service() -> (Database, SeedService) {
        let db_dir = tempdir().unwrap().into_path();
        let db_path = db_dir.join("test.db");
        let database_url = format!("sqlite:{}", db_path.display());

        let db = Database::new(&database_url, 5, 30).await.unwrap();
        db.migrate().await.unwrap();

        let auth_config = AuthConfig {
            jwt_secret: "test_secret".to_string(),
            token_ttl: 3600,
            refresh_ttl: 86400,
            password_min_length: 8,
            argon2_memory: 65536,
            argon2_iterations: 3,
            argon2_parallelism: 4,
        };
        let auth_service = AuthService::new(auth_config).unwrap();

        let seed_service = SeedService::new(db.pool().clone(), auth_service);

        (db, seed_service)
    }

    #[tokio::test]
    async fn test_create_users_collection() {
        let (db, seed_service) = setup_test_service().await;

        let result = seed_service.create_users_collection().await;
        assert!(result.is_ok());

        // Verify collection was created
        let collection = seed_service.collection_repo.find_by_name("users").await.unwrap();
        assert!(collection.is_some());

        let collection = collection.unwrap();
        assert_eq!(collection.name, "users");
        assert_eq!(collection.collection_type, CollectionType::Auth);
        assert!(!collection.schema_json.fields.is_empty());

        // Verify required fields exist
        let field_names: Vec<&str> = collection.schema_json.fields.iter()
            .map(|f| f.name.as_str())
            .collect();
        
        assert!(field_names.contains(&"email"));
        assert!(field_names.contains(&"password"));
        assert!(field_names.contains(&"role"));
        assert!(field_names.contains(&"verified"));

        db.close().await;
    }

    #[tokio::test]
    async fn test_create_posts_collection() {
        let (db, seed_service) = setup_test_service().await;

        let result = seed_service.create_posts_collection().await;
        assert!(result.is_ok());

        // Verify collection was created
        let collection = seed_service.collection_repo.find_by_name("posts").await.unwrap();
        assert!(collection.is_some());

        let collection = collection.unwrap();
        assert_eq!(collection.name, "posts");
        assert_eq!(collection.collection_type, CollectionType::Base);

        // Verify access rules are set
        assert!(collection.list_rule.is_some());
        assert!(collection.view_rule.is_some());
        assert!(collection.create_rule.is_some());
        assert!(collection.update_rule.is_some());
        assert!(collection.delete_rule.is_some());

        // Verify required fields exist
        let field_names: Vec<&str> = collection.schema_json.fields.iter()
            .map(|f| f.name.as_str())
            .collect();
        
        assert!(field_names.contains(&"title"));
        assert!(field_names.contains(&"content"));
        assert!(field_names.contains(&"owner_id"));
        assert!(field_names.contains(&"published"));

        db.close().await;
    }

    #[tokio::test]
    async fn test_create_demo_users() {
        let (db, seed_service) = setup_test_service().await;

        seed_service.initialize_examples().await.unwrap();
        let users = seed_service.user_repo.list(100, 0).await.unwrap();
        assert!(!users.is_empty());

        // Verify admin user exists
        let admin_user = users.iter().find(|u| u.email == "admin@ferritedb.dev");
        assert!(admin_user.is_some());
        assert_eq!(admin_user.unwrap().role, UserRole::Admin);

        // Verify regular users exist
        let alice = users.iter().find(|u| u.email == "alice@example.com");
        assert!(alice.is_some());
        assert_eq!(alice.unwrap().role, UserRole::User);

        db.close().await;
    }

    #[tokio::test]
    async fn test_initialize_examples() {
        let (db, seed_service) = setup_test_service().await;

        let result = seed_service.initialize_examples().await;
        assert!(result.is_ok());

        // Verify both collections were created
        let users_collection = seed_service.collection_repo.find_by_name("users").await.unwrap();
        assert!(users_collection.is_some());

        let posts_collection = seed_service.collection_repo.find_by_name("posts").await.unwrap();
        assert!(posts_collection.is_some());

        db.close().await;
    }
}
