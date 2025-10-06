use crate::{
    models::{
        AuditLog, Collection, CollectionSchema, CollectionType, CreateCollectionRequest,
        CreateUserRequest, Field, UpdateCollectionRequest, User, UserRole,
    },
    CoreError, CoreResult, DatabasePool,
};
use chrono::Utc;
use sqlx::Row;
use tracing::{debug, info};
use uuid::Uuid;

/// Repository for user operations
#[derive(Clone)]
pub struct UserRepository {
    pool: DatabasePool,
}

impl UserRepository {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }

    /// Create a new user
    pub async fn create(&self, request: CreateUserRequest, password_hash: String) -> CoreResult<User> {
        let user = User::new(
            request.email,
            password_hash,
            request.role.unwrap_or(UserRole::User),
        );

        let mut user = user;
        user.verified = request.verified;

        let user_id = user.id.to_string();
        let user_role = user.role.to_string();
        
        sqlx::query(
            r#"
            INSERT INTO users (id, email, password_hash, role, verified, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
        )
        .bind(&user_id)
        .bind(&user.email)
        .bind(&user.password_hash)
        .bind(&user_role)
        .bind(user.verified)
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(&self.pool)
        .await?;

        debug!("Created user: {}", user.email);
        Ok(user)
    }

    /// Find user by email
    pub async fn find_by_email(&self, email: &str) -> CoreResult<Option<User>> {
        let row = sqlx::query(
            "SELECT id, email, password_hash, role, verified, created_at, updated_at FROM users WHERE email = ?1"
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let user = User {
                id: Uuid::parse_str(&row.get::<String, _>("id"))?,
                email: row.get("email"),
                password_hash: row.get("password_hash"),
                role: match row.get::<String, _>("role").as_str() {
                    "admin" => UserRole::Admin,
                    "service" => UserRole::Service,
                    _ => UserRole::User,
                },
                verified: row.get("verified"),
                created_at: chrono::DateTime::from_naive_utc_and_offset(row.get("created_at"), Utc),
                updated_at: chrono::DateTime::from_naive_utc_and_offset(row.get("updated_at"), Utc),
            };
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    /// Find user by ID
    pub async fn find_by_id(&self, id: Uuid) -> CoreResult<Option<User>> {
        let id_str = id.to_string();
        let row = sqlx::query(
            "SELECT id, email, password_hash, role, verified, created_at, updated_at FROM users WHERE id = ?1"
        )
        .bind(&id_str)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let user = User {
                id: Uuid::parse_str(&row.get::<String, _>("id"))?,
                email: row.get("email"),
                password_hash: row.get("password_hash"),
                role: match row.get::<String, _>("role").as_str() {
                    "admin" => UserRole::Admin,
                    "service" => UserRole::Service,
                    _ => UserRole::User,
                },
                verified: row.get("verified"),
                created_at: chrono::DateTime::from_naive_utc_and_offset(row.get("created_at"), Utc),
                updated_at: chrono::DateTime::from_naive_utc_and_offset(row.get("updated_at"), Utc),
            };
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    /// Update user verification status
    pub async fn update_verification(&self, id: Uuid, verified: bool) -> CoreResult<()> {
        let updated_at = Utc::now();
        let id_str = id.to_string();
        sqlx::query("UPDATE users SET verified = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(verified)
            .bind(updated_at)
            .bind(&id_str)
            .execute(&self.pool)
            .await?;

        debug!("Updated user verification: {} -> {}", id, verified);
        Ok(())
    }

    /// Update user role
    pub async fn update_role(&self, id: Uuid, role: UserRole) -> CoreResult<()> {
        let updated_at = Utc::now();
        let role_str = role.to_string();
        let id_str = id.to_string();
        sqlx::query("UPDATE users SET role = ?1, updated_at = ?2 WHERE id = ?3")
            .bind(&role_str)
            .bind(updated_at)
            .bind(&id_str)
            .execute(&self.pool)
            .await?;

        debug!("Updated user role: {} -> {}", id, role);
        Ok(())
    }

    /// List users with pagination
    pub async fn list(&self, limit: i64, offset: i64) -> CoreResult<Vec<User>> {
        let rows = sqlx::query(
            "SELECT id, email, password_hash, role, verified, created_at, updated_at FROM users ORDER BY created_at DESC LIMIT ?1 OFFSET ?2"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        let mut users = Vec::new();
        for row in rows {
            let user = User {
                id: Uuid::parse_str(&row.get::<String, _>("id")).unwrap_or_default(),
                email: row.get("email"),
                password_hash: row.get("password_hash"),
                role: match row.get::<String, _>("role").as_str() {
                    "admin" => UserRole::Admin,
                    "service" => UserRole::Service,
                    _ => UserRole::User,
                },
                verified: row.get("verified"),
                created_at: chrono::DateTime::from_naive_utc_and_offset(row.get("created_at"), Utc),
                updated_at: chrono::DateTime::from_naive_utc_and_offset(row.get("updated_at"), Utc),
            };
            users.push(user);
        }

        Ok(users)
    }

    /// Delete user by ID
    pub async fn delete(&self, id: Uuid) -> CoreResult<bool> {
        let id_str = id.to_string();
        let result = sqlx::query("DELETE FROM users WHERE id = ?1")
            .bind(&id_str)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }
}

/// Repository for collection operations
#[derive(Clone)]
pub struct CollectionRepository {
    pool: DatabasePool,
}

impl CollectionRepository {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }

    /// Create a new collection
    pub async fn create(&self, request: CreateCollectionRequest) -> CoreResult<Collection> {
        let collection = Collection::new(request.name, request.collection_type.unwrap_or(CollectionType::Base));

        let mut tx = self.pool.begin().await?;

        let collection_id = collection.id.to_string();
        let collection_type_str = collection.collection_type.to_string();
        let schema_json = serde_json::to_string(&collection.schema_json)?;

        sqlx::query(
            r#"
            INSERT INTO collections (id, name, type, schema_json, list_rule, view_rule, create_rule, update_rule, delete_rule, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
        )
        .bind(&collection_id)
        .bind(&collection.name)
        .bind(&collection_type_str)
        .bind(&schema_json)
        .bind(&collection.list_rule)
        .bind(&collection.view_rule)
        .bind(&collection.create_rule)
        .bind(&collection.update_rule)
        .bind(&collection.delete_rule)
        .bind(collection.created_at)
        .bind(collection.updated_at)
        .execute(&mut *tx)
        .await?;

        // Insert collection fields from schema
        for field in &request.schema.fields {
            let field_id = field.id.to_string();
            let field_type_json = serde_json::to_string(&field.field_type)?;
            let options_json = field.options_json.as_ref().map(|o| serde_json::to_string(o)).transpose()?;

            sqlx::query(
                r#"
                INSERT INTO collection_fields (id, collection_id, name, type, required, unique_constraint, options_json, created_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#,
            )
            .bind(&field_id)
            .bind(&collection_id)
            .bind(&field.name)
            .bind(&field_type_json)
            .bind(field.required)
            .bind(field.unique_constraint)
            .bind(&options_json)
            .bind(field.created_at)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        info!("Created collection: {}", collection.name);
        Ok(collection)
    }

    /// Find collection by name
    pub async fn find_by_name(&self, name: &str) -> CoreResult<Option<Collection>> {
        let row = sqlx::query(
            r#"
            SELECT id, name, type, schema_json, list_rule, view_rule, create_rule, update_rule, delete_rule, created_at, updated_at
            FROM collections WHERE name = ?1
            "#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let collection_id = Uuid::parse_str(&row.get::<String, _>("id"))?;

            // Get collection fields
            let field_rows = sqlx::query(
                "SELECT id, collection_id, name, type, required, unique_constraint, options_json, created_at FROM collection_fields WHERE collection_id = ?1"
            )
            .bind(collection_id.to_string())
            .fetch_all(&self.pool)
            .await?;

            let mut fields = Vec::new();
            for field_row in field_rows {
                let field = Field {
                    id: Uuid::parse_str(&field_row.get::<String, _>("id"))?,
                    collection_id,
                    name: field_row.get("name"),
                    field_type: serde_json::from_str(&field_row.get::<String, _>("type"))?,
                    required: field_row.get("required"),
                    unique_constraint: field_row.get("unique_constraint"),
                    options_json: field_row.get::<Option<String>, _>("options_json")
                        .map(|s| serde_json::from_str(&s))
                        .transpose()?,
                    created_at: chrono::DateTime::from_naive_utc_and_offset(field_row.get("created_at"), Utc),
                };
                fields.push(field);
            }

            let mut schema_json: CollectionSchema = serde_json::from_str(&row.get::<String, _>("schema_json"))?;
            schema_json.fields = fields;

            let collection = Collection {
                id: collection_id,
                name: row.get("name"),
                collection_type: match row.get::<String, _>("type").as_str() {
                    "auth" => CollectionType::Auth,
                    "view" => CollectionType::View,
                    _ => CollectionType::Base,
                },
                schema_json,
                list_rule: row.get("list_rule"),
                view_rule: row.get("view_rule"),
                create_rule: row.get("create_rule"),
                update_rule: row.get("update_rule"),
                delete_rule: row.get("delete_rule"),
                created_at: chrono::DateTime::from_naive_utc_and_offset(row.get("created_at"), Utc),
                updated_at: chrono::DateTime::from_naive_utc_and_offset(row.get("updated_at"), Utc),
            };

            Ok(Some(collection))
        } else {
            Ok(None)
        }
    }

    /// Find collection by ID
    pub async fn find_by_id(&self, id: Uuid) -> CoreResult<Option<Collection>> {
        let id_str = id.to_string();
        let row = sqlx::query(
            r#"
            SELECT id, name, type, schema_json, list_rule, view_rule, create_rule, update_rule, delete_rule, created_at, updated_at
            FROM collections WHERE id = ?1
            "#,
        )
        .bind(&id_str)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            // Get collection fields
            let field_rows = sqlx::query(
                "SELECT id, collection_id, name, type, required, unique_constraint, options_json, created_at FROM collection_fields WHERE collection_id = ?1"
            )
            .bind(&id_str)
            .fetch_all(&self.pool)
            .await?;

            let mut fields = Vec::new();
            for field_row in field_rows {
                let field = Field {
                    id: Uuid::parse_str(&field_row.get::<String, _>("id"))?,
                    collection_id: id,
                    name: field_row.get("name"),
                    field_type: serde_json::from_str(&field_row.get::<String, _>("type"))?,
                    required: field_row.get("required"),
                    unique_constraint: field_row.get("unique_constraint"),
                    options_json: field_row.get::<Option<String>, _>("options_json")
                        .map(|s| serde_json::from_str(&s))
                        .transpose()?,
                    created_at: chrono::DateTime::from_naive_utc_and_offset(field_row.get("created_at"), Utc),
                };
                fields.push(field);
            }

            let mut schema_json: CollectionSchema = serde_json::from_str(&row.get::<String, _>("schema_json"))?;
            schema_json.fields = fields;

            let collection = Collection {
                id,
                name: row.get("name"),
                collection_type: match row.get::<String, _>("type").as_str() {
                    "auth" => CollectionType::Auth,
                    "view" => CollectionType::View,
                    _ => CollectionType::Base,
                },
                schema_json,
                list_rule: row.get("list_rule"),
                view_rule: row.get("view_rule"),
                create_rule: row.get("create_rule"),
                update_rule: row.get("update_rule"),
                delete_rule: row.get("delete_rule"),
                created_at: chrono::DateTime::from_naive_utc_and_offset(row.get("created_at"), Utc),
                updated_at: chrono::DateTime::from_naive_utc_and_offset(row.get("updated_at"), Utc),
            };

            Ok(Some(collection))
        } else {
            Ok(None)
        }
    }

    /// List all collections
    pub async fn list(&self) -> CoreResult<Vec<Collection>> {
        let rows = sqlx::query(
            r#"
            SELECT id, name, type, schema_json, list_rule, view_rule, create_rule, update_rule, delete_rule, created_at, updated_at
            FROM collections ORDER BY created_at DESC
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        let mut collections = Vec::new();
        for row in rows {
            let collection_id = Uuid::parse_str(&row.get::<String, _>("id"))?;

            // Get collection fields
            let field_rows = sqlx::query(
                "SELECT id, collection_id, name, type, required, unique_constraint, options_json, created_at FROM collection_fields WHERE collection_id = ?1"
            )
            .bind(collection_id.to_string())
            .fetch_all(&self.pool)
            .await?;

            let mut fields = Vec::new();
            for field_row in field_rows {
                let field = Field {
                    id: Uuid::parse_str(&field_row.get::<String, _>("id"))?,
                    collection_id,
                    name: field_row.get("name"),
                    field_type: serde_json::from_str(&field_row.get::<String, _>("type"))?,
                    required: field_row.get("required"),
                    unique_constraint: field_row.get("unique_constraint"),
                    options_json: field_row.get::<Option<String>, _>("options_json")
                        .map(|s| serde_json::from_str(&s))
                        .transpose()?,
                    created_at: chrono::DateTime::from_naive_utc_and_offset(field_row.get("created_at"), Utc),
                };
                fields.push(field);
            }

            let mut schema_json: CollectionSchema = serde_json::from_str(&row.get::<String, _>("schema_json"))?;
            schema_json.fields = fields;

            let collection = Collection {
                id: collection_id,
                name: row.get("name"),
                collection_type: match row.get::<String, _>("type").as_str() {
                    "auth" => CollectionType::Auth,
                    "view" => CollectionType::View,
                    _ => CollectionType::Base,
                },
                schema_json,
                list_rule: row.get("list_rule"),
                view_rule: row.get("view_rule"),
                create_rule: row.get("create_rule"),
                update_rule: row.get("update_rule"),
                delete_rule: row.get("delete_rule"),
                created_at: chrono::DateTime::from_naive_utc_and_offset(row.get("created_at"), Utc),
                updated_at: chrono::DateTime::from_naive_utc_and_offset(row.get("updated_at"), Utc),
            };

            collections.push(collection);
        }

        Ok(collections)
    }

    /// Update collection
    pub async fn update(&self, id: Uuid, request: UpdateCollectionRequest) -> CoreResult<Collection> {
        let mut tx = self.pool.begin().await?;
        let id_str = id.to_string();
        let updated_at = Utc::now();

        // Update collection name if provided
        if let Some(name) = &request.name {
            sqlx::query("UPDATE collections SET name = ?1, updated_at = ?2 WHERE id = ?3")
                .bind(name)
                .bind(updated_at)
                .bind(&id_str)
                .execute(&mut *tx)
                .await?;
        }

        // Update schema if provided
        if let Some(schema) = &request.schema {
            let schema_json = serde_json::to_string(schema)?;
            sqlx::query("UPDATE collections SET schema_json = ?1, updated_at = ?2 WHERE id = ?3")
                .bind(&schema_json)
                .bind(updated_at)
                .bind(&id_str)
                .execute(&mut *tx)
                .await?;

            // Delete existing fields
            sqlx::query("DELETE FROM collection_fields WHERE collection_id = ?1")
                .bind(&id_str)
                .execute(&mut *tx)
                .await?;

            // Insert new fields
            for field in &schema.fields {
                let field_id = field.id.to_string();
                let field_type_json = serde_json::to_string(&field.field_type)?;
                let options_json = field.options_json.as_ref().map(|o| serde_json::to_string(o)).transpose()?;

                sqlx::query(
                    r#"
                    INSERT INTO collection_fields (id, collection_id, name, type, required, unique_constraint, options_json, created_at)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                    "#,
                )
                .bind(&field_id)
                .bind(&id_str)
                .bind(&field.name)
                .bind(&field_type_json)
                .bind(field.required)
                .bind(field.unique_constraint)
                .bind(&options_json)
                .bind(field.created_at)
                .execute(&mut *tx)
                .await?;
            }
        }

        // Update rules if provided
        if let Some(rules) = &request.rules {
            sqlx::query(
                r#"
                UPDATE collections 
                SET list_rule = ?1, view_rule = ?2, create_rule = ?3, update_rule = ?4, delete_rule = ?5, updated_at = ?6
                WHERE id = ?7
                "#,
            )
            .bind(&rules.list_rule)
            .bind(&rules.view_rule)
            .bind(&rules.create_rule)
            .bind(&rules.update_rule)
            .bind(&rules.delete_rule)
            .bind(updated_at)
            .bind(&id_str)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        // Return updated collection
        self.find_by_id(id).await?.ok_or_else(|| CoreError::CollectionNotFound("Collection not found after update".to_string()))
    }

    /// Delete collection by ID
    pub async fn delete(&self, id: Uuid) -> CoreResult<bool> {
        let mut tx = self.pool.begin().await?;
        let id_str = id.to_string();

        // Delete collection fields first (foreign key constraint)
        sqlx::query("DELETE FROM collection_fields WHERE collection_id = ?1")
            .bind(&id_str)
            .execute(&mut *tx)
            .await?;

        // Delete collection
        let result = sqlx::query("DELETE FROM collections WHERE id = ?1")
            .bind(&id_str)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        Ok(result.rows_affected() > 0)
    }
}

/// Repository for audit log operations
#[derive(Clone)]
pub struct AuditLogRepository {
    pool: DatabasePool,
}

impl AuditLogRepository {
    pub fn new(pool: DatabasePool) -> Self {
        Self { pool }
    }

    /// Create a new audit log entry
    pub async fn create(&self, audit_log: AuditLog) -> CoreResult<()> {
        let audit_id = audit_log.id.to_string();
        let user_id_str = audit_log.user_id.map(|id| id.to_string());
        let details_json = audit_log.details_json.map(|d| serde_json::to_string(&d)).transpose()?;

        sqlx::query(
            r#"
            INSERT INTO audit_log (id, user_id, action, resource_type, resource_id, details_json, ip_address, user_agent, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
        )
        .bind(&audit_id)
        .bind(&user_id_str)
        .bind(&audit_log.action)
        .bind(&audit_log.resource_type)
        .bind(&audit_log.resource_id)
        .bind(&details_json)
        .bind(&audit_log.ip_address)
        .bind(&audit_log.user_agent)
        .bind(audit_log.created_at)
        .execute(&self.pool)
        .await?;

        debug!("Created audit log entry: {}", audit_log.action);
        Ok(())
    }

    /// Clean up old audit log entries
    pub async fn cleanup_old_entries(&self, days: i32) -> CoreResult<u64> {
        let result = sqlx::query(
            "DELETE FROM audit_log WHERE created_at < datetime('now', '-' || ?1 || ' days')"
        )
        .bind(days)
        .execute(&self.pool)
        .await?;

        info!("Cleaned up {} old audit log entries", result.rows_affected());
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CreateUserRequest, UserRole};
    use sqlx::SqlitePool;

    #[tokio::test]
    async fn test_create_user() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let repo = UserRepository::new(pool);

        let request = CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            role: Some(UserRole::Admin),
            verified: false,
        };
        let password_hash = "hashed_password".to_string();

        let user = repo.create(request, password_hash).await.unwrap();

        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.role, UserRole::Admin);
        assert!(!user.verified);
    }

    #[tokio::test]
    async fn test_find_user_by_email() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let repo = UserRepository::new(pool);

        let request = CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            role: Some(UserRole::Admin),
            verified: false,
        };
        let password_hash = "hashed_password".to_string();

        repo.create(request, password_hash).await.unwrap();

        let user = repo.find_by_email("test@example.com").await.unwrap().unwrap();

        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.role, UserRole::Admin);
        assert!(!user.verified);
    }

    #[tokio::test]
    async fn test_find_user_by_id() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let repo = UserRepository::new(pool);

        let request = CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            role: Some(UserRole::Admin),
            verified: false,
        };
        let password_hash = "hashed_password".to_string();

        let user = repo.create(request, password_hash).await.unwrap();

        let found_user = repo.find_by_id(user.id).await.unwrap().unwrap();

        assert_eq!(found_user.email, "test@example.com");
        assert_eq!(found_user.role, UserRole::Admin);
        assert!(!found_user.verified);
    }

    #[tokio::test]
    async fn test_update_user_verification() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let repo = UserRepository::new(pool);

        let request = CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            role: Some(UserRole::Admin),
            verified: false,
        };
        let password_hash = "hashed_password".to_string();

        let user = repo.create(request, password_hash).await.unwrap();

        repo.update_verification(user.id, true).await.unwrap();

        let updated_user = repo.find_by_id(user.id).await.unwrap().unwrap();

        assert!(updated_user.verified);
    }

    #[tokio::test]
    async fn test_update_user_role() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let repo = UserRepository::new(pool);

        let request = CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            role: Some(UserRole::Admin),
            verified: false,
        };
        let password_hash = "hashed_password".to_string();

        let user = repo.create(request, password_hash).await.unwrap();

        repo.update_role(user.id, UserRole::User).await.unwrap();

        let updated_user = repo.find_by_id(user.id).await.unwrap().unwrap();

        assert_eq!(updated_user.role, UserRole::User);
    }

    #[tokio::test]
    async fn test_list_users() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let repo = UserRepository::new(pool);

        let request = CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            role: Some(UserRole::Admin),
            verified: false,
        };
        let password_hash = "hashed_password".to_string();

        repo.create(request, password_hash).await.unwrap();

        let users = repo.list(10, 0).await.unwrap();

        assert_eq!(users.len(), 1);
        assert_eq!(users[0].email, "test@example.com");
        assert_eq!(users[0].role, UserRole::Admin);
        assert!(!users[0].verified);
    }

    #[tokio::test]
    async fn test_delete_user() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let repo = UserRepository::new(pool);

        let request = CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            role: Some(UserRole::Admin),
            verified: false,
        };
        let password_hash = "hashed_password".to_string();

        let user = repo.create(request, password_hash).await.unwrap();

        let deleted = repo.delete(user.id).await.unwrap();

        assert!(deleted);
        assert!(repo.find_by_id(user.id).await.unwrap().is_none());
    }
}

// Implement the server trait for UserRepository
#[cfg(feature = "server")]
#[axum::async_trait]
impl crate::server::routes::UserRepository for UserRepository {
    async fn find_by_email(&self, email: &str) -> Result<Option<crate::models::User>, Box<dyn std::error::Error + Send + Sync>> {
        match self.find_by_email(email).await {
            Ok(user) => Ok(user),
            Err(e) => Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
        }
    }
    
    async fn find_by_id(&self, id: uuid::Uuid) -> Result<Option<crate::models::User>, Box<dyn std::error::Error + Send + Sync>> {
        match self.find_by_id(id).await {
            Ok(user) => Ok(user),
            Err(e) => Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
        }
    }
    
    async fn create(&self, user: &crate::models::User) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // For now, we'll implement a simplified version that just returns Ok
        // In a real implementation, you would save the user to the database
        Ok(())
    }
}