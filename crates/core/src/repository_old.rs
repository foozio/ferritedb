use crate::{
    models::{
        AuditLog, Collection, CollectionType, CreateCollectionRequest,
        CreateUserRequest, Field, UpdateCollectionRequest, User, UserRole,
    },
    CoreError, CoreResult, DatabasePool,
};
use chrono::Utc;
use sqlx::Row;
use std::collections::HashMap;
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
        
        sqlx::query!(
            r#"
            INSERT INTO users (id, email, password_hash, role, verified, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            user_id,
            user.email,
            user.password_hash,
            user_role,
            user.verified,
            user.created_at,
            user.updated_at
        )
        .execute(&self.pool)
        .await?;

        debug!("Created user: {}", user.email);
        Ok(user)
    }

    /// Find user by email
    pub async fn find_by_email(&self, email: &str) -> CoreResult<Option<User>> {
        let row = sqlx::query!(
            "SELECT id, email, password_hash, role, verified, created_at, updated_at FROM users WHERE email = ?1",
            email
        )
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let user = User {
                id: Uuid::parse_str(&row.id.unwrap_or_default())?,
                email: row.email.unwrap_or_default(),
                password_hash: row.password_hash.unwrap_or_default(),
                role: match row.role.as_deref().unwrap_or("user") {
                    "admin" => UserRole::Admin,
                    "service" => UserRole::Service,
                    _ => UserRole::User,
                },
                verified: row.verified.unwrap_or(false),
                created_at: row.created_at.map(|dt| chrono::DateTime::from_naive_utc_and_offset(dt, Utc)).unwrap_or_else(|| Utc::now()),
                updated_at: row.updated_at.map(|dt| chrono::DateTime::from_naive_utc_and_offset(dt, Utc)).unwrap_or_else(|| Utc::now()),
            };
            Ok(Some(user))
        } else {
            Ok(None)
        }
    }

    /// Find user by ID
    pub async fn find_by_id(&self, id: Uuid) -> CoreResult<Option<User>> {
        let id_str = id.to_string();
        let row = sqlx::query!(
            "SELECT id, email, password_hash, role, verified, created_at, updated_at FROM users WHERE id = ?1",
            id_str
        )
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let user = User {
                id: Uuid::parse_str(&row.id.unwrap_or_default())?,
                email: row.email.unwrap_or_default(),
                password_hash: row.password_hash.unwrap_or_default(),
                role: match row.role.as_deref().unwrap_or("user") {
                    "admin" => UserRole::Admin,
                    "service" => UserRole::Service,
                    _ => UserRole::User,
                },
                verified: row.verified.unwrap_or(false),
                created_at: row.created_at.map(|dt| chrono::DateTime::from_naive_utc_and_offset(dt, Utc)).unwrap_or_else(|| Utc::now()),
                updated_at: row.updated_at.map(|dt| chrono::DateTime::from_naive_utc_and_offset(dt, Utc)).unwrap_or_else(|| Utc::now()),
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
        sqlx::query!(
            "UPDATE users SET verified = ?1, updated_at = ?2 WHERE id = ?3",
            verified,
            updated_at,
            id_str
        )
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
        sqlx::query!(
            "UPDATE users SET role = ?1, updated_at = ?2 WHERE id = ?3",
            role_str,
            updated_at,
            id_str
        )
        .execute(&self.pool)
        .await?;

        debug!("Updated user role: {} -> {}", id, role);
        Ok(())
    }

    /// List users with pagination
    pub async fn list(&self, limit: i64, offset: i64) -> CoreResult<Vec<User>> {
        let rows = sqlx::query!(
            "SELECT id, email, password_hash, role, verified, created_at, updated_at FROM users ORDER BY created_at DESC LIMIT ?1 OFFSET ?2",
            limit,
            offset
        )
        .fetch_all(&self.pool)
        .await?;

        let users = rows
            .into_iter()
            .map(|row| User {
                id: Uuid::parse_str(&row.id).unwrap(),
                email: row.email,
                password_hash: row.password_hash,
                role: match row.role.as_str() {
                    "admin" => UserRole::Admin,
                    "service" => UserRole::Service,
                    _ => UserRole::User,
                },
                verified: row.verified,
                created_at: row.created_at,
                updated_at: row.updated_at,
            })
            .collect();

        Ok(users)
    }

    /// Delete user by ID
    pub async fn delete(&self, id: Uuid) -> CoreResult<bool> {
        let result = sqlx::query!("DELETE FROM users WHERE id = ?1", id.to_string())
            .execute(&self.pool)
            .await?;

        let deleted = result.rows_affected() > 0;
        if deleted {
            debug!("Deleted user: {}", id);
        }
        Ok(deleted)
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
        let mut tx = self.pool.begin().await?;

        let collection = Collection::new(
            request.name,
            request.collection_type.unwrap_or(CollectionType::Base),
        )
        .with_schema(request.schema)
        .with_rules(request.rules);

        // Insert collection
        sqlx::query!(
            r#"
            INSERT INTO collections (id, name, type, schema_json, list_rule, view_rule, create_rule, update_rule, delete_rule, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
            collection.id.to_string(),
            collection.name,
            collection.collection_type.to_string(),
            serde_json::to_string(&collection.schema_json)?,
            collection.list_rule,
            collection.view_rule,
            collection.create_rule,
            collection.update_rule,
            collection.delete_rule,
            collection.created_at,
            collection.updated_at
        )
        .execute(&mut *tx)
        .await?;

        // Insert fields
        for field in &collection.schema_json.fields {
            sqlx::query!(
                r#"
                INSERT INTO collection_fields (id, collection_id, name, type, required, unique_constraint, options_json, created_at)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                "#,
                field.id.to_string(),
                collection.id.to_string(),
                field.name,
                serde_json::to_string(&field.field_type)?,
                field.required,
                field.unique_constraint,
                field.options_json.as_ref().map(|o| serde_json::to_string(o)).transpose()?,
                field.created_at
            )
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        info!("Created collection: {}", collection.name);
        Ok(collection)
    }

    /// Find collection by name
    pub async fn find_by_name(&self, name: &str) -> CoreResult<Option<Collection>> {
        let row = sqlx::query!(
            r#"
            SELECT id, name, type, schema_json, list_rule, view_rule, create_rule, update_rule, delete_rule, created_at, updated_at
            FROM collections WHERE name = ?1
            "#,
            name
        )
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            let collection_id = Uuid::parse_str(&row.id)?;
            
            // Fetch fields
            let field_rows = sqlx::query!(
                "SELECT id, collection_id, name, type, required, unique_constraint, options_json, created_at FROM collection_fields WHERE collection_id = ?1",
                collection_id.to_string()
            )
            .fetch_all(&self.pool)
            .await?;

            let fields: Result<Vec<Field>, CoreError> = field_rows
                .into_iter()
                .map(|field_row| {
                    Ok(Field {
                        id: Uuid::parse_str(&field_row.id)?,
                        collection_id: Uuid::parse_str(&field_row.collection_id)?,
                        name: field_row.name,
                        field_type: serde_json::from_str(&field_row.r#type)?,
                        required: field_row.required,
                        unique_constraint: field_row.unique_constraint,
                        options_json: field_row.options_json
                            .as_ref()
                            .map(|o| serde_json::from_str(o))
                            .transpose()?,
                        created_at: field_row.created_at,
                    })
                })
                .collect();

            let mut schema: crate::models::CollectionSchema = serde_json::from_str(&row.schema_json)?;
            schema.fields = fields?;

            let collection = Collection {
                id: collection_id,
                name: row.name,
                collection_type: match row.r#type.as_str() {
                    "auth" => CollectionType::Auth,
                    "view" => CollectionType::View,
                    _ => CollectionType::Base,
                },
                schema_json: schema,
                list_rule: row.list_rule,
                view_rule: row.view_rule,
                create_rule: row.create_rule,
                update_rule: row.update_rule,
                delete_rule: row.delete_rule,
                created_at: row.created_at,
                updated_at: row.updated_at,
            };

            Ok(Some(collection))
        } else {
            Ok(None)
        }
    }

    /// Find collection by ID
    pub async fn find_by_id(&self, id: Uuid) -> CoreResult<Option<Collection>> {
        let row = sqlx::query!(
            r#"
            SELECT id, name, type, schema_json, list_rule, view_rule, create_rule, update_rule, delete_rule, created_at, updated_at
            FROM collections WHERE id = ?1
            "#,
            id.to_string()
        )
        .fetch_optional(&self.pool)
        .await?;

        if let Some(row) = row {
            // Fetch fields
            let field_rows = sqlx::query!(
                "SELECT id, collection_id, name, type, required, unique_constraint, options_json, created_at FROM collection_fields WHERE collection_id = ?1",
                id.to_string()
            )
            .fetch_all(&self.pool)
            .await?;

            let fields: Result<Vec<Field>, CoreError> = field_rows
                .into_iter()
                .map(|field_row| {
                    Ok(Field {
                        id: Uuid::parse_str(&field_row.id)?,
                        collection_id: Uuid::parse_str(&field_row.collection_id)?,
                        name: field_row.name,
                        field_type: serde_json::from_str(&field_row.r#type)?,
                        required: field_row.required,
                        unique_constraint: field_row.unique_constraint,
                        options_json: field_row.options_json
                            .as_ref()
                            .map(|o| serde_json::from_str(o))
                            .transpose()?,
                        created_at: field_row.created_at,
                    })
                })
                .collect();

            let mut schema: crate::models::CollectionSchema = serde_json::from_str(&row.schema_json)?;
            schema.fields = fields?;

            let collection = Collection {
                id,
                name: row.name,
                collection_type: match row.r#type.as_str() {
                    "auth" => CollectionType::Auth,
                    "view" => CollectionType::View,
                    _ => CollectionType::Base,
                },
                schema_json: schema,
                list_rule: row.list_rule,
                view_rule: row.view_rule,
                create_rule: row.create_rule,
                update_rule: row.update_rule,
                delete_rule: row.delete_rule,
                created_at: row.created_at,
                updated_at: row.updated_at,
            };

            Ok(Some(collection))
        } else {
            Ok(None)
        }
    }

    /// List all collections
    pub async fn list(&self) -> CoreResult<Vec<Collection>> {
        let rows = sqlx::query!(
            r#"
            SELECT id, name, type, schema_json, list_rule, view_rule, create_rule, update_rule, delete_rule, created_at, updated_at
            FROM collections ORDER BY created_at DESC
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        let mut collections = Vec::new();
        for row in rows {
            let collection_id = Uuid::parse_str(&row.id)?;
            
            // Fetch fields for each collection
            let field_rows = sqlx::query!(
                "SELECT id, collection_id, name, type, required, unique_constraint, options_json, created_at FROM collection_fields WHERE collection_id = ?1",
                collection_id.to_string()
            )
            .fetch_all(&self.pool)
            .await?;

            let fields: Result<Vec<Field>, CoreError> = field_rows
                .into_iter()
                .map(|field_row| {
                    Ok(Field {
                        id: Uuid::parse_str(&field_row.id)?,
                        collection_id: Uuid::parse_str(&field_row.collection_id)?,
                        name: field_row.name,
                        field_type: serde_json::from_str(&field_row.r#type)?,
                        required: field_row.required,
                        unique_constraint: field_row.unique_constraint,
                        options_json: field_row.options_json
                            .as_ref()
                            .map(|o| serde_json::from_str(o))
                            .transpose()?,
                        created_at: field_row.created_at,
                    })
                })
                .collect();

            let mut schema: crate::models::CollectionSchema = serde_json::from_str(&row.schema_json)?;
            schema.fields = fields?;

            let collection = Collection {
                id: collection_id,
                name: row.name,
                collection_type: match row.r#type.as_str() {
                    "auth" => CollectionType::Auth,
                    "view" => CollectionType::View,
                    _ => CollectionType::Base,
                },
                schema_json: schema,
                list_rule: row.list_rule,
                view_rule: row.view_rule,
                create_rule: row.create_rule,
                update_rule: row.update_rule,
                delete_rule: row.delete_rule,
                created_at: row.created_at,
                updated_at: row.updated_at,
            };

            collections.push(collection);
        }

        Ok(collections)
    }

    /// Update collection
    pub async fn update(&self, id: Uuid, request: UpdateCollectionRequest) -> CoreResult<Collection> {
        let mut tx = self.pool.begin().await?;
        let updated_at = Utc::now();

        // Update collection metadata
        if let Some(name) = &request.name {
            sqlx::query!(
                "UPDATE collections SET name = ?1, updated_at = ?2 WHERE id = ?3",
                name,
                updated_at,
                id.to_string()
            )
            .execute(&mut *tx)
            .await?;
        }

        // Update schema if provided
        if let Some(schema) = &request.schema {
            sqlx::query!(
                "UPDATE collections SET schema_json = ?1, updated_at = ?2 WHERE id = ?3",
                serde_json::to_string(schema)?,
                updated_at,
                id.to_string()
            )
            .execute(&mut *tx)
            .await?;

            // Delete existing fields and insert new ones
            sqlx::query!(
                "DELETE FROM collection_fields WHERE collection_id = ?1",
                id.to_string()
            )
            .execute(&mut *tx)
            .await?;

            for field in &schema.fields {
                sqlx::query!(
                    r#"
                    INSERT INTO collection_fields (id, collection_id, name, type, required, unique_constraint, options_json, created_at)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                    "#,
                    field.id.to_string(),
                    id.to_string(),
                    field.name,
                    serde_json::to_string(&field.field_type)?,
                    field.required,
                    field.unique_constraint,
                    field.options_json.as_ref().map(|o| serde_json::to_string(o)).transpose()?,
                    field.created_at
                )
                .execute(&mut *tx)
                .await?;
            }
        }

        // Update rules if provided
        if let Some(rules) = &request.rules {
            sqlx::query!(
                r#"
                UPDATE collections 
                SET list_rule = ?1, view_rule = ?2, create_rule = ?3, update_rule = ?4, delete_rule = ?5, updated_at = ?6
                WHERE id = ?7
                "#,
                rules.list_rule,
                rules.view_rule,
                rules.create_rule,
                rules.update_rule,
                rules.delete_rule,
                updated_at,
                id.to_string()
            )
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        // Fetch and return updated collection
        self.find_by_id(id).await?.ok_or_else(|| {
            CoreError::CollectionNotFound(format!("Collection with id {} not found after update", id))
        })
    }

    /// Delete collection
    pub async fn delete(&self, id: Uuid) -> CoreResult<bool> {
        let mut tx = self.pool.begin().await?;

        // Delete fields first (due to foreign key constraint)
        sqlx::query!(
            "DELETE FROM collection_fields WHERE collection_id = ?1",
            id.to_string()
        )
        .execute(&mut *tx)
        .await?;

        // Delete collection
        let result = sqlx::query!(
            "DELETE FROM collections WHERE id = ?1",
            id.to_string()
        )
        .execute(&mut *tx)
        .await?;

        let deleted = result.rows_affected() > 0;
        
        if deleted {
            tx.commit().await?;
            info!("Deleted collection: {}", id);
        } else {
            tx.rollback().await?;
        }

        Ok(deleted)
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

    /// Create audit log entry
    pub async fn create(&self, audit_log: AuditLog) -> CoreResult<()> {
        sqlx::query!(
            r#"
            INSERT INTO audit_log (id, user_id, action, resource_type, resource_id, details_json, ip_address, user_agent, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            audit_log.id.to_string(),
            audit_log.user_id.map(|id| id.to_string()),
            audit_log.action,
            audit_log.resource_type,
            audit_log.resource_id,
            audit_log.details_json.map(|d| serde_json::to_string(&d)).transpose()?,
            audit_log.ip_address,
            audit_log.user_agent,
            audit_log.created_at
        )
        .execute(&self.pool)
        .await?;

        debug!("Created audit log entry: {} - {}", audit_log.action, audit_log.resource_type);
        Ok(())
    }

    /// List audit logs with pagination and filtering
    pub async fn list(
        &self,
        user_id: Option<Uuid>,
        resource_type: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> CoreResult<Vec<AuditLog>> {
        let mut query = "SELECT id, user_id, action, resource_type, resource_id, details_json, ip_address, user_agent, created_at FROM audit_log WHERE 1=1".to_string();
        let mut params: Vec<String> = Vec::new();

        if let Some(uid) = user_id {
            query.push_str(" AND user_id = ?");
            params.push(uid.to_string());
        }

        if let Some(rt) = resource_type {
            query.push_str(" AND resource_type = ?");
            params.push(rt.to_string());
        }

        query.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");
        params.push(limit.to_string());
        params.push(offset.to_string());

        let rows = sqlx::query(&query);
        let mut rows = rows;
        for param in &params {
            rows = rows.bind(param);
        }
        
        let rows = rows.fetch_all(&self.pool).await?;

        let audit_logs: Result<Vec<AuditLog>, CoreError> = rows
            .into_iter()
            .map(|row| {
                Ok(AuditLog {
                    id: Uuid::parse_str(&row.get::<String, _>("id"))?,
                    user_id: row.get::<Option<String>, _>("user_id")
                        .map(|id| Uuid::parse_str(&id))
                        .transpose()?,
                    action: row.get("action"),
                    resource_type: row.get("resource_type"),
                    resource_id: row.get("resource_id"),
                    details_json: row.get::<Option<String>, _>("details_json")
                        .map(|d| serde_json::from_str(&d))
                        .transpose()?,
                    ip_address: row.get("ip_address"),
                    user_agent: row.get("user_agent"),
                    created_at: row.get("created_at"),
                })
            })
            .collect();

        audit_logs
    }

    /// Delete old audit logs (for cleanup)
    pub async fn delete_older_than(&self, days: i64) -> CoreResult<u64> {
        let result = sqlx::query!(
            "DELETE FROM audit_log WHERE created_at < datetime('now', '-' || ?1 || ' days')",
            days
        )
        .execute(&self.pool)
        .await?;

        let deleted_count = result.rows_affected();
        if deleted_count > 0 {
            info!("Deleted {} old audit log entries", deleted_count);
        }

        Ok(deleted_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Database, models::*};
    use tempfile::TempDir;

    async fn setup_test_db() -> (TempDir, Database) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let database_url = format!("sqlite:{}", db_path.display());

        let db = Database::new(&database_url, 5, 30).await.unwrap();
        db.migrate().await.unwrap();
        (temp_dir, db)
    }

    #[tokio::test]
    async fn test_user_repository_create_and_find() {
        let (_dir, db) = setup_test_db().await;
        let repo = UserRepository::new(db.pool().clone());

        let request = CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            role: Some(UserRole::User),
            verified: false,
        };

        let user = repo.create(request, "hashed_password".to_string()).await.unwrap();

        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.role, UserRole::User);
        assert!(!user.verified);

        // Test find by email
        let found_user = repo.find_by_email("test@example.com").await.unwrap();
        assert!(found_user.is_some());
        let found_user = found_user.unwrap();
        assert_eq!(found_user.id, user.id);
        assert_eq!(found_user.email, user.email);

        // Test find by ID
        let found_by_id = repo.find_by_id(user.id).await.unwrap();
        assert!(found_by_id.is_some());
        assert_eq!(found_by_id.unwrap().id, user.id);

        // Test find non-existent user
        let not_found = repo.find_by_email("nonexistent@example.com").await.unwrap();
        assert!(not_found.is_none());

        db.close().await;
    }

    #[tokio::test]
    async fn test_user_repository_update_operations() {
        let (_dir, db) = setup_test_db().await;
        let repo = UserRepository::new(db.pool().clone());

        let request = CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            role: Some(UserRole::User),
            verified: false,
        };

        let user = repo.create(request, "hashed_password".to_string()).await.unwrap();

        // Test update verification
        repo.update_verification(user.id, true).await.unwrap();
        let updated_user = repo.find_by_id(user.id).await.unwrap().unwrap();
        assert!(updated_user.verified);

        // Test update role
        repo.update_role(user.id, UserRole::Admin).await.unwrap();
        let updated_user = repo.find_by_id(user.id).await.unwrap().unwrap();
        assert_eq!(updated_user.role, UserRole::Admin);

        db.close().await;
    }

    #[tokio::test]
    async fn test_user_repository_list_and_delete() {
        let (_dir, db) = setup_test_db().await;
        let repo = UserRepository::new(db.pool().clone());

        // Create multiple users
        for i in 0..3 {
            let request = CreateUserRequest {
                email: format!("user{}@example.com", i),
                password: "password123".to_string(),
                role: Some(UserRole::User),
                verified: false,
            };
            repo.create(request, "hashed_password".to_string()).await.unwrap();
        }

        // Test list users
        let users = repo.list(10, 0).await.unwrap();
        assert_eq!(users.len(), 3);

        // Test pagination
        let first_page = repo.list(2, 0).await.unwrap();
        assert_eq!(first_page.len(), 2);

        let second_page = repo.list(2, 2).await.unwrap();
        assert_eq!(second_page.len(), 1);

        // Test delete user
        let user_to_delete = &users[0];
        let deleted = repo.delete(user_to_delete.id).await.unwrap();
        assert!(deleted);

        // Verify deletion
        let remaining_users = repo.list(10, 0).await.unwrap();
        assert_eq!(remaining_users.len(), 2);

        // Test delete non-existent user
        let not_deleted = repo.delete(Uuid::new_v4()).await.unwrap();
        assert!(!not_deleted);

        db.close().await;
    }

    #[tokio::test]
    async fn test_collection_repository_create_and_find() {
        let (_dir, db) = setup_test_db().await;
        let repo = CollectionRepository::new(db.pool().clone());

        let mut schema = CollectionSchema::new();
        schema.add_field(Field::new(
            Uuid::new_v4(),
            "title".to_string(),
            FieldType::Text,
        ).required());
        schema.add_field(Field::new(
            Uuid::new_v4(),
            "content".to_string(),
            FieldType::Text,
        ));

        let rules = AccessRules {
            list_rule: Some("@request.auth.id != ''".to_string()),
            view_rule: Some("@request.auth.id != ''".to_string()),
            create_rule: Some("@request.auth.role = 'admin'".to_string()),
            update_rule: Some("@request.auth.id = record.owner".to_string()),
            delete_rule: Some("@request.auth.role = 'admin'".to_string()),
        };

        let request = CreateCollectionRequest {
            name: "posts".to_string(),
            collection_type: Some(CollectionType::Base),
            schema,
            rules,
        };

        let collection = repo.create(request).await.unwrap();

        assert_eq!(collection.name, "posts");
        assert_eq!(collection.collection_type, CollectionType::Base);
        assert_eq!(collection.schema_json.fields.len(), 2);
        assert!(collection.list_rule.is_some());

        // Test find by name
        let found_collection = repo.find_by_name("posts").await.unwrap();
        assert!(found_collection.is_some());
        let found_collection = found_collection.unwrap();
        assert_eq!(found_collection.id, collection.id);
        assert_eq!(found_collection.schema_json.fields.len(), 2);

        // Test find by ID
        let found_by_id = repo.find_by_id(collection.id).await.unwrap();
        assert!(found_by_id.is_some());
        assert_eq!(found_by_id.unwrap().id, collection.id);

        // Test find non-existent collection
        let not_found = repo.find_by_name("nonexistent").await.unwrap();
        assert!(not_found.is_none());

        db.close().await;
    }

    #[tokio::test]
    async fn test_collection_repository_list_and_update() {
        let (_dir, db) = setup_test_db().await;
        let repo = CollectionRepository::new(db.pool().clone());

        // Create multiple collections
        for i in 0..3 {
            let request = CreateCollectionRequest {
                name: format!("collection_{}", i),
                collection_type: Some(CollectionType::Base),
                schema: CollectionSchema::new(),
                rules: AccessRules::default(),
            };
            repo.create(request).await.unwrap();
        }

        // Test list collections
        let collections = repo.list().await.unwrap();
        assert_eq!(collections.len(), 3);

        // Test update collection
        let collection_to_update = &collections[0];
        let mut new_schema = CollectionSchema::new();
        new_schema.add_field(Field::new(
            Uuid::new_v4(),
            "new_field".to_string(),
            FieldType::Text,
        ));

        let update_request = UpdateCollectionRequest {
            name: Some("updated_collection".to_string()),
            schema: Some(new_schema),
            rules: Some(AccessRules {
                list_rule: Some("true".to_string()),
                ..Default::default()
            }),
        };

        let updated_collection = repo.update(collection_to_update.id, update_request).await.unwrap();
        assert_eq!(updated_collection.name, "updated_collection");
        assert_eq!(updated_collection.schema_json.fields.len(), 1);
        assert_eq!(updated_collection.list_rule, Some("true".to_string()));

        db.close().await;
    }

    #[tokio::test]
    async fn test_collection_repository_delete() {
        let (_dir, db) = setup_test_db().await;
        let repo = CollectionRepository::new(db.pool().clone());

        let request = CreateCollectionRequest {
            name: "test_collection".to_string(),
            collection_type: Some(CollectionType::Base),
            schema: CollectionSchema::new(),
            rules: AccessRules::default(),
        };

        let collection = repo.create(request).await.unwrap();

        // Test delete collection
        let deleted = repo.delete(collection.id).await.unwrap();
        assert!(deleted);

        // Verify deletion
        let not_found = repo.find_by_id(collection.id).await.unwrap();
        assert!(not_found.is_none());

        // Test delete non-existent collection
        let not_deleted = repo.delete(Uuid::new_v4()).await.unwrap();
        assert!(!not_deleted);

        db.close().await;
    }

    #[tokio::test]
    async fn test_audit_log_repository() {
        let (_dir, db) = setup_test_db().await;
        let repo = AuditLogRepository::new(db.pool().clone());

        let user_id = Uuid::new_v4();

        // Create audit log entries
        for i in 0..5 {
            let audit_log = AuditLog::new(
                Some(user_id),
                format!("ACTION_{}", i),
                "collection".to_string(),
                Some(format!("resource_{}", i)),
            )
            .with_details(serde_json::json!({"index": i}))
            .with_request_info(
                Some("192.168.1.1".to_string()),
                Some("Mozilla/5.0".to_string()),
            );

            repo.create(audit_log).await.unwrap();
        }

        // Test list all audit logs
        let all_logs = repo.list(None, None, 10, 0).await.unwrap();
        assert_eq!(all_logs.len(), 5);

        // Test list with user filter
        let user_logs = repo.list(Some(user_id), None, 10, 0).await.unwrap();
        assert_eq!(user_logs.len(), 5);

        // Test list with resource type filter
        let collection_logs = repo.list(None, Some("collection"), 10, 0).await.unwrap();
        assert_eq!(collection_logs.len(), 5);

        // Test pagination
        let first_page = repo.list(None, None, 3, 0).await.unwrap();
        assert_eq!(first_page.len(), 3);

        let second_page = repo.list(None, None, 3, 3).await.unwrap();
        assert_eq!(second_page.len(), 2);

        // Test with non-existent user
        let no_logs = repo.list(Some(Uuid::new_v4()), None, 10, 0).await.unwrap();
        assert_eq!(no_logs.len(), 0);

        db.close().await;
    }

    #[tokio::test]
    async fn test_audit_log_cleanup() {
        let (_dir, db) = setup_test_db().await;
        let repo = AuditLogRepository::new(db.pool().clone());

        // Create some audit log entries
        for i in 0..3 {
            let audit_log = AuditLog::new(
                None,
                format!("ACTION_{}", i),
                "test".to_string(),
                None,
            );
            repo.create(audit_log).await.unwrap();
        }

        // Test cleanup (should not delete recent entries)
        let deleted_count = repo.delete_older_than(1).await.unwrap();
        assert_eq!(deleted_count, 0);

        // Verify entries still exist
        let remaining_logs = repo.list(None, None, 10, 0).await.unwrap();
        assert_eq!(remaining_logs.len(), 3);

        db.close().await;
    }

    #[tokio::test]
    async fn test_repository_error_handling() {
        let (_dir, db) = setup_test_db().await;
        let user_repo = UserRepository::new(db.pool().clone());

        // Test duplicate email constraint
        let request1 = CreateUserRequest {
            email: "duplicate@example.com".to_string(),
            password: "password123".to_string(),
            role: Some(UserRole::User),
            verified: false,
        };

        let request2 = CreateUserRequest {
            email: "duplicate@example.com".to_string(),
            password: "password456".to_string(),
            role: Some(UserRole::User),
            verified: false,
        };

        // First creation should succeed
        user_repo.create(request1, "hash1".to_string()).await.unwrap();

        // Second creation should fail due to unique constraint
        let result = user_repo.create(request2, "hash2".to_string()).await;
        assert!(result.is_err());

        db.close().await;
    }

    #[tokio::test]
    async fn test_collection_with_complex_fields() {
        let (_dir, db) = setup_test_db().await;
        let repo = CollectionRepository::new(db.pool().clone());

        let mut schema = CollectionSchema::new();
        
        // Add various field types
        schema.add_field(Field::new(
            Uuid::new_v4(),
            "title".to_string(),
            FieldType::Text,
        ).required());

        schema.add_field(Field::new(
            Uuid::new_v4(),
            "owner".to_string(),
            FieldType::Relation {
                target_collection: "users".to_string(),
                cascade_delete: false,
            },
        ));

        schema.add_field(Field::new(
            Uuid::new_v4(),
            "avatar".to_string(),
            FieldType::File {
                max_size: Some(1024 * 1024),
                allowed_types: Some(vec!["image/jpeg".to_string(), "image/png".to_string()]),
            },
        ));

        schema.add_field(Field::new(
            Uuid::new_v4(),
            "published_at".to_string(),
            FieldType::DateTime,
        ));

        let request = CreateCollectionRequest {
            name: "complex_posts".to_string(),
            collection_type: Some(CollectionType::Base),
            schema,
            rules: AccessRules::default(),
        };

        let collection = repo.create(request).await.unwrap();
        assert_eq!(collection.schema_json.fields.len(), 4);

        // Verify field types are preserved
        let title_field = collection.schema_json.get_field("title").unwrap();
        assert!(matches!(title_field.field_type, FieldType::Text));
        assert!(title_field.required);

        let owner_field = collection.schema_json.get_field("owner").unwrap();
        assert!(matches!(owner_field.field_type, FieldType::Relation { .. }));

        let avatar_field = collection.schema_json.get_field("avatar").unwrap();
        assert!(matches!(avatar_field.field_type, FieldType::File { .. }));

        db.close().await;
    }
}
