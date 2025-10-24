use crate::{
    collections::CollectionService,
    models::{Collection, Field, FieldType},
    records::RecordService,
    CoreError, CoreResult, DatabasePool,
};
use sqlx::Row;
use std::collections::HashSet;

/// Service for managing dynamic database schema changes
#[derive(Clone)]
pub struct SchemaManager {
    pool: DatabasePool,
    collection_service: CollectionService,
    record_service: RecordService,
}

impl SchemaManager {
    pub fn new(
        pool: DatabasePool,
        collection_service: CollectionService,
        record_service: RecordService,
    ) -> Self {
        Self {
            pool,
            collection_service,
            record_service,
        }
    }

    /// Create a collection and its corresponding table
    pub async fn create_collection_with_table(&self, collection: &Collection) -> CoreResult<()> {
        let mut tx = self.pool.begin().await?;

        // Create the dynamic table
        let create_sql = self
            .collection_service
            .generate_create_table_sql(collection)?;
        dbg!(&create_sql);
        sqlx::query(&create_sql).execute(&mut *tx).await?;

        // Create indexes for unique fields
        for field in &collection.schema_json.fields {
            if field.unique_constraint {
                let table_name = self.collection_service.get_table_name(&collection.name);
                let index_sql = format!(
                    "CREATE UNIQUE INDEX idx_{}_{} ON {} ({})",
                    table_name, field.name, table_name, field.name
                );
                sqlx::query(&index_sql).execute(&mut *tx).await?;
            }

            // Create foreign key indexes for relations
            if let FieldType::Relation { .. } = &field.field_type {
                let table_name = self.collection_service.get_table_name(&collection.name);
                let fk_index_sql = format!(
                    "CREATE INDEX idx_{}_fk_{} ON {} ({})",
                    table_name, field.name, table_name, field.name
                );
                sqlx::query(&fk_index_sql).execute(&mut *tx).await?;
            }
        }

        tx.commit().await?;
        Ok(())
    }

    /// Delete a collection and its corresponding table
    pub async fn delete_collection_with_table(&self, collection_name: &str) -> CoreResult<()> {
        let mut tx = self.pool.begin().await?;

        // Check for foreign key references before deletion
        self.check_foreign_key_references(collection_name, &mut tx)
            .await?;

        // Drop the dynamic table
        let drop_sql = self
            .collection_service
            .generate_drop_table_sql(collection_name);
        sqlx::query(&drop_sql).execute(&mut *tx).await?;

        tx.commit().await?;
        Ok(())
    }

    /// Update collection schema and modify the corresponding table
    pub async fn update_collection_schema(
        &self,
        old_collection: &Collection,
        new_collection: &Collection,
    ) -> CoreResult<()> {
        let mut tx = self.pool.begin().await?;

        // Analyze schema changes
        let schema_changes = self.analyze_schema_changes(old_collection, new_collection)?;

        // Apply schema changes
        for change in schema_changes {
            match change {
                SchemaChange::AddField(field) => {
                    self.add_column_to_table(&new_collection.name, field.as_ref(), &mut tx)
                        .await?;
                }
                SchemaChange::RemoveField(field_name) => {
                    self.remove_column_from_table(&new_collection.name, &field_name, &mut tx)
                        .await?;
                }
                SchemaChange::ModifyField { old, new } => {
                    self.modify_column_in_table(
                        &new_collection.name,
                        old.as_ref(),
                        new.as_ref(),
                        &mut tx,
                    )
                    .await?;
                }
                SchemaChange::RecreateTable => {
                    // For complex changes, recreate the entire table
                    self.recreate_table(old_collection, new_collection, &mut tx)
                        .await?;
                    break; // No need to process other changes
                }
            }
        }

        tx.commit().await?;
        Ok(())
    }

    /// Ensure all collection tables exist and are up to date
    pub async fn sync_all_collection_tables(&self) -> CoreResult<()> {
        let collections = self.collection_service.list_collections().await?;

        for collection in collections {
            let table_exists = self.record_service.table_exists(&collection.name).await?;

            if !table_exists {
                self.create_collection_with_table(&collection).await?;
            } else {
                // Verify table schema matches collection schema
                self.verify_table_schema(&collection).await?;
            }
        }

        Ok(())
    }

    /// Check if a table schema matches the collection schema
    pub async fn verify_table_schema(&self, collection: &Collection) -> CoreResult<bool> {
        let table_name = self.collection_service.get_table_name(&collection.name);

        // Get table info from SQLite
        let table_info_sql = format!("PRAGMA table_info({})", table_name);
        let rows = sqlx::query(&table_info_sql).fetch_all(&self.pool).await?;

        let mut existing_columns = HashSet::new();
        for row in rows {
            let column_name: String = row.get("name");
            existing_columns.insert(column_name);
        }

        // Check if all collection fields exist as columns
        for field in &collection.schema_json.fields {
            if !existing_columns.contains(&field.name) {
                return Ok(false);
            }
        }

        // Check for standard columns
        let required_columns = ["id", "created_at", "updated_at"];
        for &col in &required_columns {
            if !existing_columns.contains(col) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    // Private helper methods

    async fn check_foreign_key_references(
        &self,
        collection_name: &str,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ) -> CoreResult<()> {
        // Check if any other collections reference this collection
        let collections = self.collection_service.list_collections().await?;

        for collection in collections {
            if collection.name == collection_name {
                continue;
            }

            for field in &collection.schema_json.fields {
                if let FieldType::Relation {
                    target_collection,
                    cascade_delete,
                } = &field.field_type
                {
                    if target_collection == collection_name {
                        if !cascade_delete {
                            // Check if there are any records referencing this collection
                            let ref_table =
                                self.collection_service.get_table_name(&collection.name);
                            let count_sql = format!(
                                "SELECT COUNT(*) as count FROM {} WHERE {} IS NOT NULL",
                                ref_table, field.name
                            );
                            let row = sqlx::query(&count_sql).fetch_one(&mut **tx).await?;
                            let count: i64 = row.get("count");

                            if count > 0 {
                                return Err(CoreError::ValidationError(format!(
                                    "Cannot delete collection '{}': {} records in '{}' reference it",
                                    collection_name, count, collection.name
                                )));
                            }
                        } else {
                            // Cascade delete: remove referencing records
                            let ref_table =
                                self.collection_service.get_table_name(&collection.name);
                            let delete_sql = format!(
                                "DELETE FROM {} WHERE {} IS NOT NULL",
                                ref_table, field.name
                            );
                            sqlx::query(&delete_sql).execute(&mut **tx).await?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn analyze_schema_changes(
        &self,
        old_collection: &Collection,
        new_collection: &Collection,
    ) -> CoreResult<Vec<SchemaChange>> {
        let mut changes = Vec::new();

        let old_fields: std::collections::HashMap<String, Field> = old_collection
            .schema_json
            .fields
            .iter()
            .map(|f| (f.name.clone(), f.clone()))
            .collect();

        let new_fields: std::collections::HashMap<String, Field> = new_collection
            .schema_json
            .fields
            .iter()
            .map(|f| (f.name.clone(), f.clone()))
            .collect();

        // Check for added fields
        for field in new_fields.values() {
            if !old_fields.contains_key(&field.name) {
                changes.push(SchemaChange::AddField(Box::new(field.clone())));
            }
        }

        // Check for removed fields
        for name in old_fields.keys() {
            if !new_fields.contains_key(name) {
                changes.push(SchemaChange::RemoveField(name.clone()));
            }
        }

        // Check for modified fields
        for new_field in new_fields.values() {
            if let Some(old_field) = old_fields.get(&new_field.name) {
                if self.field_changed(old_field, new_field) {
                    // For complex field changes, we might need to recreate the table
                    if self.requires_table_recreation(old_field, new_field) {
                        return Ok(vec![SchemaChange::RecreateTable]);
                    } else {
                        changes.push(SchemaChange::ModifyField {
                            old: Box::new(old_field.clone()),
                            new: Box::new(new_field.clone()),
                        });
                    }
                }
            }
        }

        Ok(changes)
    }

    fn field_changed(&self, old_field: &Field, new_field: &Field) -> bool {
        // Check if field type changed
        if std::mem::discriminant(&old_field.field_type)
            != std::mem::discriminant(&new_field.field_type)
        {
            return true;
        }

        // Check if constraints changed
        if old_field.required != new_field.required
            || old_field.unique_constraint != new_field.unique_constraint
        {
            return true;
        }

        // Check if options changed (simplified check)
        match (&old_field.options_json, &new_field.options_json) {
            (None, None) => false,
            (Some(_), None) | (None, Some(_)) => true,
            (Some(old_opts), Some(new_opts)) => {
                serde_json::to_string(old_opts).unwrap() != serde_json::to_string(new_opts).unwrap()
            }
        }
    }

    fn requires_table_recreation(&self, old_field: &Field, new_field: &Field) -> bool {
        // SQLite has limited ALTER TABLE support, so we need to recreate for:
        // - Type changes
        // - Adding/removing NOT NULL constraints on existing data
        // - Adding/removing UNIQUE constraints

        std::mem::discriminant(&old_field.field_type)
            != std::mem::discriminant(&new_field.field_type)
            || old_field.required != new_field.required
            || old_field.unique_constraint != new_field.unique_constraint
    }

    async fn add_column_to_table(
        &self,
        collection_name: &str,
        field: &Field,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ) -> CoreResult<()> {
        let table_name = self.collection_service.get_table_name(collection_name);
        let column_def = self.field_to_sql_column_def(field)?;

        let alter_sql = format!("ALTER TABLE {} ADD COLUMN {}", table_name, column_def);
        sqlx::query(&alter_sql).execute(&mut **tx).await?;

        // Create index if unique
        if field.unique_constraint {
            let index_sql = format!(
                "CREATE UNIQUE INDEX idx_{}_{} ON {} ({})",
                table_name, field.name, table_name, field.name
            );
            sqlx::query(&index_sql).execute(&mut **tx).await?;
        }

        Ok(())
    }

    async fn remove_column_from_table(
        &self,
        _collection_name: &str,
        _field_name: &str,
        _tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ) -> CoreResult<()> {
        // SQLite doesn't support DROP COLUMN directly, so we need to recreate the table
        // For now, we'll just mark this as requiring table recreation
        Err(CoreError::ValidationError(
            "Column removal requires table recreation".to_string(),
        ))
    }

    async fn modify_column_in_table(
        &self,
        _collection_name: &str,
        _old_field: &Field,
        _new_field: &Field,
        _tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ) -> CoreResult<()> {
        // SQLite has very limited ALTER COLUMN support
        // For most changes, we need to recreate the table
        Err(CoreError::ValidationError(
            "Column modification requires table recreation".to_string(),
        ))
    }

    async fn recreate_table(
        &self,
        old_collection: &Collection,
        new_collection: &Collection,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ) -> CoreResult<()> {
        let old_table_name = self.collection_service.get_table_name(&old_collection.name);
        let new_table_name = self.collection_service.get_table_name(&new_collection.name);
        let temp_table_name = format!("{}_temp", new_table_name);

        // Create new table with temporary name
        let create_sql = self
            .collection_service
            .generate_create_table_sql(new_collection)?
            .replace(&new_table_name, &temp_table_name);
        sqlx::query(&create_sql).execute(&mut **tx).await?;

        // Copy compatible data from old table to new table
        self.copy_compatible_data(
            old_collection,
            new_collection,
            &old_table_name,
            &temp_table_name,
            tx,
        )
        .await?;

        // Drop old table
        let drop_old_sql = format!("DROP TABLE {}", old_table_name);
        sqlx::query(&drop_old_sql).execute(&mut **tx).await?;

        // Rename temp table to final name
        let rename_sql = format!(
            "ALTER TABLE {} RENAME TO {}",
            temp_table_name, new_table_name
        );
        sqlx::query(&rename_sql).execute(&mut **tx).await?;

        Ok(())
    }

    async fn copy_compatible_data(
        &self,
        old_collection: &Collection,
        new_collection: &Collection,
        old_table: &str,
        new_table: &str,
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ) -> CoreResult<()> {
        // Find common fields between old and new schema
        let old_fields: std::collections::HashMap<String, Field> = old_collection
            .schema_json
            .fields
            .iter()
            .map(|f| (f.name.clone(), f.clone()))
            .collect();

        let new_fields: std::collections::HashMap<String, Field> = new_collection
            .schema_json
            .fields
            .iter()
            .map(|f| (f.name.clone(), f.clone()))
            .collect();

        let mut common_fields = Vec::new();
        for name in new_fields.keys() {
            if old_fields.contains_key(name) {
                common_fields.push(name.clone());
            }
        }

        if common_fields.is_empty() {
            return Ok(()); // No compatible data to copy
        }

        // Add standard fields
        common_fields.insert(0, "id".to_string());
        common_fields.push("created_at".to_string());
        common_fields.push("updated_at".to_string());

        let columns = common_fields.join(", ");
        let copy_sql = format!(
            "INSERT INTO {} ({}) SELECT {} FROM {}",
            new_table, columns, columns, old_table
        );

        sqlx::query(&copy_sql).execute(&mut **tx).await?;
        Ok(())
    }

    fn field_to_sql_column_def(&self, field: &Field) -> CoreResult<String> {
        let sql_type = match &field.field_type {
            FieldType::Text => "TEXT",
            FieldType::Number => "REAL",
            FieldType::Boolean => "BOOLEAN",
            FieldType::Email => "TEXT",
            FieldType::Url => "TEXT",
            FieldType::Json => "TEXT",
            FieldType::Date => "DATE",
            FieldType::DateTime => "DATETIME",
            FieldType::Relation { .. } => "TEXT",
            FieldType::File { .. } => "TEXT",
        };

        let mut column_def = format!("{} {}", field.name, sql_type);

        if field.required {
            column_def.push_str(" NOT NULL");
        }

        if field.unique_constraint {
            column_def.push_str(" UNIQUE");
        }

        Ok(column_def)
    }
}

#[derive(Debug, Clone)]
enum SchemaChange {
    AddField(Box<Field>),
    RemoveField(String),
    ModifyField { old: Box<Field>, new: Box<Field> },
    RecreateTable,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        collections::CollectionService, records::RecordService, repository::CollectionRepository,
        AccessRules, CollectionSchema, CollectionType, CreateCollectionRequest, Database,
    };
    use tempfile::TempDir;
    use uuid::Uuid;

    async fn setup_test_services() -> (
        TempDir,
        Database,
        CollectionService,
        RecordService,
        SchemaManager,
    ) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let database_url = format!("sqlite:{}", db_path.display());

        let db = Database::new(&database_url, 5, 30).await.unwrap();
        db.migrate().await.unwrap();

        let repository = CollectionRepository::new(db.pool().clone());
        let collection_service = CollectionService::new(repository);
        let record_service = RecordService::new(db.pool().clone(), collection_service.clone());
        let schema_manager = SchemaManager::new(
            db.pool().clone(),
            collection_service.clone(),
            record_service.clone(),
        );

        (
            temp_dir,
            db,
            collection_service,
            record_service,
            schema_manager,
        )
    }

    async fn create_test_collection(collection_service: &CollectionService) -> Collection {
        let mut schema = CollectionSchema::new();
        schema
            .add_field(Field::new(Uuid::new_v4(), "title".to_string(), FieldType::Text).required());
        schema.add_field(Field::new(
            Uuid::new_v4(),
            "content".to_string(),
            FieldType::Text,
        ));

        let request = CreateCollectionRequest {
            name: "test_collection".to_string(),
            collection_type: Some(CollectionType::Base),
            schema,
            rules: AccessRules::default(),
        };

        collection_service.create_collection(request).await.unwrap()
    }

    #[tokio::test]
    async fn test_create_collection_with_table() {
        let (_dir, db, collection_service, _record_service, schema_manager) =
            setup_test_services().await;
        let collection = create_test_collection(&collection_service).await;

        // Create collection with table
        schema_manager
            .create_collection_with_table(&collection)
            .await
            .unwrap();

        // Verify table exists
        let table_name = collection_service.get_table_name(&collection.name);
        let check_sql = "SELECT name FROM sqlite_master WHERE type='table' AND name = ?1";
        let row = sqlx::query(check_sql)
            .bind(&table_name)
            .fetch_optional(db.pool())
            .await
            .unwrap();

        assert!(row.is_some());

        // Verify table structure
        let table_info_sql = format!("PRAGMA table_info({})", table_name);
        let rows = sqlx::query(&table_info_sql)
            .fetch_all(db.pool())
            .await
            .unwrap();

        let column_names: Vec<String> = rows
            .iter()
            .map(|row| row.get::<String, _>("name"))
            .collect();

        assert!(column_names.contains(&"id".to_string()));
        assert!(column_names.contains(&"title".to_string()));
        assert!(column_names.contains(&"content".to_string()));
        assert!(column_names.contains(&"created_at".to_string()));
        assert!(column_names.contains(&"updated_at".to_string()));

        db.close().await;
    }

    #[tokio::test]
    async fn test_delete_collection_with_table() {
        let (_dir, db, collection_service, _record_service, schema_manager) =
            setup_test_services().await;
        let collection = create_test_collection(&collection_service).await;

        // Create collection with table
        schema_manager
            .create_collection_with_table(&collection)
            .await
            .unwrap();

        // Verify table exists
        let table_name = collection_service.get_table_name(&collection.name);
        let check_sql = "SELECT name FROM sqlite_master WHERE type='table' AND name = ?1";
        let row = sqlx::query(check_sql)
            .bind(&table_name)
            .fetch_optional(db.pool())
            .await
            .unwrap();
        assert!(row.is_some());

        // Delete collection with table
        schema_manager
            .delete_collection_with_table(&collection.name)
            .await
            .unwrap();

        // Verify table is deleted
        let row = sqlx::query(check_sql)
            .bind(&table_name)
            .fetch_optional(db.pool())
            .await
            .unwrap();
        assert!(row.is_none());

        db.close().await;
    }

    #[tokio::test]
    async fn test_verify_table_schema() {
        let (_dir, db, collection_service, _record_service, schema_manager) =
            setup_test_services().await;
        let collection = create_test_collection(&collection_service).await;

        // Create collection with table
        schema_manager
            .create_collection_with_table(&collection)
            .await
            .unwrap();

        // Verify schema matches
        let matches = schema_manager
            .verify_table_schema(&collection)
            .await
            .unwrap();
        assert!(matches);

        // Create a collection with different schema
        let mut different_schema = CollectionSchema::new();
        different_schema.add_field(Field::new(
            Uuid::new_v4(),
            "title".to_string(),
            FieldType::Text,
        ));
        different_schema.add_field(Field::new(
            Uuid::new_v4(),
            "missing_field".to_string(), // This field doesn't exist in the table
            FieldType::Text,
        ));

        let different_collection =
            Collection::new("test_collection".to_string(), CollectionType::Base)
                .with_schema(different_schema);

        // Verify schema doesn't match
        let matches = schema_manager
            .verify_table_schema(&different_collection)
            .await
            .unwrap();
        assert!(!matches);

        db.close().await;
    }

    #[tokio::test]
    async fn test_sync_all_collection_tables() {
        let (_dir, db, collection_service, _record_service, schema_manager) =
            setup_test_services().await;

        // Create multiple collections without tables
        let collection1 = create_test_collection(&collection_service).await;

        let mut schema2 = CollectionSchema::new();
        schema2
            .add_field(Field::new(Uuid::new_v4(), "name".to_string(), FieldType::Text).required());

        let request2 = CreateCollectionRequest {
            name: "test_collection2".to_string(),
            collection_type: Some(CollectionType::Base),
            schema: schema2,
            rules: AccessRules::default(),
        };

        let collection2 = collection_service
            .create_collection(request2)
            .await
            .unwrap();

        // Sync all tables
        schema_manager.sync_all_collection_tables().await.unwrap();

        // Verify both tables exist
        let table1_name = collection_service.get_table_name(&collection1.name);
        let table2_name = collection_service.get_table_name(&collection2.name);

        let check_sql = "SELECT name FROM sqlite_master WHERE type='table' AND name = ?1";

        let row1 = sqlx::query(check_sql)
            .bind(&table1_name)
            .fetch_optional(db.pool())
            .await
            .unwrap();
        assert!(row1.is_some());

        let row2 = sqlx::query(check_sql)
            .bind(&table2_name)
            .fetch_optional(db.pool())
            .await
            .unwrap();
        assert!(row2.is_some());

        db.close().await;
    }

    #[tokio::test]
    async fn test_analyze_schema_changes() {
        let (_dir, db, collection_service, _record_service, schema_manager) =
            setup_test_services().await;

        // Create original collection
        let mut old_schema = CollectionSchema::new();
        old_schema.add_field(Field::new(
            Uuid::new_v4(),
            "title".to_string(),
            FieldType::Text,
        ));
        old_schema.add_field(Field::new(
            Uuid::new_v4(),
            "content".to_string(),
            FieldType::Text,
        ));

        let old_collection =
            Collection::new("test".to_string(), CollectionType::Base).with_schema(old_schema);

        // Create new collection with changes
        let mut new_schema = CollectionSchema::new();
        new_schema.add_field(Field::new(
            Uuid::new_v4(),
            "title".to_string(),
            FieldType::Text,
        )); // Same field
        new_schema.add_field(Field::new(
            Uuid::new_v4(),
            "score".to_string(),
            FieldType::Number,
        )); // New field
            // content field removed

        let new_collection =
            Collection::new("test".to_string(), CollectionType::Base).with_schema(new_schema);

        let changes = schema_manager
            .analyze_schema_changes(&old_collection, &new_collection)
            .unwrap();

        // Should detect one added field and one removed field
        let mut has_add = false;
        let mut has_remove = false;

        for change in changes {
            match change {
                SchemaChange::AddField(field) => {
                    assert_eq!(field.name, "score");
                    has_add = true;
                }
                SchemaChange::RemoveField(name) => {
                    assert_eq!(name, "content");
                    has_remove = true;
                }
                _ => {}
            }
        }

        assert!(has_add);
        assert!(has_remove);

        db.close().await;
    }

    #[tokio::test]
    async fn test_field_changed_detection() {
        let (_dir, db, _collection_service, _record_service, schema_manager) =
            setup_test_services().await;

        let field1 = Field::new(Uuid::new_v4(), "test".to_string(), FieldType::Text);

        let field2 = Field::new(Uuid::new_v4(), "test".to_string(), FieldType::Text);

        // Same fields should not be detected as changed
        assert!(!schema_manager.field_changed(&field1, &field2));

        // Different types should be detected as changed
        let field3 = Field::new(Uuid::new_v4(), "test".to_string(), FieldType::Number);

        assert!(schema_manager.field_changed(&field1, &field3));

        // Different constraints should be detected as changed
        let field4 = Field::new(Uuid::new_v4(), "test".to_string(), FieldType::Text).required();

        assert!(schema_manager.field_changed(&field1, &field4));

        db.close().await;
    }

    #[tokio::test]
    async fn test_requires_table_recreation() {
        let (_dir, db, _collection_service, _record_service, schema_manager) =
            setup_test_services().await;

        let text_field = Field::new(Uuid::new_v4(), "test".to_string(), FieldType::Text);

        let number_field = Field::new(Uuid::new_v4(), "test".to_string(), FieldType::Number);

        // Type change should require recreation
        assert!(schema_manager.requires_table_recreation(&text_field, &number_field));

        // Constraint changes should require recreation
        let required_field =
            Field::new(Uuid::new_v4(), "test".to_string(), FieldType::Text).required();

        assert!(schema_manager.requires_table_recreation(&text_field, &required_field));

        let unique_field = Field::new(Uuid::new_v4(), "test".to_string(), FieldType::Text).unique();

        assert!(schema_manager.requires_table_recreation(&text_field, &unique_field));

        db.close().await;
    }
}
