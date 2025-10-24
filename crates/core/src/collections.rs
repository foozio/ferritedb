use crate::{
    models::{
        Collection, CollectionSchema, CreateCollectionRequest, CreateFieldRequest, Field,
        FieldOptions, FieldType, UpdateCollectionRequest,
    },
    repository::CollectionRepository,
    CoreError, CoreResult,
};
use serde_json::{json, Value};
use uuid::Uuid;

#[cfg(test)]
use crate::models::CollectionType;

/// Service for managing collections and their schemas
#[derive(Clone)]
pub struct CollectionService {
    repository: CollectionRepository,
}

impl CollectionService {
    pub fn new(repository: CollectionRepository) -> Self {
        Self { repository }
    }

    /// Create a new collection with validation
    pub async fn create_collection(
        &self,
        request: CreateCollectionRequest,
    ) -> CoreResult<Collection> {
        // Validate collection name
        self.validate_collection_name(&request.name)?;

        // Check if collection already exists
        if self.repository.find_by_name(&request.name).await?.is_some() {
            return Err(CoreError::CollectionAlreadyExists(request.name));
        }

        // Validate schema fields
        self.validate_schema(&request.schema)?;

        // Generate JSON Schema from field definitions
        let mut schema_with_json = request.schema;
        schema_with_json.json_schema = Some(self.generate_json_schema(&schema_with_json)?);

        let validated_request = CreateCollectionRequest {
            schema: schema_with_json,
            ..request
        };

        self.repository.create(validated_request).await
    }

    /// Create a new collection with validation (without table creation)
    /// This is used internally when the table creation is handled separately
    pub async fn create_collection_metadata_only(
        &self,
        request: CreateCollectionRequest,
    ) -> CoreResult<Collection> {
        self.create_collection(request).await
    }

    /// Add a field to an existing collection
    pub async fn add_field(
        &self,
        collection_name: &str,
        field_request: CreateFieldRequest,
    ) -> CoreResult<Collection> {
        let mut collection = self
            .repository
            .find_by_name(collection_name)
            .await?
            .ok_or_else(|| CoreError::CollectionNotFound(collection_name.to_string()))?;

        // Validate field name
        self.validate_field_name(&field_request.name)?;

        // Check if field already exists
        if collection
            .schema_json
            .get_field(&field_request.name)
            .is_some()
        {
            return Err(CoreError::FieldAlreadyExists(field_request.name));
        }

        // Validate field type and options
        self.validate_field_type(&field_request.field_type, &field_request.options)?;

        // Create new field
        let field = Field::new(collection.id, field_request.name, field_request.field_type);
        let field = if field_request.required {
            field.required()
        } else {
            field
        };
        let field = if field_request.unique_constraint {
            field.unique()
        } else {
            field
        };
        let field = if let Some(options) = field_request.options {
            field.with_options(options)
        } else {
            field
        };

        // Add field to schema
        collection.schema_json.add_field(field);

        // Regenerate JSON Schema
        collection.schema_json.json_schema =
            Some(self.generate_json_schema(&collection.schema_json)?);

        // Update collection
        let update_request = UpdateCollectionRequest {
            name: None,
            schema: Some(collection.schema_json),
            rules: None,
        };

        self.repository.update(collection.id, update_request).await
    }

    /// Remove a field from an existing collection
    pub async fn remove_field(
        &self,
        collection_name: &str,
        field_name: &str,
    ) -> CoreResult<Collection> {
        let mut collection = self
            .repository
            .find_by_name(collection_name)
            .await?
            .ok_or_else(|| CoreError::CollectionNotFound(collection_name.to_string()))?;

        // Check if field exists
        if collection.schema_json.get_field(field_name).is_none() {
            return Err(CoreError::FieldNotFound(field_name.to_string()));
        }

        // Remove field from schema
        collection.schema_json.remove_field(field_name);

        // Regenerate JSON Schema
        collection.schema_json.json_schema =
            Some(self.generate_json_schema(&collection.schema_json)?);

        // Update collection
        let update_request = UpdateCollectionRequest {
            name: None,
            schema: Some(collection.schema_json),
            rules: None,
        };

        self.repository.update(collection.id, update_request).await
    }

    /// Update an existing field in a collection
    pub async fn update_field(
        &self,
        collection_name: &str,
        field_name: &str,
        field_request: CreateFieldRequest,
    ) -> CoreResult<Collection> {
        let mut collection = self
            .repository
            .find_by_name(collection_name)
            .await?
            .ok_or_else(|| CoreError::CollectionNotFound(collection_name.to_string()))?;

        // Check if field exists
        if collection.schema_json.get_field(field_name).is_none() {
            return Err(CoreError::FieldNotFound(field_name.to_string()));
        }

        // Validate new field configuration
        self.validate_field_type(&field_request.field_type, &field_request.options)?;

        // Remove old field and add updated field
        collection.schema_json.remove_field(field_name);

        let field = Field::new(collection.id, field_request.name, field_request.field_type);
        let field = if field_request.required {
            field.required()
        } else {
            field
        };
        let field = if field_request.unique_constraint {
            field.unique()
        } else {
            field
        };
        let field = if let Some(options) = field_request.options {
            field.with_options(options)
        } else {
            field
        };

        collection.schema_json.add_field(field);

        // Regenerate JSON Schema
        collection.schema_json.json_schema =
            Some(self.generate_json_schema(&collection.schema_json)?);

        // Update collection
        let update_request = UpdateCollectionRequest {
            name: None,
            schema: Some(collection.schema_json),
            rules: None,
        };

        self.repository.update(collection.id, update_request).await
    }

    /// Get collection by name
    pub async fn get_collection(&self, name: &str) -> CoreResult<Option<Collection>> {
        self.repository.find_by_name(name).await
    }

    /// List all collections
    pub async fn list_collections(&self) -> CoreResult<Vec<Collection>> {
        self.repository.list().await
    }

    /// Delete a collection
    pub async fn delete_collection(&self, name: &str) -> CoreResult<bool> {
        let collection = self
            .repository
            .find_by_name(name)
            .await?
            .ok_or_else(|| CoreError::CollectionNotFound(name.to_string()))?;

        self.repository.delete(collection.id).await
    }

    /// Validate record data against collection schema
    pub async fn validate_record_data(
        &self,
        collection_name: &str,
        data: &Value,
    ) -> CoreResult<()> {
        let collection = self
            .repository
            .find_by_name(collection_name)
            .await?
            .ok_or_else(|| CoreError::CollectionNotFound(collection_name.to_string()))?;

        if let Some(json_schema) = &collection.schema_json.json_schema {
            self.validate_against_json_schema(data, json_schema)?;
        }

        // Additional field-level validation
        for field in &collection.schema_json.fields {
            self.validate_field_data(field, data)?;
        }

        Ok(())
    }

    /// Generate SQL table name for a collection
    pub fn get_table_name(&self, collection_name: &str) -> String {
        format!("records_{}", collection_name)
    }

    /// Generate CREATE TABLE SQL for a collection
    pub fn generate_create_table_sql(&self, collection: &Collection) -> CoreResult<String> {
        let table_name = self.get_table_name(&collection.name);
        let mut columns = Vec::new();
        let mut foreign_keys = Vec::new();

        columns.push("    id TEXT PRIMARY KEY".to_string());

        let mut has_created_at = false;
        let mut has_updated_at = false;

        for field in &collection.schema_json.fields {
            if field.name == "created_at" {
                has_created_at = true;
            }
            if field.name == "updated_at" {
                has_updated_at = true;
            }

            let column_def = self.field_to_sql_column(field)?;
            columns.push(format!("    {}", column_def));

            if let FieldType::Relation {
                target_collection, ..
            } = &field.field_type
            {
                let target_table = if target_collection == "users" {
                    // Built-in users table stores canonical auth records
                    "users".to_string()
                } else {
                    self.get_table_name(target_collection)
                };

                foreign_keys.push(format!(
                    "    FOREIGN KEY ({}) REFERENCES {}(id)",
                    field.name, target_table
                ));
            }
        }

        if !has_created_at {
            columns.push("    created_at DATETIME DEFAULT CURRENT_TIMESTAMP".to_string());
        }
        if !has_updated_at {
            columns.push("    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP".to_string());
        }

        let mut sql = format!("CREATE TABLE {} (\n", table_name);
        sql.push_str(&columns.join(",\n"));

        if !foreign_keys.is_empty() {
            sql.push_str(",\n");
            sql.push_str(&foreign_keys.join(",\n"));
        }

        sql.push_str("\n)");

        Ok(sql)
    }

    /// Generate DROP TABLE SQL for a collection
    pub fn generate_drop_table_sql(&self, collection_name: &str) -> String {
        let table_name = self.get_table_name(collection_name);
        format!("DROP TABLE IF EXISTS {}", table_name)
    }

    // Private helper methods

    fn validate_collection_name(&self, name: &str) -> CoreResult<()> {
        if name.is_empty() {
            return Err(CoreError::ValidationError(
                "Collection name cannot be empty".to_string(),
            ));
        }

        if name.len() > 64 {
            return Err(CoreError::ValidationError(
                "Collection name cannot exceed 64 characters".to_string(),
            ));
        }

        // Check for valid identifier (alphanumeric + underscore, starting with letter)
        if !name.chars().next().unwrap_or('0').is_ascii_alphabetic() {
            return Err(CoreError::ValidationError(
                "Collection name must start with a letter".to_string(),
            ));
        }

        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(CoreError::ValidationError(
                "Collection name can only contain letters, numbers, and underscores".to_string(),
            ));
        }

        // Reserved names
        let reserved_names = ["users", "collections", "collection_fields", "audit_log"];
        if reserved_names.contains(&name) {
            return Err(CoreError::ValidationError(format!(
                "Collection name '{}' is reserved",
                name
            )));
        }

        Ok(())
    }

    fn validate_field_name(&self, name: &str) -> CoreResult<()> {
        if name.is_empty() {
            return Err(CoreError::ValidationError(
                "Field name cannot be empty".to_string(),
            ));
        }

        if name.len() > 64 {
            return Err(CoreError::ValidationError(
                "Field name cannot exceed 64 characters".to_string(),
            ));
        }

        // Check for valid identifier
        if !name.chars().next().unwrap_or('0').is_ascii_alphabetic() {
            return Err(CoreError::ValidationError(
                "Field name must start with a letter".to_string(),
            ));
        }

        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(CoreError::ValidationError(
                "Field name can only contain letters, numbers, and underscores".to_string(),
            ));
        }

        // Reserved field names
        let reserved_names = ["id", "created_at", "updated_at"];
        if reserved_names.contains(&name) {
            return Err(CoreError::ValidationError(format!(
                "Field name '{}' is reserved",
                name
            )));
        }

        Ok(())
    }

    fn validate_schema(&self, schema: &CollectionSchema) -> CoreResult<()> {
        let mut field_names = std::collections::HashSet::new();

        for field in &schema.fields {
            // Check for duplicate field names
            if !field_names.insert(&field.name) {
                return Err(CoreError::ValidationError(format!(
                    "Duplicate field name: {}",
                    field.name
                )));
            }

            // Validate field name
            self.validate_field_name(&field.name)?;

            // Validate field type and options
            self.validate_field_type(&field.field_type, &field.options_json)?;
        }

        Ok(())
    }

    fn validate_field_type(
        &self,
        field_type: &FieldType,
        options: &Option<FieldOptions>,
    ) -> CoreResult<()> {
        match field_type {
            FieldType::Text => {
                if let Some(opts) = options {
                    if let Some(min_len) = opts.min_length {
                        if min_len > 10000 {
                            return Err(CoreError::ValidationError(
                                "Text field min_length cannot exceed 10000".to_string(),
                            ));
                        }
                    }
                    if let Some(max_len) = opts.max_length {
                        if max_len > 100000 {
                            return Err(CoreError::ValidationError(
                                "Text field max_length cannot exceed 100000".to_string(),
                            ));
                        }
                    }
                    if let (Some(min), Some(max)) = (opts.min_length, opts.max_length) {
                        if min > max {
                            return Err(CoreError::ValidationError(
                                "Text field min_length cannot be greater than max_length"
                                    .to_string(),
                            ));
                        }
                    }
                }
            }
            FieldType::Number => {
                if let Some(opts) = options {
                    if let (Some(min), Some(max)) = (opts.min_value, opts.max_value) {
                        if min > max {
                            return Err(CoreError::ValidationError(
                                "Number field min_value cannot be greater than max_value"
                                    .to_string(),
                            ));
                        }
                    }
                }
            }
            FieldType::Relation {
                target_collection, ..
            } => {
                if target_collection.is_empty() {
                    return Err(CoreError::ValidationError(
                        "Relation field must specify target_collection".to_string(),
                    ));
                }
                // Note: We could add validation to check if target collection exists,
                // but that might create circular dependencies during collection creation
            }
            FieldType::File {
                max_size,
                allowed_types,
            } => {
                if let Some(size) = max_size {
                    if *size > 100 * 1024 * 1024 {
                        // 100MB limit
                        return Err(CoreError::ValidationError(
                            "File field max_size cannot exceed 100MB".to_string(),
                        ));
                    }
                }
                if let Some(types) = allowed_types {
                    for mime_type in types {
                        if !mime_type.contains('/') {
                            return Err(CoreError::ValidationError(format!(
                                "Invalid MIME type: {}",
                                mime_type
                            )));
                        }
                    }
                }
            }
            _ => {} // Other types don't need special validation
        }

        Ok(())
    }

    pub(crate) fn generate_json_schema(&self, schema: &CollectionSchema) -> CoreResult<Value> {
        let mut json_schema = json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {},
            "required": []
        });

        {
            let properties = json_schema["properties"].as_object_mut().unwrap();
            for field in &schema.fields {
                let field_schema = self.field_to_json_schema(field)?;
                properties.insert(field.name.clone(), field_schema);
            }
        }

        {
            let required = json_schema["required"].as_array_mut().unwrap();
            for field in &schema.fields {
                if field.required {
                    required.push(json!(field.name));
                }
            }
        }

        Ok(json_schema)
    }

    fn field_to_json_schema(&self, field: &Field) -> CoreResult<Value> {
        let mut field_schema = match &field.field_type {
            FieldType::Text => json!({"type": "string"}),
            FieldType::Number => json!({"type": "number"}),
            FieldType::Boolean => json!({"type": "boolean"}),
            FieldType::Email => json!({
                "type": "string",
                "format": "email"
            }),
            FieldType::Url => json!({
                "type": "string",
                "format": "uri"
            }),
            FieldType::Json => json!({}), // Any valid JSON
            FieldType::Date => json!({
                "type": "string",
                "format": "date"
            }),
            FieldType::DateTime => json!({
                "type": "string",
                "format": "date-time"
            }),
            FieldType::Relation {
                target_collection, ..
            } => json!({
                "type": "string",
                "description": format!("Reference to {}", target_collection)
            }),
            FieldType::File { .. } => json!({
                "type": "string",
                "description": "File reference"
            }),
        };

        // Apply field options to schema
        if let Some(options) = &field.options_json {
            if let Some(min_len) = options.min_length {
                field_schema["minLength"] = json!(min_len);
            }
            if let Some(max_len) = options.max_length {
                field_schema["maxLength"] = json!(max_len);
            }
            if let Some(min_val) = options.min_value {
                field_schema["minimum"] = json!(min_val);
            }
            if let Some(max_val) = options.max_value {
                field_schema["maximum"] = json!(max_val);
            }
            if let Some(pattern) = &options.pattern {
                field_schema["pattern"] = json!(pattern);
            }
            if let Some(enum_values) = &options.enum_values {
                field_schema["enum"] = json!(enum_values);
            }
            if let Some(default) = &options.default_value {
                field_schema["default"] = default.clone();
            }
        }

        Ok(field_schema)
    }

    fn field_to_sql_column(&self, field: &Field) -> CoreResult<String> {
        let sql_type = match &field.field_type {
            FieldType::Text => "TEXT",
            FieldType::Number => "REAL",
            FieldType::Boolean => "BOOLEAN",
            FieldType::Email => "TEXT",
            FieldType::Url => "TEXT",
            FieldType::Json => "TEXT", // Store as JSON string
            FieldType::Date => "DATE",
            FieldType::DateTime => "DATETIME",
            FieldType::Relation { .. } => "TEXT", // Store as UUID string
            FieldType::File { .. } => "TEXT",     // Store file metadata as JSON
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

    fn validate_against_json_schema(&self, data: &Value, schema: &Value) -> CoreResult<()> {
        // This is a simplified validation - in a real implementation,
        // you'd use a proper JSON Schema validator like jsonschema crate

        if !data.is_object() {
            return Err(CoreError::ValidationError(
                "Record data must be a JSON object".to_string(),
            ));
        }

        let data_obj = data.as_object().ok_or_else(|| {
            CoreError::ValidationError("Record data must be a JSON object".to_string())
        })?;
        let schema_obj = schema.as_object().ok_or_else(|| {
            CoreError::ValidationError("Collection schema must be a JSON object".to_string())
        })?;

        // Check required fields
        if let Some(required) = schema_obj.get("required").and_then(|r| r.as_array()) {
            for req_field in required {
                if let Some(field_name) = req_field.as_str() {
                    if !data_obj.contains_key(field_name) {
                        return Err(CoreError::ValidationError(format!(
                            "Required field '{}' is missing",
                            field_name
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    fn validate_field_data(&self, field: &Field, data: &Value) -> CoreResult<()> {
        let data_obj = data.as_object().ok_or_else(|| {
            CoreError::ValidationError("Record data must be a JSON object".to_string())
        })?;

        if let Some(field_value) = data_obj.get(&field.name) {
            match &field.field_type {
                FieldType::Text => {
                    if !field_value.is_string() {
                        return Err(CoreError::ValidationError(format!(
                            "Field '{}' must be a string",
                            field.name
                        )));
                    }
                    if let Some(options) = &field.options_json {
                        let text = field_value.as_str().unwrap();
                        if let Some(min_len) = options.min_length {
                            if text.len() < min_len {
                                return Err(CoreError::ValidationError(format!(
                                    "Field '{}' is too short (minimum {} characters)",
                                    field.name, min_len
                                )));
                            }
                        }
                        if let Some(max_len) = options.max_length {
                            if text.len() > max_len {
                                return Err(CoreError::ValidationError(format!(
                                    "Field '{}' is too long (maximum {} characters)",
                                    field.name, max_len
                                )));
                            }
                        }
                    }
                }
                FieldType::Number => {
                    if !field_value.is_number() {
                        return Err(CoreError::ValidationError(format!(
                            "Field '{}' must be a number",
                            field.name
                        )));
                    }
                    if let Some(options) = &field.options_json {
                        let num = field_value.as_f64().unwrap();
                        if let Some(min_val) = options.min_value {
                            if num < min_val {
                                return Err(CoreError::ValidationError(format!(
                                    "Field '{}' is too small (minimum {})",
                                    field.name, min_val
                                )));
                            }
                        }
                        if let Some(max_val) = options.max_value {
                            if num > max_val {
                                return Err(CoreError::ValidationError(format!(
                                    "Field '{}' is too large (maximum {})",
                                    field.name, max_val
                                )));
                            }
                        }
                    }
                }
                FieldType::Boolean => {
                    if !field_value.is_boolean() {
                        return Err(CoreError::ValidationError(format!(
                            "Field '{}' must be a boolean",
                            field.name
                        )));
                    }
                }
                FieldType::Email => {
                    if !field_value.is_string() {
                        return Err(CoreError::ValidationError(format!(
                            "Field '{}' must be a string",
                            field.name
                        )));
                    }
                    let email = field_value.as_str().unwrap();
                    if !email.contains('@') || !email.contains('.') {
                        return Err(CoreError::ValidationError(format!(
                            "Field '{}' must be a valid email address",
                            field.name
                        )));
                    }
                }
                FieldType::Url => {
                    if !field_value.is_string() {
                        return Err(CoreError::ValidationError(format!(
                            "Field '{}' must be a string",
                            field.name
                        )));
                    }
                    let url = field_value.as_str().unwrap();
                    if !url.starts_with("http://") && !url.starts_with("https://") {
                        return Err(CoreError::ValidationError(format!(
                            "Field '{}' must be a valid URL",
                            field.name
                        )));
                    }
                }
                FieldType::Relation { .. } => {
                    if !field_value.is_string() {
                        return Err(CoreError::ValidationError(format!(
                            "Field '{}' must be a string (UUID)",
                            field.name
                        )));
                    }
                    let id_str = field_value.as_str().unwrap();
                    if Uuid::parse_str(id_str).is_err() {
                        return Err(CoreError::ValidationError(format!(
                            "Field '{}' must be a valid UUID",
                            field.name
                        )));
                    }
                }
                _ => {} // Other types handled by JSON schema validation
            }
        } else if field.required {
            return Err(CoreError::ValidationError(format!(
                "Required field '{}' is missing",
                field.name
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{repository::CollectionRepository, AccessRules, Database};
    use serde_json::json;
    use tempfile::TempDir;

    async fn setup_test_db() -> (TempDir, Database, CollectionService) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let database_url = format!("sqlite:{}", db_path.display());

        let db = Database::new(&database_url, 5, 30).await.unwrap();
        db.migrate().await.unwrap();

        let repository = CollectionRepository::new(db.pool().clone());
        let service = CollectionService::new(repository);

        (temp_dir, db, service)
    }

    #[tokio::test]
    async fn test_create_collection_with_fields() {
        let (_dir, db, service) = setup_test_db().await;

        let mut schema = CollectionSchema::new();
        schema
            .add_field(Field::new(Uuid::new_v4(), "title".to_string(), FieldType::Text).required());
        schema.add_field(Field::new(
            Uuid::new_v4(),
            "content".to_string(),
            FieldType::Text,
        ));
        schema.add_field(Field::new(
            Uuid::new_v4(),
            "published".to_string(),
            FieldType::Boolean,
        ));

        let request = CreateCollectionRequest {
            name: "posts".to_string(),
            collection_type: Some(CollectionType::Base),
            schema,
            rules: AccessRules::default(),
        };

        let collection = service.create_collection(request).await.unwrap();

        assert_eq!(collection.name, "posts");
        assert_eq!(collection.collection_type, CollectionType::Base);
        assert_eq!(collection.schema_json.fields.len(), 3);
        assert!(collection.schema_json.json_schema.is_some());

        // Verify JSON schema was generated
        let json_schema = collection.schema_json.json_schema.unwrap();
        assert!(json_schema["properties"]["title"].is_object());
        assert!(json_schema["properties"]["content"].is_object());
        assert!(json_schema["properties"]["published"].is_object());
        assert_eq!(json_schema["required"].as_array().unwrap().len(), 1); // Only title is required

        db.close().await;
    }

    #[tokio::test]
    async fn test_create_collection_validation() {
        let (_dir, db, service) = setup_test_db().await;

        // Test invalid collection name
        let request = CreateCollectionRequest {
            name: "".to_string(),
            collection_type: Some(CollectionType::Base),
            schema: CollectionSchema::new(),
            rules: AccessRules::default(),
        };

        let result = service.create_collection(request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot be empty"));

        // Test reserved collection name
        let request = CreateCollectionRequest {
            name: "users".to_string(),
            collection_type: Some(CollectionType::Base),
            schema: CollectionSchema::new(),
            rules: AccessRules::default(),
        };

        let result = service.create_collection(request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("reserved"));

        // Test invalid field name
        let mut schema = CollectionSchema::new();
        schema.add_field(Field::new(
            Uuid::new_v4(),
            "id".to_string(), // Reserved field name
            FieldType::Text,
        ));

        let request = CreateCollectionRequest {
            name: "test_collection".to_string(),
            collection_type: Some(CollectionType::Base),
            schema,
            rules: AccessRules::default(),
        };

        let result = service.create_collection(request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("reserved"));

        db.close().await;
    }

    #[tokio::test]
    async fn test_add_field_to_collection() {
        let (_dir, db, service) = setup_test_db().await;

        // Create initial collection
        let schema = CollectionSchema::new();
        let request = CreateCollectionRequest {
            name: "test_posts".to_string(),
            collection_type: Some(CollectionType::Base),
            schema,
            rules: AccessRules::default(),
        };

        service.create_collection(request).await.unwrap();

        // Add a field
        let field_request = CreateFieldRequest {
            name: "title".to_string(),
            field_type: FieldType::Text,
            required: true,
            unique_constraint: false,
            options: Some(FieldOptions {
                min_length: Some(1),
                max_length: Some(255),
                ..Default::default()
            }),
        };

        let updated_collection = service
            .add_field("test_posts", field_request)
            .await
            .unwrap();

        assert_eq!(updated_collection.schema_json.fields.len(), 1);
        let field = &updated_collection.schema_json.fields[0];
        assert_eq!(field.name, "title");
        assert!(field.required);
        assert!(!field.unique_constraint);
        assert!(field.options_json.is_some());

        // Verify JSON schema was updated
        let json_schema = updated_collection.schema_json.json_schema.unwrap();
        assert!(json_schema["properties"]["title"].is_object());
        assert_eq!(json_schema["required"].as_array().unwrap().len(), 1);

        db.close().await;
    }

    #[tokio::test]
    async fn test_field_type_validation() {
        let (_dir, db, service) = setup_test_db().await;

        // Test text field with invalid constraints
        let options = FieldOptions {
            min_length: Some(100),
            max_length: Some(50), // min > max
            ..Default::default()
        };

        let result = service.validate_field_type(&FieldType::Text, &Some(options));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("min_length cannot be greater than max_length"));

        // Test number field with invalid constraints
        let options = FieldOptions {
            min_value: Some(100.0),
            max_value: Some(50.0), // min > max
            ..Default::default()
        };

        let result = service.validate_field_type(&FieldType::Number, &Some(options));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("min_value cannot be greater than max_value"));

        // Test relation field without target
        let result = service.validate_field_type(
            &FieldType::Relation {
                target_collection: "".to_string(),
                cascade_delete: false,
            },
            &None,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must specify target_collection"));

        // Test file field with excessive size
        let result = service.validate_field_type(
            &FieldType::File {
                max_size: Some(200 * 1024 * 1024), // 200MB > 100MB limit
                allowed_types: None,
            },
            &None,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("cannot exceed 100MB"));

        db.close().await;
    }

    #[tokio::test]
    async fn test_json_schema_generation() {
        let (_dir, db, service) = setup_test_db().await;

        let mut schema = CollectionSchema::new();

        // Add various field types
        schema.add_field(
            Field::new(Uuid::new_v4(), "title".to_string(), FieldType::Text)
                .required()
                .with_options(FieldOptions {
                    min_length: Some(1),
                    max_length: Some(100),
                    ..Default::default()
                }),
        );

        schema.add_field(
            Field::new(Uuid::new_v4(), "score".to_string(), FieldType::Number).with_options(
                FieldOptions {
                    min_value: Some(0.0),
                    max_value: Some(100.0),
                    ..Default::default()
                },
            ),
        );

        schema.add_field(Field::new(
            Uuid::new_v4(),
            "email".to_string(),
            FieldType::Email,
        ));

        schema.add_field(Field::new(
            Uuid::new_v4(),
            "website".to_string(),
            FieldType::Url,
        ));

        schema.add_field(Field::new(
            Uuid::new_v4(),
            "published".to_string(),
            FieldType::Boolean,
        ));

        schema.add_field(Field::new(
            Uuid::new_v4(),
            "metadata".to_string(),
            FieldType::Json,
        ));

        let json_schema = service.generate_json_schema(&schema).unwrap();

        // Verify schema structure
        assert_eq!(
            json_schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(json_schema["type"], "object");

        let properties = &json_schema["properties"];
        assert!(properties["title"].is_object());
        assert_eq!(properties["title"]["type"], "string");
        assert_eq!(properties["title"]["minLength"], 1);
        assert_eq!(properties["title"]["maxLength"], 100);

        assert!(properties["score"].is_object());
        assert_eq!(properties["score"]["type"], "number");
        assert_eq!(properties["score"]["minimum"], 0.0);
        assert_eq!(properties["score"]["maximum"], 100.0);

        assert!(properties["email"].is_object());
        assert_eq!(properties["email"]["type"], "string");
        assert_eq!(properties["email"]["format"], "email");

        assert!(properties["website"].is_object());
        assert_eq!(properties["website"]["type"], "string");
        assert_eq!(properties["website"]["format"], "uri");

        assert!(properties["published"].is_object());
        assert_eq!(properties["published"]["type"], "boolean");

        assert!(properties["metadata"].is_object());

        // Verify required fields
        let required = json_schema["required"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0], "title");

        db.close().await;
    }

    #[tokio::test]
    async fn test_record_data_validation() {
        let (_dir, db, service) = setup_test_db().await;

        // Create collection with validation rules
        let mut schema = CollectionSchema::new();
        schema.add_field(
            Field::new(Uuid::new_v4(), "title".to_string(), FieldType::Text)
                .required()
                .with_options(FieldOptions {
                    min_length: Some(5),
                    max_length: Some(100),
                    ..Default::default()
                }),
        );

        schema.add_field(
            Field::new(Uuid::new_v4(), "score".to_string(), FieldType::Number).with_options(
                FieldOptions {
                    min_value: Some(0.0),
                    max_value: Some(100.0),
                    ..Default::default()
                },
            ),
        );

        schema.add_field(Field::new(
            Uuid::new_v4(),
            "email".to_string(),
            FieldType::Email,
        ));

        let request = CreateCollectionRequest {
            name: "test_validation".to_string(),
            collection_type: Some(CollectionType::Base),
            schema,
            rules: AccessRules::default(),
        };

        service.create_collection(request).await.unwrap();

        // Test valid data
        let valid_data = json!({
            "title": "Valid Title",
            "score": 85.5,
            "email": "test@example.com"
        });

        let result = service
            .validate_record_data("test_validation", &valid_data)
            .await;
        assert!(result.is_ok());

        // Test missing required field
        let invalid_data = json!({
            "score": 85.5,
            "email": "test@example.com"
        });

        let result = service
            .validate_record_data("test_validation", &invalid_data)
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Required field 'title' is missing"));

        // Test field too short
        let invalid_data = json!({
            "title": "Hi", // Too short (< 5 chars)
            "score": 85.5,
            "email": "test@example.com"
        });

        let result = service
            .validate_record_data("test_validation", &invalid_data)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));

        // Test number out of range
        let invalid_data = json!({
            "title": "Valid Title",
            "score": 150.0, // Too high (> 100)
            "email": "test@example.com"
        });

        let result = service
            .validate_record_data("test_validation", &invalid_data)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));

        // Test invalid email
        let invalid_data = json!({
            "title": "Valid Title",
            "score": 85.5,
            "email": "invalid-email" // No @ or .
        });

        let result = service
            .validate_record_data("test_validation", &invalid_data)
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("valid email address"));

        db.close().await;
    }

    #[tokio::test]
    async fn test_sql_table_generation() {
        let (_dir, db, service) = setup_test_db().await;

        let mut schema = CollectionSchema::new();
        schema
            .add_field(Field::new(Uuid::new_v4(), "title".to_string(), FieldType::Text).required());

        schema.add_field(Field::new(
            Uuid::new_v4(),
            "score".to_string(),
            FieldType::Number,
        ));

        schema.add_field(Field::new(
            Uuid::new_v4(),
            "published".to_string(),
            FieldType::Boolean,
        ));

        schema.add_field(Field::new(
            Uuid::new_v4(),
            "author_id".to_string(),
            FieldType::Relation {
                target_collection: "users".to_string(),
                cascade_delete: false,
            },
        ));

        let collection =
            Collection::new("posts".to_string(), CollectionType::Base).with_schema(schema);

        let create_sql = service.generate_create_table_sql(&collection).unwrap();

        // Verify SQL contains expected elements
        assert!(create_sql.contains("CREATE TABLE records_posts"));
        assert!(create_sql.contains("id TEXT PRIMARY KEY"));
        assert!(create_sql.contains("title TEXT NOT NULL"));
        assert!(create_sql.contains("score REAL"));
        assert!(create_sql.contains("published BOOLEAN"));
        assert!(create_sql.contains("author_id TEXT"));
        assert!(create_sql.contains("FOREIGN KEY (author_id) REFERENCES users(id)"));
        assert!(create_sql.contains("created_at DATETIME DEFAULT CURRENT_TIMESTAMP"));
        assert!(create_sql.contains("updated_at DATETIME DEFAULT CURRENT_TIMESTAMP"));

        // Test drop SQL
        let drop_sql = service.generate_drop_table_sql("posts");
        assert_eq!(drop_sql, "DROP TABLE IF EXISTS records_posts");

        db.close().await;
    }

    #[tokio::test]
    async fn test_collection_crud_operations() {
        let (_dir, db, service) = setup_test_db().await;

        // Create collection
        let schema = CollectionSchema::new();
        let request = CreateCollectionRequest {
            name: "test_crud".to_string(),
            collection_type: Some(CollectionType::Base),
            schema,
            rules: AccessRules::default(),
        };

        let collection = service.create_collection(request).await.unwrap();
        let collection_id = collection.id;

        // Get collection
        let retrieved = service.get_collection("test_crud").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, collection_id);

        // List collections
        let collections = service.list_collections().await.unwrap();
        assert!(collections.iter().any(|c| c.name == "test_crud"));

        // Delete collection
        let deleted = service.delete_collection("test_crud").await.unwrap();
        assert!(deleted);

        // Verify deletion
        let not_found = service.get_collection("test_crud").await.unwrap();
        assert!(not_found.is_none());

        db.close().await;
    }

    #[tokio::test]
    async fn test_duplicate_collection_name() {
        let (_dir, db, service) = setup_test_db().await;

        let request = CreateCollectionRequest {
            name: "duplicate_test".to_string(),
            collection_type: Some(CollectionType::Base),
            schema: CollectionSchema::new(),
            rules: AccessRules::default(),
        };

        // Create first collection
        service.create_collection(request.clone()).await.unwrap();

        // Try to create duplicate
        let result = service.create_collection(request).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));

        db.close().await;
    }

    #[tokio::test]
    async fn test_field_management() {
        let (_dir, db, service) = setup_test_db().await;

        // Create collection
        let schema = CollectionSchema::new();
        let request = CreateCollectionRequest {
            name: "field_test".to_string(),
            collection_type: Some(CollectionType::Base),
            schema,
            rules: AccessRules::default(),
        };

        service.create_collection(request).await.unwrap();

        // Add field
        let field_request = CreateFieldRequest {
            name: "title".to_string(),
            field_type: FieldType::Text,
            required: true,
            unique_constraint: false,
            options: None,
        };

        let updated = service
            .add_field("field_test", field_request)
            .await
            .unwrap();
        assert_eq!(updated.schema_json.fields.len(), 1);

        // Try to add duplicate field
        let duplicate_field = CreateFieldRequest {
            name: "title".to_string(),
            field_type: FieldType::Number,
            required: false,
            unique_constraint: false,
            options: None,
        };

        let result = service.add_field("field_test", duplicate_field).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));

        // Remove field
        let updated = service.remove_field("field_test", "title").await.unwrap();
        assert_eq!(updated.schema_json.fields.len(), 0);

        // Try to remove non-existent field
        let result = service.remove_field("field_test", "nonexistent").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));

        db.close().await;
    }
}
