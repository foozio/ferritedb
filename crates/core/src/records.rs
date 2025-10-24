use crate::{
    collections::CollectionService,
    models::{Collection, Field, FieldType, Record},
    CoreError, CoreResult, DatabasePool,
};
use chrono::Utc;
use serde_json::{json, Value};
use sqlx::QueryBuilder;
use sqlx::{Row, Sqlite};
use std::collections::HashMap;
use uuid::Uuid;

/// Service for managing dynamic collection records
#[derive(Clone)]
pub struct RecordService {
    pool: DatabasePool,
    collection_service: CollectionService,
}

#[derive(Clone)]
enum FilterValue {
    Text(String),
    Number(f64),
    Boolean(bool),
}

impl FilterValue {
    fn bind<'qb>(&self, builder: &mut QueryBuilder<'qb, Sqlite>) {
        match self {
            FilterValue::Text(value) => {
                builder.push_bind(value.clone());
            }
            FilterValue::Number(value) => {
                builder.push_bind(*value);
            }
            FilterValue::Boolean(value) => {
                builder.push_bind(*value);
            }
        }
    }
}

#[derive(Clone)]
enum FilterCondition {
    Equals { column: String, value: FilterValue },
    NotEquals { column: String, value: FilterValue },
    GreaterThan { column: String, value: FilterValue },
    LessThan { column: String, value: FilterValue },
    GreaterThanOrEqual { column: String, value: FilterValue },
    LessThanOrEqual { column: String, value: FilterValue },
    IsNotNull { column: String },
    IsNull { column: String },
}

impl RecordService {
    pub fn new(pool: DatabasePool, collection_service: CollectionService) -> Self {
        Self {
            pool,
            collection_service,
        }
    }

    /// Create the dynamic table for a collection
    pub async fn create_collection_table(&self, collection: &Collection) -> CoreResult<()> {
        let create_sql = self
            .collection_service
            .generate_create_table_sql(collection)?;

        sqlx::query(&create_sql).execute(&self.pool).await?;

        // Create indexes for unique fields
        for field in &collection.schema_json.fields {
            if field.unique_constraint {
                let table_name = self.collection_service.get_table_name(&collection.name);
                let index_sql = format!(
                    "CREATE UNIQUE INDEX idx_{}_{} ON {} ({})",
                    table_name, field.name, table_name, field.name
                );
                sqlx::query(&index_sql).execute(&self.pool).await?;
            }
        }

        Ok(())
    }

    /// Drop the dynamic table for a collection
    pub async fn drop_collection_table(&self, collection_name: &str) -> CoreResult<()> {
        let drop_sql = self
            .collection_service
            .generate_drop_table_sql(collection_name);

        sqlx::query(&drop_sql).execute(&self.pool).await?;

        Ok(())
    }

    /// Create a new record in a collection
    pub async fn create_record(&self, collection_name: &str, data: Value) -> CoreResult<Record> {
        let collection = self
            .collection_service
            .get_collection(collection_name)
            .await?
            .ok_or_else(|| CoreError::CollectionNotFound(collection_name.to_string()))?;

        // Validate record data against schema
        self.collection_service
            .validate_record_data(collection_name, &data)
            .await?;

        let record_id = Uuid::new_v4();
        let now = Utc::now();

        let mut tx = self.pool.begin().await?;

        // Build dynamic INSERT query
        let table_name = self.collection_service.get_table_name(collection_name);
        let mut columns = vec![
            "id".to_string(),
            "created_at".to_string(),
            "updated_at".to_string(),
        ];
        let mut placeholders = vec!["?1".to_string(), "?2".to_string(), "?3".to_string()];
        let mut values: Vec<Value> = vec![
            json!(record_id.to_string()),
            json!(now.to_rfc3339()),
            json!(now.to_rfc3339()),
        ];

        let data_obj = data.as_object().ok_or_else(|| {
            CoreError::ValidationError("Record data must be a JSON object".to_string())
        })?;
        let mut param_index = 4;

        for field in &collection.schema_json.fields {
            if let Some(field_value) = data_obj.get(&field.name) {
                columns.push(field.name.clone());
                placeholders.push(format!("?{}", param_index));

                // Convert value based on field type
                let converted_value = self.convert_value_for_storage(field, field_value)?;
                values.push(converted_value);
                param_index += 1;
            } else if field.required {
                return Err(CoreError::ValidationError(format!(
                    "Required field '{}' is missing",
                    field.name
                )));
            }
        }

        let insert_sql = format!(
            "INSERT INTO {} ({}) VALUES ({})",
            table_name,
            columns.join(", "),
            placeholders.join(", ")
        );

        let mut query = sqlx::query(&insert_sql);
        for value in &values {
            query = self.bind_value(query, value)?;
        }

        query.execute(&mut *tx).await?;
        tx.commit().await?;

        // Create record object
        let mut record_data = HashMap::new();
        for (field_name, field_value) in data_obj.iter() {
            record_data.insert(field_name.clone(), field_value.clone());
        }

        Ok(Record {
            id: record_id,
            collection_id: collection.id,
            data: record_data,
            created_at: now,
            updated_at: now,
        })
    }

    /// Get a record by ID from a collection
    pub async fn get_record(
        &self,
        collection_name: &str,
        record_id: Uuid,
    ) -> CoreResult<Option<Record>> {
        let collection = self
            .collection_service
            .get_collection(collection_name)
            .await?
            .ok_or_else(|| CoreError::CollectionNotFound(collection_name.to_string()))?;

        let table_name = self.collection_service.get_table_name(collection_name);
        let select_sql = format!("SELECT * FROM {} WHERE id = ?1", table_name);

        let row = sqlx::query(&select_sql)
            .bind(record_id.to_string())
            .fetch_optional(&self.pool)
            .await?;

        if let Some(row) = row {
            let record = self.row_to_record(&collection, row)?;
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    /// List records from a collection with pagination
    pub async fn list_records(
        &self,
        collection_name: &str,
        limit: i64,
        offset: i64,
    ) -> CoreResult<Vec<Record>> {
        self.list_records_with_query(collection_name, limit, offset, None, None, None)
            .await
    }

    /// List records with advanced query options
    pub async fn list_records_with_query(
        &self,
        collection_name: &str,
        limit: i64,
        offset: i64,
        filter: Option<&str>,
        sort: Option<&str>,
        fields: Option<&[String]>,
    ) -> CoreResult<Vec<Record>> {
        let collection = self
            .collection_service
            .get_collection(collection_name)
            .await?
            .ok_or_else(|| CoreError::CollectionNotFound(collection_name.to_string()))?;

        let table_name = self.collection_service.get_table_name(collection_name);

        // Build SELECT clause with field selection
        let select_clause = if let Some(field_list) = fields {
            let mut columns = vec![
                "id".to_string(),
                "created_at".to_string(),
                "updated_at".to_string(),
            ];
            for field_name in field_list {
                // Validate field exists in collection schema
                if collection.schema_json.get_field(field_name).is_some() {
                    columns.push(field_name.clone());
                }
            }
            columns.join(", ")
        } else {
            "*".to_string()
        };

        let filter_condition = match filter {
            Some(filter_expr) => Some(self.parse_filter_condition(filter_expr, &collection)?),
            None => None,
        };

        let order_clause = if let Some(sort_expr) = sort {
            self.parse_sort_expression(sort_expr, &collection)?
        } else {
            "created_at DESC".to_string()
        };

        let mut query_builder: QueryBuilder<Sqlite> =
            QueryBuilder::new(format!("SELECT {} FROM {}", select_clause, table_name));

        if let Some(condition) = filter_condition.as_ref() {
            query_builder.push(" WHERE ");
            self.apply_filter_condition(&mut query_builder, condition);
        }

        query_builder.push(" ORDER BY ");
        query_builder.push(&order_clause);
        query_builder.push(" LIMIT ");
        query_builder.push_bind(limit);
        query_builder.push(" OFFSET ");
        query_builder.push_bind(offset);

        let rows = query_builder.build().fetch_all(&self.pool).await?;

        let mut records = Vec::new();
        for row in rows {
            let record = self.row_to_record(&collection, row)?;
            records.push(record);
        }

        Ok(records)
    }

    /// Count records with optional filter
    pub async fn count_records_with_filter(
        &self,
        collection_name: &str,
        filter: Option<&str>,
    ) -> CoreResult<i64> {
        let collection = self
            .collection_service
            .get_collection(collection_name)
            .await?
            .ok_or_else(|| CoreError::CollectionNotFound(collection_name.to_string()))?;

        let table_name = self.collection_service.get_table_name(collection_name);
        let filter_condition = match filter {
            Some(filter_expr) => Some(self.parse_filter_condition(filter_expr, &collection)?),
            None => None,
        };

        let mut query_builder: QueryBuilder<Sqlite> =
            QueryBuilder::new(format!("SELECT COUNT(*) as count FROM {}", table_name));

        if let Some(condition) = filter_condition.as_ref() {
            query_builder.push(" WHERE ");
            self.apply_filter_condition(&mut query_builder, condition);
        }

        let row = query_builder.build().fetch_one(&self.pool).await?;

        Ok(row.get::<i64, _>("count"))
    }

    /// Update a record in a collection
    pub async fn update_record(
        &self,
        collection_name: &str,
        record_id: Uuid,
        data: Value,
    ) -> CoreResult<Record> {
        let collection = self
            .collection_service
            .get_collection(collection_name)
            .await?
            .ok_or_else(|| CoreError::CollectionNotFound(collection_name.to_string()))?;

        // Validate record data against schema
        self.collection_service
            .validate_record_data(collection_name, &data)
            .await?;

        let now = Utc::now();
        let mut tx = self.pool.begin().await?;

        // Build dynamic UPDATE query
        let table_name = self.collection_service.get_table_name(collection_name);
        let mut set_clauses = vec!["updated_at = ?1".to_string()];
        let mut values: Vec<Value> = vec![json!(now.to_rfc3339())];

        let data_obj = data.as_object().ok_or_else(|| {
            CoreError::ValidationError("Record data must be a JSON object".to_string())
        })?;
        let mut param_index = 2;

        for field in &collection.schema_json.fields {
            if let Some(field_value) = data_obj.get(&field.name) {
                set_clauses.push(format!("{} = ?{}", field.name, param_index));

                // Convert value based on field type
                let converted_value = self.convert_value_for_storage(field, field_value)?;
                values.push(converted_value);
                param_index += 1;
            }
        }

        let update_sql = format!(
            "UPDATE {} SET {} WHERE id = ?{}",
            table_name,
            set_clauses.join(", "),
            param_index
        );

        values.push(json!(record_id.to_string()));

        let mut query = sqlx::query(&update_sql);
        for value in &values {
            query = self.bind_value(query, value)?;
        }

        let result = query.execute(&mut *tx).await?;

        if result.rows_affected() == 0 {
            return Err(CoreError::RecordNotFound(record_id.to_string()));
        }

        tx.commit().await?;

        // Fetch and return updated record
        self.get_record(collection_name, record_id)
            .await?
            .ok_or_else(|| CoreError::RecordNotFound(record_id.to_string()))
    }

    /// Delete a record from a collection
    pub async fn delete_record(&self, collection_name: &str, record_id: Uuid) -> CoreResult<bool> {
        let table_name = self.collection_service.get_table_name(collection_name);
        let delete_sql = format!("DELETE FROM {} WHERE id = ?1", table_name);

        let result = sqlx::query(&delete_sql)
            .bind(record_id.to_string())
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Count records in a collection
    pub async fn count_records(&self, collection_name: &str) -> CoreResult<i64> {
        let table_name = self.collection_service.get_table_name(collection_name);
        let count_sql = format!("SELECT COUNT(*) as count FROM {}", table_name);

        let row = sqlx::query(&count_sql).fetch_one(&self.pool).await?;

        Ok(row.get::<i64, _>("count"))
    }

    /// Check if a collection table exists
    pub async fn table_exists(&self, collection_name: &str) -> CoreResult<bool> {
        let table_name = self.collection_service.get_table_name(collection_name);
        let check_sql = "SELECT name FROM sqlite_master WHERE type='table' AND name = ?1";

        let row = sqlx::query(check_sql)
            .bind(&table_name)
            .fetch_optional(&self.pool)
            .await?;

        Ok(row.is_some())
    }

    // Private helper methods

    fn convert_value_for_storage(&self, field: &Field, value: &Value) -> CoreResult<Value> {
        match &field.field_type {
            FieldType::Text | FieldType::Email | FieldType::Url => {
                if let Some(s) = value.as_str() {
                    Ok(json!(s))
                } else {
                    Err(CoreError::ValidationError(format!(
                        "Field '{}' must be a string",
                        field.name
                    )))
                }
            }
            FieldType::Number => {
                if let Some(n) = value.as_f64() {
                    Ok(json!(n))
                } else {
                    Err(CoreError::ValidationError(format!(
                        "Field '{}' must be a number",
                        field.name
                    )))
                }
            }
            FieldType::Boolean => {
                if let Some(b) = value.as_bool() {
                    Ok(json!(b))
                } else {
                    Err(CoreError::ValidationError(format!(
                        "Field '{}' must be a boolean",
                        field.name
                    )))
                }
            }
            FieldType::Json => {
                // Store JSON as string
                Ok(json!(value.to_string()))
            }
            FieldType::Date | FieldType::DateTime => {
                if let Some(s) = value.as_str() {
                    // Validate date/datetime format
                    if field.field_type == FieldType::Date {
                        chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").map_err(|_| {
                            CoreError::ValidationError(format!(
                                "Field '{}' must be a valid date (YYYY-MM-DD)",
                                field.name
                            ))
                        })?;
                    } else {
                        chrono::DateTime::parse_from_rfc3339(s).map_err(|_| {
                            CoreError::ValidationError(format!(
                                "Field '{}' must be a valid datetime (RFC3339)",
                                field.name
                            ))
                        })?;
                    }
                    Ok(json!(s))
                } else {
                    Err(CoreError::ValidationError(format!(
                        "Field '{}' must be a string",
                        field.name
                    )))
                }
            }
            FieldType::Relation { .. } => {
                if let Some(s) = value.as_str() {
                    // Validate UUID format
                    Uuid::parse_str(s).map_err(|_| {
                        CoreError::ValidationError(format!(
                            "Field '{}' must be a valid UUID",
                            field.name
                        ))
                    })?;
                    Ok(json!(s))
                } else {
                    Err(CoreError::ValidationError(format!(
                        "Field '{}' must be a string (UUID)",
                        field.name
                    )))
                }
            }
            FieldType::File { .. } => {
                if value.is_object() {
                    Ok(value.clone())
                } else {
                    Err(CoreError::ValidationError(format!(
                        "Field '{}' must be a JSON object describing file metadata",
                        field.name
                    )))
                }
            }
        }
    }

    fn bind_value<'a>(
        &self,
        query: sqlx::query::Query<'a, Sqlite, sqlx::sqlite::SqliteArguments<'a>>,
        value: &Value,
    ) -> CoreResult<sqlx::query::Query<'a, Sqlite, sqlx::sqlite::SqliteArguments<'a>>> {
        match value {
            Value::String(s) => Ok(query.bind(s.clone())),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(query.bind(i))
                } else if let Some(f) = n.as_f64() {
                    Ok(query.bind(f))
                } else {
                    Err(CoreError::ValidationError(
                        "Invalid number format".to_string(),
                    ))
                }
            }
            Value::Bool(b) => Ok(query.bind(*b)),
            Value::Null => Ok(query.bind(None::<String>)),
            _ => Ok(query.bind(value.to_string())),
        }
    }

    fn row_to_record(
        &self,
        collection: &Collection,
        row: sqlx::sqlite::SqliteRow,
    ) -> CoreResult<Record> {
        let id_str: String = row.get("id");
        let id = Uuid::parse_str(&id_str)?;
        let created_at: chrono::DateTime<Utc> = row.get("created_at");
        let updated_at: chrono::DateTime<Utc> = row.get("updated_at");

        let mut data = HashMap::new();

        for field in &collection.schema_json.fields {
            if let Ok(value) = self.get_field_value_from_row(&row, field) {
                if !value.is_null() {
                    data.insert(field.name.clone(), value);
                }
            }
        }

        Ok(Record {
            id,
            collection_id: collection.id,
            data,
            created_at,
            updated_at,
        })
    }

    /// Parse filter expression into a structured condition
    fn parse_filter_condition(
        &self,
        filter: &str,
        collection: &Collection,
    ) -> CoreResult<FilterCondition> {
        let filter = filter.trim();
        if filter.is_empty() {
            return Err(CoreError::ValidationError(
                "Filter expression cannot be empty".to_string(),
            ));
        }

        // Define operators in order of precedence (longest first to avoid partial matches)
        let operators = [
            ("!=", "NotEquals"),
            (">=", "GreaterThanOrEqual"),
            ("<=", "LessThanOrEqual"),
            ("=", "Equals"),
            (">", "GreaterThan"),
            ("<", "LessThan"),
        ];

        for (op_str, op_name) in &operators {
            if let Some((field_name, raw_value)) = filter.split_once(op_str) {
                let field_name = field_name.trim();
                let raw_value = raw_value.trim();
                let column = self
                    .resolve_filter_column(field_name, collection)
                    .ok_or_else(|| {
                        CoreError::ValidationError(format!(
                            "Field '{}' not found in collection",
                            field_name
                        ))
                    })?;

                let value = self.parse_filter_value(field_name, raw_value, collection)?;
                return match *op_name {
                    "Equals" => Ok(FilterCondition::Equals { column, value }),
                    "NotEquals" => Ok(FilterCondition::NotEquals { column, value }),
                    "GreaterThan" => Ok(FilterCondition::GreaterThan { column, value }),
                    "LessThan" => Ok(FilterCondition::LessThan { column, value }),
                    "GreaterThanOrEqual" => Ok(FilterCondition::GreaterThanOrEqual { column, value }),
                    "LessThanOrEqual" => Ok(FilterCondition::LessThanOrEqual { column, value }),
                    _ => unreachable!(),
                };
            }
        }

        // Check for IS NULL / IS NOT NULL
        if filter.ends_with(" IS NOT NULL") {
            let field_name = filter.trim_end_matches(" IS NOT NULL").trim();
            let column = self
                .resolve_filter_column(field_name, collection)
                .ok_or_else(|| {
                    CoreError::ValidationError(format!(
                        "Field '{}' not found in collection",
                        field_name
                    ))
                })?;
            return Ok(FilterCondition::IsNotNull { column });
        }

        if filter.ends_with(" IS NULL") {
            let field_name = filter.trim_end_matches(" IS NULL").trim();
            let column = self
                .resolve_filter_column(field_name, collection)
                .ok_or_else(|| {
                    CoreError::ValidationError(format!(
                        "Field '{}' not found in collection",
                        field_name
                    ))
                })?;
            return Ok(FilterCondition::IsNull { column });
        }

        // Default to IS NOT NULL if no operator
        let column = self
            .resolve_filter_column(filter, collection)
            .ok_or_else(|| {
                CoreError::ValidationError("Invalid filter expression".to_string())
            })?;

        Ok(FilterCondition::IsNotNull { column })
    }

    fn apply_filter_condition(
        &self,
        builder: &mut QueryBuilder<'_, Sqlite>,
        condition: &FilterCondition,
    ) {
        match condition {
            FilterCondition::Equals { column, value } => {
                builder.push("\"").push(column).push("\"");
                builder.push(" = ");
                value.bind(builder);
            }
            FilterCondition::NotEquals { column, value } => {
                builder.push("\"").push(column).push("\"");
                builder.push(" != ");
                value.bind(builder);
            }
            FilterCondition::GreaterThan { column, value } => {
                builder.push("\"").push(column).push("\"");
                builder.push(" > ");
                value.bind(builder);
            }
            FilterCondition::LessThan { column, value } => {
                builder.push("\"").push(column).push("\"");
                builder.push(" < ");
                value.bind(builder);
            }
            FilterCondition::GreaterThanOrEqual { column, value } => {
                builder.push("\"").push(column).push("\"");
                builder.push(" >= ");
                value.bind(builder);
            }
            FilterCondition::LessThanOrEqual { column, value } => {
                builder.push("\"").push(column).push("\"");
                builder.push(" <= ");
                value.bind(builder);
            }
            FilterCondition::IsNotNull { column } => {
                builder.push("\"").push(column).push("\"");
                builder.push(" IS NOT NULL");
            }
            FilterCondition::IsNull { column } => {
                builder.push("\"").push(column).push("\"");
                builder.push(" IS NULL");
            }
        }
    }

    fn resolve_filter_column(&self, field_name: &str, collection: &Collection) -> Option<String> {
        let standard_fields = ["id", "created_at", "updated_at"];
        if standard_fields.contains(&field_name) {
            return Some(field_name.to_string());
        }

        collection
            .schema_json
            .get_field(field_name)
            .map(|_| field_name.to_string())
    }

    fn parse_filter_value(
        &self,
        field_name: &str,
        raw_value: &str,
        collection: &Collection,
    ) -> CoreResult<FilterValue> {
        let trimmed_value = raw_value.trim();
        let cleaned_value = trimmed_value
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();

        if let Some(field) = collection.schema_json.get_field(field_name) {
            match &field.field_type {
                FieldType::Number => {
                    let parsed = cleaned_value.parse::<f64>().map_err(|_| {
                        CoreError::ValidationError(format!(
                            "Field '{}' expects a numeric value",
                            field_name
                        ))
                    })?;
                    Ok(FilterValue::Number(parsed))
                }
                FieldType::Boolean => match cleaned_value.to_lowercase().as_str() {
                    "true" => Ok(FilterValue::Boolean(true)),
                    "false" => Ok(FilterValue::Boolean(false)),
                    _ => Err(CoreError::ValidationError(format!(
                        "Field '{}' expects a boolean value",
                        field_name
                    ))),
                },
                FieldType::Date => {
                    chrono::NaiveDate::parse_from_str(&cleaned_value, "%Y-%m-%d").map_err(
                        |_| {
                            CoreError::ValidationError(format!(
                                "Field '{}' must be a valid date (YYYY-MM-DD)",
                                field_name
                            ))
                        },
                    )?;
                    Ok(FilterValue::Text(cleaned_value))
                }
                FieldType::DateTime => {
                    chrono::DateTime::parse_from_rfc3339(&cleaned_value).map_err(|_| {
                        CoreError::ValidationError(format!(
                            "Field '{}' must be a valid datetime (RFC3339)",
                            field_name
                        ))
                    })?;
                    Ok(FilterValue::Text(cleaned_value))
                }
                FieldType::Relation { .. } => {
                    Uuid::parse_str(&cleaned_value).map_err(|_| {
                        CoreError::ValidationError(format!(
                            "Field '{}' must be a valid UUID",
                            field_name
                        ))
                    })?;
                    Ok(FilterValue::Text(cleaned_value))
                }
                _ => Ok(FilterValue::Text(cleaned_value)),
            }
        } else {
            match field_name {
                "id" => {
                    Uuid::parse_str(&cleaned_value).map_err(|_| {
                        CoreError::ValidationError(
                            "Record ID filter must be a valid UUID".to_string(),
                        )
                    })?;
                    Ok(FilterValue::Text(cleaned_value))
                }
                "created_at" | "updated_at" => {
                    chrono::DateTime::parse_from_rfc3339(&cleaned_value).map_err(|_| {
                        CoreError::ValidationError(format!(
                            "Field '{}' must be a valid datetime (RFC3339)",
                            field_name
                        ))
                    })?;
                    Ok(FilterValue::Text(cleaned_value))
                }
                _ => Err(CoreError::ValidationError(format!(
                    "Field '{}' not found in collection",
                    field_name
                ))),
            }
        }
    }

    /// Parse sort expression into SQL ORDER BY clause
    fn parse_sort_expression(&self, sort: &str, collection: &Collection) -> CoreResult<String> {
        let mut order_parts = Vec::new();

        for sort_field in sort.split(',') {
            let sort_field = sort_field.trim();
            let (field_name, direction) = if let Some(name) = sort_field.strip_prefix('-') {
                (name, "DESC")
            } else if let Some(name) = sort_field.strip_prefix('+') {
                (name, "ASC")
            } else {
                (sort_field, "ASC")
            };

            // Validate field exists or is a standard field
            let valid_fields = ["id", "created_at", "updated_at"];
            if !valid_fields.contains(&field_name)
                && collection.schema_json.get_field(field_name).is_none()
            {
                return Err(CoreError::ValidationError(format!(
                    "Field '{}' not found in collection",
                    field_name
                )));
            }

            order_parts.push(format!("{} {}", field_name, direction));
        }

        if order_parts.is_empty() {
            Ok("created_at DESC".to_string())
        } else {
            Ok(order_parts.join(", "))
        }
    }

    fn get_field_value_from_row(
        &self,
        row: &sqlx::sqlite::SqliteRow,
        field: &Field,
    ) -> CoreResult<Value> {
        match &field.field_type {
            FieldType::Text | FieldType::Email | FieldType::Url => {
                if let Ok(s) = row.try_get::<Option<String>, _>(field.name.as_str()) {
                    Ok(s.map(Value::String).unwrap_or(Value::Null))
                } else {
                    Ok(Value::Null)
                }
            }
            FieldType::Number => {
                if let Ok(f) = row.try_get::<Option<f64>, _>(field.name.as_str()) {
                    Ok(f.map(|n| json!(n)).unwrap_or(Value::Null))
                } else {
                    Ok(Value::Null)
                }
            }
            FieldType::Boolean => {
                if let Ok(b) = row.try_get::<Option<bool>, _>(field.name.as_str()) {
                    Ok(b.map(Value::Bool).unwrap_or(Value::Null))
                } else {
                    Ok(Value::Null)
                }
            }
            FieldType::Json => match row.try_get::<Option<String>, _>(field.name.as_str()) {
                Ok(Some(json_str)) => serde_json::from_str(&json_str).map_err(CoreError::from),
                Ok(None) | Err(_) => Ok(Value::Null),
            },
            FieldType::Date | FieldType::DateTime | FieldType::Relation { .. } => {
                if let Ok(s) = row.try_get::<Option<String>, _>(field.name.as_str()) {
                    Ok(s.map(Value::String).unwrap_or(Value::Null))
                } else {
                    Ok(Value::Null)
                }
            }
            FieldType::File { .. } => match row.try_get::<Option<String>, _>(field.name.as_str()) {
                Ok(Some(json_str)) => serde_json::from_str(&json_str).map_err(CoreError::from),
                Ok(None) | Err(_) => Ok(Value::Null),
            },
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        collections::CollectionService, repository::CollectionRepository, AccessRules,
        CollectionSchema, CollectionType, CreateCollectionRequest, Database,
    };
    use serde_json::json;
    use tempfile::TempDir;

    async fn setup_test_services() -> (TempDir, Database, CollectionService, RecordService) {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let database_url = format!("sqlite:{}", db_path.display());

        let db = Database::new(&database_url, 5, 30).await.unwrap();
        db.migrate().await.unwrap();

        let repository = CollectionRepository::new(db.pool().clone());
        let collection_service = CollectionService::new(repository);
        let record_service = RecordService::new(db.pool().clone(), collection_service.clone());

        (temp_dir, db, collection_service, record_service)
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

        let request = CreateCollectionRequest {
            name: "test_posts".to_string(),
            collection_type: Some(CollectionType::Base),
            schema,
            rules: AccessRules::default(),
        };

        collection_service.create_collection(request).await.unwrap()
    }

    #[tokio::test]
    async fn test_create_collection_table() {
        let (_dir, db, collection_service, record_service) = setup_test_services().await;
        let collection = create_test_collection(&collection_service).await;

        // Create table
        record_service
            .create_collection_table(&collection)
            .await
            .unwrap();

        // Verify table exists
        let exists = record_service.table_exists("test_posts").await.unwrap();
        assert!(exists);

        // Verify table structure by trying to query it
        let table_name = collection_service.get_table_name("test_posts");
        let query_sql = format!("SELECT * FROM {} LIMIT 0", table_name);
        let result = sqlx::query(&query_sql).fetch_all(db.pool()).await;
        assert!(result.is_ok());

        db.close().await;
    }

    #[tokio::test]
    async fn test_create_and_get_record() {
        let (_dir, db, collection_service, record_service) = setup_test_services().await;
        let collection = create_test_collection(&collection_service).await;

        // Create table
        record_service
            .create_collection_table(&collection)
            .await
            .unwrap();

        // Create record
        let record_data = json!({
            "title": "Test Post",
            "content": "This is a test post content",
            "score": 85.5,
            "published": true
        });

        let record = record_service
            .create_record("test_posts", record_data.clone())
            .await
            .unwrap();

        assert_eq!(record.collection_id, collection.id);
        assert_eq!(record.data["title"], "Test Post");
        assert_eq!(record.data["content"], "This is a test post content");
        assert_eq!(record.data["score"], 85.5);
        assert_eq!(record.data["published"], true);

        // Get record by ID
        let retrieved = record_service
            .get_record("test_posts", record.id)
            .await
            .unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.id, record.id);
        assert_eq!(retrieved.data["title"], "Test Post");

        db.close().await;
    }

    #[tokio::test]
    async fn test_record_validation() {
        let (_dir, db, collection_service, record_service) = setup_test_services().await;
        let collection = create_test_collection(&collection_service).await;

        record_service
            .create_collection_table(&collection)
            .await
            .unwrap();

        // Test missing required field
        let invalid_data = json!({
            "content": "Missing title",
            "score": 85.5
        });

        let result = record_service
            .create_record("test_posts", invalid_data)
            .await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Required field 'title' is missing"));

        // Test invalid field type
        let invalid_data = json!({
            "title": "Valid Title",
            "content": "Valid content",
            "score": "not_a_number" // Should be number
        });

        let result = record_service
            .create_record("test_posts", invalid_data)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be a number"));

        db.close().await;
    }

    #[tokio::test]
    async fn test_list_records() {
        let (_dir, db, collection_service, record_service) = setup_test_services().await;
        let collection = create_test_collection(&collection_service).await;

        record_service
            .create_collection_table(&collection)
            .await
            .unwrap();

        // Create multiple records
        for i in 0..5 {
            let record_data = json!({
                "title": format!("Post {}", i),
                "content": format!("Content for post {}", i),
                "score": i as f64 * 10.0,
                "published": i % 2 == 0
            });

            record_service
                .create_record("test_posts", record_data)
                .await
                .unwrap();
        }

        // List all records
        let records = record_service
            .list_records("test_posts", 10, 0)
            .await
            .unwrap();
        assert_eq!(records.len(), 5);

        // Test pagination
        let first_page = record_service
            .list_records("test_posts", 2, 0)
            .await
            .unwrap();
        assert_eq!(first_page.len(), 2);

        let second_page = record_service
            .list_records("test_posts", 2, 2)
            .await
            .unwrap();
        assert_eq!(second_page.len(), 2);

        let third_page = record_service
            .list_records("test_posts", 2, 4)
            .await
            .unwrap();
        assert_eq!(third_page.len(), 1);

        // Test count
        let count = record_service.count_records("test_posts").await.unwrap();
        assert_eq!(count, 5);

        db.close().await;
    }

    #[tokio::test]
    async fn test_update_record() {
        let (_dir, db, collection_service, record_service) = setup_test_services().await;
        let collection = create_test_collection(&collection_service).await;

        record_service
            .create_collection_table(&collection)
            .await
            .unwrap();

        // Create record
        let record_data = json!({
            "title": "Original Title",
            "content": "Original content",
            "score": 50.0,
            "published": false
        });

        let record = record_service
            .create_record("test_posts", record_data)
            .await
            .unwrap();

        // Update record
        let update_data = json!({
            "title": "Updated Title",
            "content": "Updated content",
            "score": 95.0,
            "published": true
        });

        let updated = record_service
            .update_record("test_posts", record.id, update_data)
            .await
            .unwrap();

        assert_eq!(updated.id, record.id);
        assert_eq!(updated.data["title"], "Updated Title");
        assert_eq!(updated.data["content"], "Updated content");
        assert_eq!(updated.data["score"], 95.0);
        assert_eq!(updated.data["published"], true);
        assert!(updated.updated_at > record.updated_at);

        db.close().await;
    }

    #[tokio::test]
    async fn test_delete_record() {
        let (_dir, db, collection_service, record_service) = setup_test_services().await;
        let collection = create_test_collection(&collection_service).await;

        record_service
            .create_collection_table(&collection)
            .await
            .unwrap();

        // Create record
        let record_data = json!({
            "title": "To Be Deleted",
            "content": "This record will be deleted",
            "score": 0.0,
            "published": false
        });

        let record = record_service
            .create_record("test_posts", record_data)
            .await
            .unwrap();

        // Delete record
        let deleted = record_service
            .delete_record("test_posts", record.id)
            .await
            .unwrap();
        assert!(deleted);

        // Verify deletion
        let not_found = record_service
            .get_record("test_posts", record.id)
            .await
            .unwrap();
        assert!(not_found.is_none());

        // Try to delete non-existent record
        let not_deleted = record_service
            .delete_record("test_posts", Uuid::new_v4())
            .await
            .unwrap();
        assert!(!not_deleted);

        db.close().await;
    }

    #[tokio::test]
    async fn test_drop_collection_table() {
        let (_dir, db, collection_service, record_service) = setup_test_services().await;
        let collection = create_test_collection(&collection_service).await;

        // Create table
        record_service
            .create_collection_table(&collection)
            .await
            .unwrap();
        let exists = record_service.table_exists("test_posts").await.unwrap();
        assert!(exists);

        // Drop table
        record_service
            .drop_collection_table("test_posts")
            .await
            .unwrap();
        let exists = record_service.table_exists("test_posts").await.unwrap();
        assert!(!exists);

        db.close().await;
    }

    #[tokio::test]
    async fn test_field_type_conversions() {
        let (_dir, db, collection_service, record_service) = setup_test_services().await;

        // Create collection with various field types
        let mut schema = CollectionSchema::new();
        schema.add_field(Field::new(
            Uuid::new_v4(),
            "text_field".to_string(),
            FieldType::Text,
        ));
        schema.add_field(Field::new(
            Uuid::new_v4(),
            "number_field".to_string(),
            FieldType::Number,
        ));
        schema.add_field(Field::new(
            Uuid::new_v4(),
            "bool_field".to_string(),
            FieldType::Boolean,
        ));
        schema.add_field(Field::new(
            Uuid::new_v4(),
            "email_field".to_string(),
            FieldType::Email,
        ));
        schema.add_field(Field::new(
            Uuid::new_v4(),
            "url_field".to_string(),
            FieldType::Url,
        ));
        schema.add_field(Field::new(
            Uuid::new_v4(),
            "json_field".to_string(),
            FieldType::Json,
        ));
        schema.add_field(Field::new(
            Uuid::new_v4(),
            "date_field".to_string(),
            FieldType::Date,
        ));
        schema.add_field(Field::new(
            Uuid::new_v4(),
            "datetime_field".to_string(),
            FieldType::DateTime,
        ));

        let request = CreateCollectionRequest {
            name: "type_test".to_string(),
            collection_type: Some(CollectionType::Base),
            schema,
            rules: AccessRules::default(),
        };

        let collection = collection_service.create_collection(request).await.unwrap();
        record_service
            .create_collection_table(&collection)
            .await
            .unwrap();

        // Create record with various field types
        let record_data = json!({
            "text_field": "Hello World",
            "number_field": 42.5,
            "bool_field": true,
            "email_field": "test@example.com",
            "url_field": "https://example.com",
            "json_field": {"key": "value", "number": 123},
            "date_field": "2023-12-25",
            "datetime_field": "2023-12-25T10:30:00Z"
        });

        let record = record_service
            .create_record("type_test", record_data)
            .await
            .unwrap();

        // Verify field values
        assert_eq!(record.data["text_field"], "Hello World");
        assert_eq!(record.data["number_field"], 42.5);
        assert_eq!(record.data["bool_field"], true);
        assert_eq!(record.data["email_field"], "test@example.com");
        assert_eq!(record.data["url_field"], "https://example.com");

        // Retrieve and verify
        let retrieved = record_service
            .get_record("type_test", record.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.data["text_field"], "Hello World");
        assert_eq!(retrieved.data["number_field"], 42.5);
        assert_eq!(retrieved.data["bool_field"], true);

        db.close().await;
    }

    #[tokio::test]
    async fn test_nonexistent_collection() {
        let (_dir, db, _collection_service, record_service) = setup_test_services().await;

        let record_data = json!({
            "title": "Test"
        });

        let result = record_service
            .create_record("nonexistent", record_data)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));

        db.close().await;
    }

    #[tokio::test]
    async fn test_filter_expression_rejects_injection() {
        let (_dir, db, collection_service, record_service) = setup_test_services().await;
        let collection = create_test_collection(&collection_service).await;

        record_service
            .create_collection_table(&collection)
            .await
            .unwrap();

        let results = record_service
            .list_records_with_query(
                "test_posts",
                10,
                0,
                Some("title = 'Hello'; DROP TABLE users"),
                None,
                None,
            )
            .await
            .unwrap();

        assert!(results.is_empty());

        let table_still_exists = record_service.table_exists("test_posts").await.unwrap();
        assert!(table_still_exists);

        db.close().await;
    }

    #[tokio::test]
    async fn test_filter_expression_matches_exact_value() {
        let (_dir, db, collection_service, record_service) = setup_test_services().await;
        let collection = create_test_collection(&collection_service).await;

        record_service
            .create_collection_table(&collection)
            .await
            .unwrap();

        let record_a = json!({
            "title": "Hello",
            "content": "First",
            "score": 10.0,
            "published": true
        });
        let record_b = json!({
            "title": "Goodbye",
            "content": "Second",
            "score": 20.0,
            "published": false
        });

        record_service
            .create_record("test_posts", record_a)
            .await
            .unwrap();
        record_service
            .create_record("test_posts", record_b)
            .await
            .unwrap();

        let results = record_service
            .list_records_with_query("test_posts", 10, 0, Some("title = 'Hello'"), None, None)
            .await
            .unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0]
                .data
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap(),
            "Hello"
        );

        db.close().await;
    }
}
