use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use std::collections::HashMap;
use uuid::Uuid;

/// User model with role-based permissions
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: UserRole,
    pub verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// User roles for authorization
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, sqlx::Type)]
#[sqlx(type_name = "TEXT")]
#[sqlx(rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    Admin,
    User,
    Service,
}

impl std::fmt::Display for UserRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserRole::Admin => write!(f, "admin"),
            UserRole::User => write!(f, "user"),
            UserRole::Service => write!(f, "service"),
        }
    }
}

/// Collection model with dynamic schema and access rules
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, FromRow)]
pub struct Collection {
    pub id: Uuid,
    pub name: String,
    #[serde(rename = "type")]
    pub collection_type: CollectionType,
    #[sqlx(json)]
    pub schema_json: CollectionSchema,
    pub list_rule: Option<String>,
    pub view_rule: Option<String>,
    pub create_rule: Option<String>,
    pub update_rule: Option<String>,
    pub delete_rule: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Collection type enumeration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema, sqlx::Type)]
#[sqlx(type_name = "TEXT")]
#[sqlx(rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum CollectionType {
    Base,
    Auth,
    View,
}

impl std::fmt::Display for CollectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CollectionType::Base => write!(f, "base"),
            CollectionType::Auth => write!(f, "auth"),
            CollectionType::View => write!(f, "view"),
        }
    }
}

/// Collection schema containing field definitions
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CollectionSchema {
    pub fields: Vec<Field>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_schema: Option<serde_json::Value>,
}

impl CollectionSchema {
    pub fn new() -> Self {
        Self {
            fields: Vec::new(),
            json_schema: None,
        }
    }

    pub fn add_field(&mut self, field: Field) {
        self.fields.push(field);
    }

    pub fn get_field(&self, name: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.name == name)
    }

    pub fn remove_field(&mut self, name: &str) -> bool {
        if let Some(pos) = self.fields.iter().position(|f| f.name == name) {
            self.fields.remove(pos);
            true
        } else {
            false
        }
    }
}

impl Default for CollectionSchema {
    fn default() -> Self {
        Self::new()
    }
}

/// Field definition for collections
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, FromRow)]
pub struct Field {
    pub id: Uuid,
    pub collection_id: Uuid,
    pub name: String,
    #[serde(rename = "type")]
    #[sqlx(rename = "type")]
    pub field_type: FieldType,
    pub required: bool,
    pub unique_constraint: bool,
    #[sqlx(json)]
    pub options_json: Option<FieldOptions>,
    pub created_at: DateTime<Utc>,
}

/// Field type enumeration with associated data
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub enum FieldType {
    Text,
    Number,
    Boolean,
    Email,
    Url,
    Json,
    Date,
    DateTime,
    Relation {
        target_collection: String,
        cascade_delete: bool,
    },
    File {
        max_size: Option<u64>,
        allowed_types: Option<Vec<String>>,
    },
}

impl std::fmt::Display for FieldType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FieldType::Text => write!(f, "text"),
            FieldType::Number => write!(f, "number"),
            FieldType::Boolean => write!(f, "boolean"),
            FieldType::Email => write!(f, "email"),
            FieldType::Url => write!(f, "url"),
            FieldType::Json => write!(f, "json"),
            FieldType::Date => write!(f, "date"),
            FieldType::DateTime => write!(f, "datetime"),
            FieldType::Relation { .. } => write!(f, "relation"),
            FieldType::File { .. } => write!(f, "file"),
        }
    }
}

/// Field options for additional configuration
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct FieldOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_value: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_value: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enum_values: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_value: Option<serde_json::Value>,
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

/// Audit log entry for administrative actions
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, FromRow)]
pub struct AuditLog {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    #[sqlx(json)]
    pub details_json: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Access rules for collections
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
pub struct AccessRules {
    pub list_rule: Option<String>,
    pub view_rule: Option<String>,
    pub create_rule: Option<String>,
    pub update_rule: Option<String>,
    pub delete_rule: Option<String>,
}

/// Record data structure for dynamic collections
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Record {
    pub id: Uuid,
    pub collection_id: Uuid,
    #[serde(flatten)]
    pub data: HashMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request for creating a new user
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub role: Option<UserRole>,
    #[serde(default)]
    pub verified: bool,
}

/// Request for creating a new collection
#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct CreateCollectionRequest {
    pub name: String,
    #[serde(rename = "type", default)]
    pub collection_type: Option<CollectionType>,
    #[serde(default)]
    pub schema: CollectionSchema,
    #[serde(default)]
    pub rules: AccessRules,
}

/// Request for updating a collection
#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateCollectionRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<CollectionSchema>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<AccessRules>,
}

/// Request for creating a new field
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateFieldRequest {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: FieldType,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub unique_constraint: bool,
    #[serde(default)]
    pub options: Option<FieldOptions>,
}

impl User {
    pub fn new(email: String, password_hash: String, role: UserRole) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            email,
            password_hash,
            role,
            verified: false,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn is_admin(&self) -> bool {
        matches!(self.role, UserRole::Admin)
    }

    pub fn is_service(&self) -> bool {
        matches!(self.role, UserRole::Service)
    }
}

impl Collection {
    pub fn new(name: String, collection_type: CollectionType) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            collection_type,
            schema_json: CollectionSchema::new(),
            list_rule: None,
            view_rule: None,
            create_rule: None,
            update_rule: None,
            delete_rule: None,
            created_at: now,
            updated_at: now,
        }
    }

    pub fn with_rules(mut self, rules: AccessRules) -> Self {
        self.list_rule = rules.list_rule;
        self.view_rule = rules.view_rule;
        self.create_rule = rules.create_rule;
        self.update_rule = rules.update_rule;
        self.delete_rule = rules.delete_rule;
        self
    }

    pub fn with_schema(mut self, schema: CollectionSchema) -> Self {
        self.schema_json = schema;
        self
    }
}

impl Field {
    pub fn new(collection_id: Uuid, name: String, field_type: FieldType) -> Self {
        Self {
            id: Uuid::new_v4(),
            collection_id,
            name,
            field_type,
            required: false,
            unique_constraint: false,
            options_json: None,
            created_at: Utc::now(),
        }
    }

    pub fn with_options(mut self, options: FieldOptions) -> Self {
        self.options_json = Some(options);
        self
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    pub fn unique(mut self) -> Self {
        self.unique_constraint = true;
        self
    }
}

impl AuditLog {
    pub fn new(
        user_id: Option<Uuid>,
        action: String,
        resource_type: String,
        resource_id: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id,
            action,
            resource_type,
            resource_id,
            details_json: None,
            ip_address: None,
            user_agent: None,
            created_at: Utc::now(),
        }
    }

    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details_json = Some(details);
        self
    }

    pub fn with_request_info(mut self, ip_address: Option<String>, user_agent: Option<String>) -> Self {
        self.ip_address = ip_address;
        self.user_agent = user_agent;
        self
    }
}
#[cfg
(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_user_creation() {
        let user = User::new(
            "test@example.com".to_string(),
            "hashed_password".to_string(),
            UserRole::User,
        );

        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.password_hash, "hashed_password");
        assert_eq!(user.role, UserRole::User);
        assert!(!user.verified);
        assert!(!user.is_admin());
        assert!(!user.is_service());
    }

    #[test]
    fn test_user_roles() {
        let admin = User::new("admin@example.com".to_string(), "hash".to_string(), UserRole::Admin);
        let service = User::new("service@example.com".to_string(), "hash".to_string(), UserRole::Service);
        let user = User::new("user@example.com".to_string(), "hash".to_string(), UserRole::User);

        assert!(admin.is_admin());
        assert!(!admin.is_service());

        assert!(!service.is_admin());
        assert!(service.is_service());

        assert!(!user.is_admin());
        assert!(!user.is_service());
    }

    #[test]
    fn test_user_role_serialization() {
        assert_eq!(UserRole::Admin.to_string(), "admin");
        assert_eq!(UserRole::User.to_string(), "user");
        assert_eq!(UserRole::Service.to_string(), "service");
    }

    #[test]
    fn test_collection_creation() {
        let collection = Collection::new("posts".to_string(), CollectionType::Base);

        assert_eq!(collection.name, "posts");
        assert_eq!(collection.collection_type, CollectionType::Base);
        assert!(collection.schema_json.fields.is_empty());
        assert!(collection.list_rule.is_none());
    }

    #[test]
    fn test_collection_with_rules() {
        let rules = AccessRules {
            list_rule: Some("@request.auth.id != ''".to_string()),
            view_rule: Some("@request.auth.id != ''".to_string()),
            create_rule: Some("@request.auth.role = 'admin'".to_string()),
            update_rule: Some("@request.auth.id = record.owner".to_string()),
            delete_rule: Some("@request.auth.role = 'admin'".to_string()),
        };

        let collection = Collection::new("posts".to_string(), CollectionType::Base)
            .with_rules(rules);

        assert_eq!(collection.list_rule, Some("@request.auth.id != ''".to_string()));
        assert_eq!(collection.create_rule, Some("@request.auth.role = 'admin'".to_string()));
    }

    #[test]
    fn test_collection_schema() {
        let mut schema = CollectionSchema::new();
        
        let field = Field::new(
            Uuid::new_v4(),
            "title".to_string(),
            FieldType::Text,
        ).required();

        schema.add_field(field);

        assert_eq!(schema.fields.len(), 1);
        assert!(schema.get_field("title").is_some());
        assert!(schema.get_field("nonexistent").is_none());

        let removed = schema.remove_field("title");
        assert!(removed);
        assert_eq!(schema.fields.len(), 0);

        let not_removed = schema.remove_field("nonexistent");
        assert!(!not_removed);
    }

    #[test]
    fn test_field_creation() {
        let collection_id = Uuid::new_v4();
        let field = Field::new(collection_id, "email".to_string(), FieldType::Email)
            .required()
            .unique();

        assert_eq!(field.collection_id, collection_id);
        assert_eq!(field.name, "email");
        assert!(matches!(field.field_type, FieldType::Email));
        assert!(field.required);
        assert!(field.unique_constraint);
    }

    #[test]
    fn test_field_types() {
        let text_field = FieldType::Text;
        let relation_field = FieldType::Relation {
            target_collection: "users".to_string(),
            cascade_delete: true,
        };
        let file_field = FieldType::File {
            max_size: Some(1024 * 1024),
            allowed_types: Some(vec!["image/jpeg".to_string(), "image/png".to_string()]),
        };

        assert_eq!(text_field.to_string(), "text");
        assert_eq!(relation_field.to_string(), "relation");
        assert_eq!(file_field.to_string(), "file");
    }

    #[test]
    fn test_field_options() {
        let options = FieldOptions {
            min_length: Some(5),
            max_length: Some(100),
            pattern: Some(r"^[a-zA-Z0-9]+$".to_string()),
            enum_values: Some(vec!["draft".to_string(), "published".to_string()]),
            default_value: Some(json!("draft")),
            ..Default::default()
        };

        let field = Field::new(Uuid::new_v4(), "status".to_string(), FieldType::Text)
            .with_options(options);

        assert!(field.options_json.is_some());
        let opts = field.options_json.unwrap();
        assert_eq!(opts.min_length, Some(5));
        assert_eq!(opts.max_length, Some(100));
        assert!(opts.enum_values.is_some());
    }

    #[test]
    fn test_audit_log_creation() {
        let audit_log = AuditLog::new(
            Some(Uuid::new_v4()),
            "CREATE".to_string(),
            "collection".to_string(),
            Some("posts".to_string()),
        )
        .with_details(json!({"name": "posts", "type": "base"}))
        .with_request_info(
            Some("192.168.1.1".to_string()),
            Some("Mozilla/5.0".to_string()),
        );

        assert_eq!(audit_log.action, "CREATE");
        assert_eq!(audit_log.resource_type, "collection");
        assert_eq!(audit_log.resource_id, Some("posts".to_string()));
        assert!(audit_log.details_json.is_some());
        assert_eq!(audit_log.ip_address, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_collection_type_serialization() {
        assert_eq!(CollectionType::Base.to_string(), "base");
        assert_eq!(CollectionType::Auth.to_string(), "auth");
        assert_eq!(CollectionType::View.to_string(), "view");
    }

    #[test]
    fn test_create_user_request() {
        let request = CreateUserRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
            role: Some(UserRole::Admin),
            verified: true,
        };

        assert_eq!(request.email, "test@example.com");
        assert_eq!(request.password, "password123");
        assert_eq!(request.role, Some(UserRole::Admin));
        assert!(request.verified);
    }

    #[test]
    fn test_create_collection_request() {
        let mut schema = CollectionSchema::new();
        schema.add_field(Field::new(
            Uuid::new_v4(),
            "title".to_string(),
            FieldType::Text,
        ));

        let request = CreateCollectionRequest {
            name: "posts".to_string(),
            collection_type: Some(CollectionType::Base),
            schema,
            rules: AccessRules::default(),
        };

        assert_eq!(request.name, "posts");
        assert_eq!(request.collection_type, Some(CollectionType::Base));
        assert_eq!(request.schema.fields.len(), 1);
    }

    #[test]
    fn test_field_serialization() {
        let field = Field::new(
            Uuid::new_v4(),
            "content".to_string(),
            FieldType::Text,
        );

        let serialized = serde_json::to_string(&field).unwrap();
        let deserialized: Field = serde_json::from_str(&serialized).unwrap();

        assert_eq!(field.name, deserialized.name);
        assert_eq!(field.required, deserialized.required);
    }

    #[test]
    fn test_user_serialization_excludes_password() {
        let user = User::new(
            "test@example.com".to_string(),
            "secret_hash".to_string(),
            UserRole::User,
        );

        let serialized = serde_json::to_string(&user).unwrap();
        assert!(!serialized.contains("secret_hash"));
        assert!(serialized.contains("test@example.com"));
    }
}
