use rustbase_core::{
    models::{Collection, CollectionSchema, CollectionType, Field, FieldOptions, FieldType},
    AccessRules,
};
use rustbase_server::openapi::OpenApiGenerator;
use serde_json::{json, Value};
use uuid::Uuid;

/// Tests for OpenAPI specification generation
#[test]
fn test_openapi_spec_structure() {
    let generator = OpenApiGenerator::new("http://localhost:8090".to_string());
    let collections = vec![create_test_posts_collection()];

    let spec = generator.generate_spec(&collections);

    // Verify OpenAPI version
    assert_eq!(spec["openapi"], "3.1.0");

    // Verify info section
    assert_eq!(spec["info"]["title"], "RustBase API");
    assert_eq!(spec["info"]["version"], "1.0.0");
    assert!(spec["info"]["description"].is_string());

    // Verify server configuration
    assert!(spec["servers"].is_array());
    let servers = spec["servers"].as_array().unwrap();
    assert!(!servers.is_empty());
    assert_eq!(servers[0]["url"], "http://localhost:8090");

    // Verify components section
    assert!(spec["components"].is_object());
    assert!(spec["components"]["schemas"].is_object());
    assert!(spec["components"]["securitySchemes"].is_object());

    // Verify security configuration
    assert!(spec["security"].is_array());
    let security = spec["security"].as_array().unwrap();
    assert!(!security.is_empty());
    assert!(security[0]["bearerAuth"].is_array());
}

#[test]
fn test_authentication_endpoints() {
    let generator = OpenApiGenerator::new("http://localhost:8090".to_string());
    let collections = vec![];

    let spec = generator.generate_spec(&collections);
    let paths = &spec["paths"];

    // Verify login endpoint
    assert!(paths["/api/auth/login"].is_object());
    let login = &paths["/api/auth/login"]["post"];
    assert_eq!(login["tags"][0], "Authentication");
    assert_eq!(login["summary"], "User login");
    assert!(login["requestBody"].is_object());
    assert!(login["responses"]["200"].is_object());
    assert!(login["responses"]["401"].is_object());

    // Verify register endpoint
    assert!(paths["/api/auth/register"].is_object());
    let register = &paths["/api/auth/register"]["post"];
    assert_eq!(register["tags"][0], "Authentication");
    assert_eq!(register["summary"], "User registration");
    assert!(register["responses"]["201"].is_object());

    // Verify refresh endpoint
    assert!(paths["/api/auth/refresh"].is_object());
    let refresh = &paths["/api/auth/refresh"]["post"];
    assert_eq!(refresh["tags"][0], "Authentication");
    assert_eq!(refresh["summary"], "Refresh access token");
}

#[test]
fn test_health_check_endpoints() {
    let generator = OpenApiGenerator::new("http://localhost:8090".to_string());
    let collections = vec![];

    let spec = generator.generate_spec(&collections);
    let paths = &spec["paths"];

    // Verify health check endpoint
    assert!(paths["/healthz"].is_object());
    let healthz = &paths["/healthz"]["get"];
    assert_eq!(healthz["tags"][0], "Health");
    assert_eq!(healthz["summary"], "Health check");
    assert!(healthz["security"].is_array());
    assert!(healthz["security"].as_array().unwrap().is_empty()); // No auth required

    // Verify readiness check endpoint
    assert!(paths["/readyz"].is_object());
    let readyz = &paths["/readyz"]["get"];
    assert_eq!(readyz["tags"][0], "Health");
    assert_eq!(readyz["summary"], "Readiness check");
}

#[test]
fn test_collection_crud_endpoints() {
    let generator = OpenApiGenerator::new("http://localhost:8090".to_string());
    let collections = vec![create_test_posts_collection()];

    let spec = generator.generate_spec(&collections);
    let paths = &spec["paths"];

    let collection_path = "/api/collections/posts/records";
    let record_path = "/api/collections/posts/records/{id}";

    // Verify collection list/create endpoint
    assert!(paths[collection_path].is_object());
    let collection_endpoint = &paths[collection_path];

    // GET (list records)
    let get_method = &collection_endpoint["get"];
    assert_eq!(get_method["tags"][0], "posts Collection");
    assert_eq!(get_method["summary"], "List posts records");
    assert!(get_method["parameters"].is_array());

    // Verify query parameters
    let params = get_method["parameters"].as_array().unwrap();
    let param_names: Vec<&str> = params
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert!(param_names.contains(&"page"));
    assert!(param_names.contains(&"perPage"));
    assert!(param_names.contains(&"sort"));
    assert!(param_names.contains(&"filter"));
    assert!(param_names.contains(&"fields"));

    // POST (create record)
    let post_method = &collection_endpoint["post"];
    assert_eq!(post_method["tags"][0], "posts Collection");
    assert_eq!(post_method["summary"], "Create posts record");
    assert!(post_method["requestBody"].is_object());
    assert!(post_method["responses"]["201"].is_object());

    // Verify individual record endpoint
    assert!(paths[record_path].is_object());
    let record_endpoint = &paths[record_path];

    // GET (get record)
    assert!(record_endpoint["get"].is_object());
    // PATCH (update record)
    assert!(record_endpoint["patch"].is_object());
    // DELETE (delete record)
    assert!(record_endpoint["delete"].is_object());
}

#[test]
fn test_file_upload_endpoints() {
    let generator = OpenApiGenerator::new("http://localhost:8090".to_string());
    let collections = vec![create_test_posts_collection()];

    let spec = generator.generate_spec(&collections);
    let paths = &spec["paths"];

    let file_path = "/api/files/posts/{recordId}/{fieldName}";

    // Verify file endpoint exists (posts has featured_image field)
    assert!(paths[file_path].is_object());
    let file_endpoint = &paths[file_path];

    // POST (upload file)
    let post_method = &file_endpoint["post"];
    assert_eq!(post_method["tags"][0], "posts Collection");
    assert_eq!(post_method["summary"], "Upload file to posts record");
    assert!(post_method["requestBody"]["content"]["multipart/form-data"].is_object());

    // GET (download file)
    let get_method = &file_endpoint["get"];
    assert_eq!(get_method["tags"][0], "posts Collection");
    assert_eq!(get_method["summary"], "Download file from posts record");
    assert!(get_method["responses"]["200"]["content"]["application/octet-stream"].is_object());
}

#[test]
fn test_schema_generation() {
    let generator = OpenApiGenerator::new("http://localhost:8090".to_string());
    let collections = vec![create_test_posts_collection()];

    let spec = generator.generate_spec(&collections);
    let schemas = &spec["components"]["schemas"];

    // Verify common schemas
    assert!(schemas["ErrorResponse"].is_object());
    assert!(schemas["AuthToken"].is_object());
    assert!(schemas["LoginRequest"].is_object());
    assert!(schemas["RegisterRequest"].is_object());
    assert!(schemas["User"].is_object());

    // Verify collection-specific schemas
    assert!(schemas["postsRecord"].is_object());
    assert!(schemas["CreatepostsRequest"].is_object());
    assert!(schemas["UpdatepostsRequest"].is_object());

    // Verify record schema structure
    let posts_record = &schemas["postsRecord"];
    assert_eq!(posts_record["type"], "object");
    assert!(posts_record["properties"].is_object());
    assert!(posts_record["required"].is_array());

    let properties = posts_record["properties"].as_object().unwrap();
    assert!(properties.contains_key("id"));
    assert!(properties.contains_key("title"));
    assert!(properties.contains_key("content"));
    assert!(properties.contains_key("owner_id"));
    assert!(properties.contains_key("published"));
    assert!(properties.contains_key("created_at"));
    assert!(properties.contains_key("updated_at"));

    // Verify required fields
    let required = posts_record["required"].as_array().unwrap();
    assert!(required.contains(&json!("id")));
    assert!(required.contains(&json!("title")));
    assert!(required.contains(&json!("content")));
    assert!(required.contains(&json!("owner_id")));
}

#[test]
fn test_field_type_mapping() {
    let generator = OpenApiGenerator::new("http://localhost:8090".to_string());

    // Test text field
    let text_field = Field::new(Uuid::new_v4(), "title".to_string(), FieldType::Text)
        .with_options(FieldOptions {
            min_length: Some(1),
            max_length: Some(255),
            ..Default::default()
        });

    let schema = generator.field_to_json_schema(&text_field);
    assert_eq!(schema["type"], "string");
    assert_eq!(schema["minLength"], 1);
    assert_eq!(schema["maxLength"], 255);

    // Test number field
    let number_field = Field::new(Uuid::new_v4(), "score".to_string(), FieldType::Number)
        .with_options(FieldOptions {
            min_value: Some(0.0),
            max_value: Some(100.0),
            ..Default::default()
        });

    let schema = generator.field_to_json_schema(&number_field);
    assert_eq!(schema["type"], "number");
    assert_eq!(schema["minimum"], 0.0);
    assert_eq!(schema["maximum"], 100.0);

    // Test boolean field
    let bool_field = Field::new(Uuid::new_v4(), "active".to_string(), FieldType::Boolean)
        .with_options(FieldOptions {
            default_value: Some(json!(true)),
            ..Default::default()
        });

    let schema = generator.field_to_json_schema(&bool_field);
    assert_eq!(schema["type"], "boolean");
    assert_eq!(schema["default"], true);

    // Test email field
    let email_field = Field::new(Uuid::new_v4(), "email".to_string(), FieldType::Email);
    let schema = generator.field_to_json_schema(&email_field);
    assert_eq!(schema["type"], "string");
    assert_eq!(schema["format"], "email");

    // Test relation field
    let relation_field = Field::new(
        Uuid::new_v4(),
        "author_id".to_string(),
        FieldType::Relation {
            target_collection: "users".to_string(),
            cascade_delete: false,
        },
    );

    let schema = generator.field_to_json_schema(&relation_field);
    assert_eq!(schema["type"], "string");
    assert_eq!(schema["format"], "uuid");
    assert!(schema["description"]
        .as_str()
        .unwrap()
        .contains("users"));

    // Test file field
    let file_field = Field::new(
        Uuid::new_v4(),
        "avatar".to_string(),
        FieldType::File {
            max_size: Some(1024 * 1024),
            allowed_types: Some(vec!["image/jpeg".to_string(), "image/png".to_string()]),
        },
    );

    let schema = generator.field_to_json_schema(&file_field);
    assert_eq!(schema["type"], "string");
    assert!(schema["description"]
        .as_str()
        .unwrap()
        .contains("File"));

    // Test date/datetime fields
    let date_field = Field::new(Uuid::new_v4(), "birth_date".to_string(), FieldType::Date);
    let schema = generator.field_to_json_schema(&date_field);
    assert_eq!(schema["type"], "string");
    assert_eq!(schema["format"], "date");

    let datetime_field = Field::new(
        Uuid::new_v4(),
        "published_at".to_string(),
        FieldType::DateTime,
    );
    let schema = generator.field_to_json_schema(&datetime_field);
    assert_eq!(schema["type"], "string");
    assert_eq!(schema["format"], "date-time");
}

#[test]
fn test_enum_field_schema() {
    let generator = OpenApiGenerator::new("http://localhost:8090".to_string());

    let enum_field = Field::new(Uuid::new_v4(), "status".to_string(), FieldType::Text)
        .with_options(FieldOptions {
            enum_values: Some(vec![
                "draft".to_string(),
                "published".to_string(),
                "archived".to_string(),
            ]),
            default_value: Some(json!("draft")),
            ..Default::default()
        });

    let schema = generator.field_to_json_schema(&enum_field);
    assert_eq!(schema["type"], "string");
    assert_eq!(schema["default"], "draft");

    let enum_values = schema["enum"].as_array().unwrap();
    assert_eq!(enum_values.len(), 3);
    assert!(enum_values.contains(&json!("draft")));
    assert!(enum_values.contains(&json!("published")));
    assert!(enum_values.contains(&json!("archived")));
}

#[test]
fn test_pattern_field_schema() {
    let generator = OpenApiGenerator::new("http://localhost:8090".to_string());

    let pattern_field = Field::new(Uuid::new_v4(), "slug".to_string(), FieldType::Text)
        .with_options(FieldOptions {
            pattern: Some(r"^[a-z0-9-]+$".to_string()),
            ..Default::default()
        });

    let schema = generator.field_to_json_schema(&pattern_field);
    assert_eq!(schema["type"], "string");
    assert_eq!(schema["pattern"], r"^[a-z0-9-]+$");
}

#[test]
fn test_tags_generation() {
    let generator = OpenApiGenerator::new("http://localhost:8090".to_string());
    let collections = vec![
        create_test_posts_collection(),
        create_test_users_collection(),
    ];

    let tags = generator.generate_tags(&collections);
    let tags_array = tags.as_array().unwrap();

    // Should have Authentication, Health, and collection tags
    assert!(tags_array.len() >= 4);

    let tag_names: Vec<&str> = tags_array
        .iter()
        .map(|tag| tag["name"].as_str().unwrap())
        .collect();

    assert!(tag_names.contains(&"Authentication"));
    assert!(tag_names.contains(&"Health"));
    assert!(tag_names.contains(&"posts Collection"));
    assert!(tag_names.contains(&"users Collection"));

    // Verify tag structure
    for tag in tags_array {
        assert!(tag["name"].is_string());
        assert!(tag["description"].is_string());
    }
}

#[test]
fn test_security_scheme() {
    let generator = OpenApiGenerator::new("http://localhost:8090".to_string());
    let collections = vec![];

    let spec = generator.generate_spec(&collections);
    let security_schemes = &spec["components"]["securitySchemes"];

    assert!(security_schemes["bearerAuth"].is_object());
    let bearer_auth = &security_schemes["bearerAuth"];
    assert_eq!(bearer_auth["type"], "http");
    assert_eq!(bearer_auth["scheme"], "bearer");
    assert_eq!(bearer_auth["bearerFormat"], "JWT");
}

#[test]
fn test_request_response_schemas() {
    let generator = OpenApiGenerator::new("http://localhost:8090".to_string());
    let collections = vec![create_test_posts_collection()];

    let spec = generator.generate_spec(&collections);
    let schemas = &spec["components"]["schemas"];

    // Test create request schema (should not have system fields)
    let create_request = &schemas["CreatepostsRequest"];
    let create_properties = create_request["properties"].as_object().unwrap();
    assert!(!create_properties.contains_key("id"));
    assert!(!create_properties.contains_key("created_at"));
    assert!(!create_properties.contains_key("updated_at"));
    assert!(create_properties.contains_key("title"));
    assert!(create_properties.contains_key("content"));

    // Test update request schema (all fields optional)
    let update_request = &schemas["UpdatepostsRequest"];
    assert_eq!(update_request["type"], "object");
    let update_properties = update_request["properties"].as_object().unwrap();
    assert!(update_properties.contains_key("title"));
    assert!(update_properties.contains_key("published"));
    // Should not have required array or should be empty
    if let Some(required) = update_request.get("required") {
        assert!(required.as_array().unwrap().is_empty());
    }
}

#[test]
fn test_response_status_codes() {
    let generator = OpenApiGenerator::new("http://localhost:8090".to_string());
    let collections = vec![create_test_posts_collection()];

    let spec = generator.generate_spec(&collections);
    let paths = &spec["paths"];

    // Test collection endpoints
    let collection_path = "/api/collections/posts/records";
    let collection_endpoint = &paths[collection_path];

    // GET should return 200
    let get_responses = &collection_endpoint["get"]["responses"];
    assert!(get_responses["200"].is_object());

    // POST should return 201 and 400
    let post_responses = &collection_endpoint["post"]["responses"];
    assert!(post_responses["201"].is_object());
    assert!(post_responses["400"].is_object());

    // Test record endpoints
    let record_path = "/api/collections/posts/records/{id}";
    let record_endpoint = &paths[record_path];

    // GET should return 200 and 404
    let get_responses = &record_endpoint["get"]["responses"];
    assert!(get_responses["200"].is_object());
    assert!(get_responses["404"].is_object());

    // DELETE should return 204 and 404
    let delete_responses = &record_endpoint["delete"]["responses"];
    assert!(delete_responses["204"].is_object());
    assert!(delete_responses["404"].is_object());
}

// Helper functions

fn create_test_posts_collection() -> Collection {
    let mut schema = CollectionSchema::new();

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
        Field::new(Uuid::new_v4(), "content".to_string(), FieldType::Text).required(),
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

    schema.add_field(Field::new(
        Uuid::new_v4(),
        "featured_image".to_string(),
        FieldType::File {
            max_size: Some(10 * 1024 * 1024),
            allowed_types: Some(vec![
                "image/jpeg".to_string(),
                "image/png".to_string(),
            ]),
        },
    ));

    schema.add_field(Field::new(
        Uuid::new_v4(),
        "status".to_string(),
        FieldType::Text,
    ).with_options(FieldOptions {
        enum_values: Some(vec![
            "draft".to_string(),
            "published".to_string(),
            "archived".to_string(),
        ]),
        default_value: Some(json!("draft")),
        ..Default::default()
    }));

    Collection::new("posts".to_string(), CollectionType::Base).with_schema(schema)
}

fn create_test_users_collection() -> Collection {
    let mut schema = CollectionSchema::new();

    schema.add_field(
        Field::new(Uuid::new_v4(), "email".to_string(), FieldType::Email)
            .required()
            .unique(),
    );

    schema.add_field(
        Field::new(Uuid::new_v4(), "name".to_string(), FieldType::Text).required(),
    );

    Collection::new("users".to_string(), CollectionType::Auth).with_schema(schema)
}