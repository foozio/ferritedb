use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use rustbase_core::{Collection, Field, FieldType, UserRole};
use serde_json::{json, Value};
use std::collections::HashMap;

/// OpenAPI specification generator for RustBase
pub struct OpenApiGenerator {
    title: String,
    version: String,
    description: String,
    server_url: String,
}

impl OpenApiGenerator {
    pub fn new(server_url: String) -> Self {
        Self {
            title: "RustBase API".to_string(),
            version: "1.0.0".to_string(),
            description: "A production-ready, developer-friendly backend service that provides a complete backend-as-a-service solution.".to_string(),
            server_url,
        }
    }

    /// Generate OpenAPI 3.1 specification
    pub fn generate_spec(&self, collections: &[Collection]) -> Value {
        json!({
            "openapi": "3.1.0",
            "info": {
                "title": self.title,
                "version": self.version,
                "description": self.description,
                "contact": {
                    "name": "RustBase",
                    "url": "https://github.com/rustbase/rustbase"
                },
                "license": {
                    "name": "MIT",
                    "url": "https://opensource.org/licenses/MIT"
                }
            },
            "servers": [
                {
                    "url": self.server_url,
                    "description": "RustBase Server"
                }
            ],
            "paths": self.generate_paths(collections),
            "components": {
                "schemas": self.generate_schemas(collections),
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    }
                }
            },
            "security": [
                {
                    "bearerAuth": []
                }
            ],
            "tags": self.generate_tags(collections)
        })
    }

    fn generate_paths(&self, collections: &[Collection]) -> Value {
        let mut paths = json!({});

        // Authentication endpoints
        paths["/api/auth/login"] = json!({
            "post": {
                "tags": ["Authentication"],
                "summary": "User login",
                "description": "Authenticate a user with email and password",
                "security": [],
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/LoginRequest"
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Login successful",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/LoginResponse"
                                }
                            }
                        }
                    },
                    "401": {
                        "description": "Invalid credentials",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/ErrorResponse"
                                }
                            }
                        }
                    }
                }
            }
        });

        paths["/api/auth/register"] = json!({
            "post": {
                "tags": ["Authentication"],
                "summary": "User registration",
                "description": "Register a new user account",
                "security": [],
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/RegisterRequest"
                            }
                        }
                    }
                },
                "responses": {
                    "201": {
                        "description": "Registration successful",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/RegisterResponse"
                                }
                            }
                        }
                    },
                    "400": {
                        "description": "Validation error",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/ErrorResponse"
                                }
                            }
                        }
                    }
                }
            }
        });

        paths["/api/auth/refresh"] = json!({
            "post": {
                "tags": ["Authentication"],
                "summary": "Refresh access token",
                "description": "Get a new access token using a refresh token",
                "security": [],
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/RefreshTokenRequest"
                            }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Token refreshed successfully",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/AuthToken"
                                }
                            }
                        }
                    },
                    "401": {
                        "description": "Invalid refresh token",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/ErrorResponse"
                                }
                            }
                        }
                    }
                }
            }
        });

        // Health check endpoints
        paths["/healthz"] = json!({
            "get": {
                "tags": ["Health"],
                "summary": "Health check",
                "description": "Check if the service is healthy",
                "security": [],
                "responses": {
                    "200": {
                        "description": "Service is healthy",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "status": {
                                            "type": "string",
                                            "example": "ok"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        paths["/readyz"] = json!({
            "get": {
                "tags": ["Health"],
                "summary": "Readiness check",
                "description": "Check if the service is ready to accept requests",
                "security": [],
                "responses": {
                    "200": {
                        "description": "Service is ready",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "status": {
                                            "type": "string",
                                            "example": "ready"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        // Collection endpoints
        for collection in collections {
            let collection_name = &collection.name;
            let tag_name = format!("{} Collection", collection_name);

            // List records
            paths[format!("/api/collections/{}/records", collection_name)] = json!({
                "get": {
                    "tags": [tag_name.clone()],
                    "summary": format!("List {} records", collection_name),
                    "description": format!("Get a paginated list of {} records", collection_name),
                    "parameters": [
                        {
                            "name": "page",
                            "in": "query",
                            "description": "Page number (1-based)",
                            "schema": {
                                "type": "integer",
                                "minimum": 1,
                                "default": 1
                            }
                        },
                        {
                            "name": "perPage",
                            "in": "query",
                            "description": "Number of records per page",
                            "schema": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 500,
                                "default": 30
                            }
                        },
                        {
                            "name": "sort",
                            "in": "query",
                            "description": "Sort field and direction (e.g., '-created_at')",
                            "schema": {
                                "type": "string"
                            }
                        },
                        {
                            "name": "filter",
                            "in": "query",
                            "description": "Filter expression",
                            "schema": {
                                "type": "string"
                            }
                        },
                        {
                            "name": "fields",
                            "in": "query",
                            "description": "Comma-separated list of fields to include",
                            "schema": {
                                "type": "string"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "List of records",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "page": {
                                                "type": "integer"
                                            },
                                            "perPage": {
                                                "type": "integer"
                                            },
                                            "totalItems": {
                                                "type": "integer"
                                            },
                                            "totalPages": {
                                                "type": "integer"
                                            },
                                            "items": {
                                                "type": "array",
                                                "items": {
                                                    "$ref": format!("#/components/schemas/{}Record", collection_name)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "post": {
                    "tags": [tag_name.clone()],
                    "summary": format!("Create {} record", collection_name),
                    "description": format!("Create a new {} record", collection_name),
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": format!("#/components/schemas/Create{}Request", collection_name)
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Record created successfully",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": format!("#/components/schemas/{}Record", collection_name)
                                    }
                                }
                            }
                        },
                        "400": {
                            "description": "Validation error",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/ErrorResponse"
                                    }
                                }
                            }
                        }
                    }
                }
            });

            // Get single record
            paths[format!("/api/collections/{}/records/{{id}}", collection_name)] = json!({
                "get": {
                    "tags": [tag_name.clone()],
                    "summary": format!("Get {} record", collection_name),
                    "description": format!("Get a specific {} record by ID", collection_name),
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "description": "Record ID",
                            "schema": {
                                "type": "string",
                                "format": "uuid"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Record found",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": format!("#/components/schemas/{}Record", collection_name)
                                    }
                                }
                            }
                        },
                        "404": {
                            "description": "Record not found",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/ErrorResponse"
                                    }
                                }
                            }
                        }
                    }
                },
                "patch": {
                    "tags": [tag_name.clone()],
                    "summary": format!("Update {} record", collection_name),
                    "description": format!("Update a specific {} record", collection_name),
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "description": "Record ID",
                            "schema": {
                                "type": "string",
                                "format": "uuid"
                            }
                        }
                    ],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": format!("#/components/schemas/Update{}Request", collection_name)
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Record updated successfully",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": format!("#/components/schemas/{}Record", collection_name)
                                    }
                                }
                            }
                        },
                        "404": {
                            "description": "Record not found",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/ErrorResponse"
                                    }
                                }
                            }
                        }
                    }
                },
                "delete": {
                    "tags": [tag_name.clone()],
                    "summary": format!("Delete {} record", collection_name),
                    "description": format!("Delete a specific {} record", collection_name),
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "description": "Record ID",
                            "schema": {
                                "type": "string",
                                "format": "uuid"
                            }
                        }
                    ],
                    "responses": {
                        "204": {
                            "description": "Record deleted successfully"
                        },
                        "404": {
                            "description": "Record not found",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/ErrorResponse"
                                    }
                                }
                            }
                        }
                    }
                }
            });

            // File upload/download endpoints for collections with file fields
            if collection.schema_json.fields.iter().any(|f| matches!(f.field_type, FieldType::File { .. })) {
                paths[format!("/api/files/{}/{{recordId}}/{{fieldName}}", collection_name)] = json!({
                    "post": {
                        "tags": [tag_name.clone()],
                        "summary": format!("Upload file to {} record", collection_name),
                        "description": format!("Upload a file to a specific field in a {} record", collection_name),
                        "parameters": [
                            {
                                "name": "recordId",
                                "in": "path",
                                "required": true,
                                "description": "Record ID",
                                "schema": {
                                    "type": "string",
                                    "format": "uuid"
                                }
                            },
                            {
                                "name": "fieldName",
                                "in": "path",
                                "required": true,
                                "description": "Field name",
                                "schema": {
                                    "type": "string"
                                }
                            }
                        ],
                        "requestBody": {
                            "required": true,
                            "content": {
                                "multipart/form-data": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "file": {
                                                "type": "string",
                                                "format": "binary"
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {
                            "200": {
                                "description": "File uploaded successfully",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "filename": {
                                                    "type": "string"
                                                },
                                                "size": {
                                                    "type": "integer"
                                                },
                                                "contentType": {
                                                    "type": "string"
                                                },
                                                "url": {
                                                    "type": "string"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "get": {
                        "tags": [tag_name.clone()],
                        "summary": format!("Download file from {} record", collection_name),
                        "description": format!("Download a file from a specific field in a {} record", collection_name),
                        "parameters": [
                            {
                                "name": "recordId",
                                "in": "path",
                                "required": true,
                                "description": "Record ID",
                                "schema": {
                                    "type": "string",
                                    "format": "uuid"
                                }
                            },
                            {
                                "name": "fieldName",
                                "in": "path",
                                "required": true,
                                "description": "Field name",
                                "schema": {
                                    "type": "string"
                                }
                            }
                        ],
                        "responses": {
                            "200": {
                                "description": "File content",
                                "content": {
                                    "application/octet-stream": {
                                        "schema": {
                                            "type": "string",
                                            "format": "binary"
                                        }
                                    }
                                }
                            },
                            "404": {
                                "description": "File not found"
                            }
                        }
                    }
                });
            }
        }

        paths
    }

    fn generate_schemas(&self, collections: &[Collection]) -> Value {
        let mut schemas = json!({});

        // Common schemas
        schemas["ErrorResponse"] = json!({
            "type": "object",
            "properties": {
                "error": {
                    "type": "string",
                    "description": "Error message"
                }
            },
            "required": ["error"]
        });

        schemas["AuthToken"] = json!({
            "type": "object",
            "properties": {
                "access_token": {
                    "type": "string",
                    "description": "JWT access token"
                },
                "refresh_token": {
                    "type": "string",
                    "description": "JWT refresh token"
                },
                "token_type": {
                    "type": "string",
                    "example": "Bearer"
                },
                "expires_in": {
                    "type": "integer",
                    "description": "Token expiration time in seconds"
                }
            },
            "required": ["access_token", "refresh_token", "token_type", "expires_in"]
        });

        schemas["LoginRequest"] = json!({
            "type": "object",
            "properties": {
                "email": {
                    "type": "string",
                    "format": "email"
                },
                "password": {
                    "type": "string",
                    "minLength": 8
                }
            },
            "required": ["email", "password"]
        });

        schemas["RegisterRequest"] = json!({
            "type": "object",
            "properties": {
                "email": {
                    "type": "string",
                    "format": "email"
                },
                "password": {
                    "type": "string",
                    "minLength": 8
                },
                "password_confirm": {
                    "type": "string",
                    "minLength": 8
                }
            },
            "required": ["email", "password", "password_confirm"]
        });

        schemas["RefreshTokenRequest"] = json!({
            "type": "object",
            "properties": {
                "refresh_token": {
                    "type": "string"
                }
            },
            "required": ["refresh_token"]
        });

        schemas["LoginResponse"] = json!({
            "type": "object",
            "properties": {
                "user": {
                    "$ref": "#/components/schemas/User"
                },
                "token": {
                    "$ref": "#/components/schemas/AuthToken"
                }
            },
            "required": ["user", "token"]
        });

        schemas["RegisterResponse"] = json!({
            "type": "object",
            "properties": {
                "user": {
                    "$ref": "#/components/schemas/User"
                },
                "token": {
                    "$ref": "#/components/schemas/AuthToken"
                }
            },
            "required": ["user", "token"]
        });

        schemas["User"] = json!({
            "type": "object",
            "properties": {
                "id": {
                    "type": "string",
                    "format": "uuid"
                },
                "email": {
                    "type": "string",
                    "format": "email"
                },
                "role": {
                    "type": "string",
                    "enum": ["admin", "user", "service"]
                },
                "verified": {
                    "type": "boolean"
                },
                "created_at": {
                    "type": "string",
                    "format": "date-time"
                },
                "updated_at": {
                    "type": "string",
                    "format": "date-time"
                }
            },
            "required": ["id", "email", "role", "verified", "created_at", "updated_at"]
        });

        // Generate schemas for each collection
        for collection in collections {
            let collection_name = &collection.name;
            
            // Record schema
            let mut record_properties = json!({
                "id": {
                    "type": "string",
                    "format": "uuid",
                    "description": "Unique record identifier"
                },
                "created_at": {
                    "type": "string",
                    "format": "date-time",
                    "description": "Record creation timestamp"
                },
                "updated_at": {
                    "type": "string",
                    "format": "date-time",
                    "description": "Record last update timestamp"
                }
            });

            let mut required_fields = vec!["id".to_string(), "created_at".to_string(), "updated_at".to_string()];

            // Add collection fields
            for field in &collection.schema_json.fields {
                let field_schema = self.field_to_json_schema(field);
                record_properties[&field.name] = field_schema;
                
                if field.required {
                    required_fields.push(field.name.clone());
                }
            }

            schemas[format!("{}Record", collection_name)] = json!({
                "type": "object",
                "properties": record_properties,
                "required": required_fields
            });

            // Create request schema (without id, created_at, updated_at)
            let mut create_properties = json!({});
            let mut create_required = Vec::new();

            for field in &collection.schema_json.fields {
                let field_schema = self.field_to_json_schema(field);
                create_properties[&field.name] = field_schema;
                
                if field.required {
                    create_required.push(field.name.clone());
                }
            }

            schemas[format!("Create{}Request", collection_name)] = json!({
                "type": "object",
                "properties": create_properties,
                "required": create_required
            });

            // Update request schema (all fields optional)
            schemas[format!("Update{}Request", collection_name)] = json!({
                "type": "object",
                "properties": create_properties
            });
        }

        schemas
    }

    fn field_to_json_schema(&self, field: &Field) -> Value {
        let mut schema = match &field.field_type {
            FieldType::Text => json!({
                "type": "string"
            }),
            FieldType::Number => json!({
                "type": "number"
            }),
            FieldType::Boolean => json!({
                "type": "boolean"
            }),
            FieldType::Email => json!({
                "type": "string",
                "format": "email"
            }),
            FieldType::Url => json!({
                "type": "string",
                "format": "uri"
            }),
            FieldType::Json => json!({}),
            FieldType::Date => json!({
                "type": "string",
                "format": "date"
            }),
            FieldType::DateTime => json!({
                "type": "string",
                "format": "date-time"
            }),
            FieldType::Relation { target_collection, .. } => json!({
                "type": "string",
                "format": "uuid",
                "description": format!("Reference to {} collection", target_collection)
            }),
            FieldType::File { .. } => json!({
                "type": "string",
                "description": "File reference or URL"
            }),
        };

        // Add field options
        if let Some(options) = &field.options_json {
            if let Some(min_length) = options.min_length {
                schema["minLength"] = json!(min_length);
            }
            if let Some(max_length) = options.max_length {
                schema["maxLength"] = json!(max_length);
            }
            if let Some(min_value) = options.min_value {
                schema["minimum"] = json!(min_value);
            }
            if let Some(max_value) = options.max_value {
                schema["maximum"] = json!(max_value);
            }
            if let Some(pattern) = &options.pattern {
                schema["pattern"] = json!(pattern);
            }
            if let Some(enum_values) = &options.enum_values {
                schema["enum"] = json!(enum_values);
            }
            if let Some(default) = &options.default_value {
                schema["default"] = default.clone();
            }
        }

        schema
    }

    fn generate_tags(&self, collections: &[Collection]) -> Value {
        let mut tags = vec![
            json!({
                "name": "Authentication",
                "description": "User authentication and authorization endpoints"
            }),
            json!({
                "name": "Health",
                "description": "Health check and monitoring endpoints"
            })
        ];

        for collection in collections {
            tags.push(json!({
                "name": format!("{} Collection", collection.name),
                "description": format!("CRUD operations for {} collection", collection.name)
            }));
        }

        json!(tags)
    }
}

/// Handler for serving OpenAPI specification
pub async fn openapi_spec_handler(
    State(collections): State<Vec<Collection>>,
) -> impl IntoResponse {
    let generator = OpenApiGenerator::new("http://localhost:8090".to_string());
    let spec = generator.generate_spec(&collections);
    Json(spec)
}

/// Handler for serving Swagger UI
pub async fn swagger_ui_handler() -> impl IntoResponse {
    let html = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RustBase API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui.css" />
    <style>
        html {
            box-sizing: border-box;
            overflow: -moz-scrollbars-vertical;
            overflow-y: scroll;
        }
        *, *:before, *:after {
            box-sizing: inherit;
        }
        body {
            margin:0;
            background: #fafafa;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5.9.0/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: '/api/openapi.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout",
                tryItOutEnabled: true,
                requestInterceptor: function(request) {
                    // Add authorization header if token is available
                    const token = localStorage.getItem('rustbase_token');
                    if (token) {
                        request.headers['Authorization'] = 'Bearer ' + token;
                    }
                    return request;
                },
                onComplete: function() {
                    // Add custom styling or functionality
                    console.log('RustBase API Documentation loaded');
                }
            });

            // Add token management functionality
            window.setAuthToken = function(token) {
                localStorage.setItem('rustbase_token', token);
                console.log('Auth token set');
            };

            window.clearAuthToken = function() {
                localStorage.removeItem('rustbase_token');
                console.log('Auth token cleared');
            };

            // Add helper functions to window for easy testing
            window.rustbaseHelpers = {
                setToken: window.setAuthToken,
                clearToken: window.clearAuthToken,
                getToken: function() {
                    return localStorage.getItem('rustbase_token');
                }
            };
        };
    </script>
    <style>
        .swagger-ui .topbar {
            background-color: #2c3e50;
        }
        .swagger-ui .topbar .download-url-wrapper {
            display: none;
        }
        .swagger-ui .info .title {
            color: #2c3e50;
        }
    </style>
</body>
</html>
"#;

    Html(html)
}

/// Create routes for OpenAPI documentation
pub fn create_docs_routes() -> Router<Vec<Collection>> {
    Router::new()
        .route("/docs", get(swagger_ui_handler))
        .route("/api/openapi.json", get(openapi_spec_handler))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustbase_core::{CollectionSchema, CollectionType, Field, FieldOptions, FieldType};
    use uuid::Uuid;

    fn create_test_collection() -> Collection {
        let mut schema = CollectionSchema::new();
        
        schema.add_field(
            Field::new(Uuid::new_v4(), "title".to_string(), FieldType::Text)
                .required()
                .with_options(FieldOptions {
                    min_length: Some(1),
                    max_length: Some(255),
                    ..Default::default()
                })
        );

        schema.add_field(
            Field::new(Uuid::new_v4(), "content".to_string(), FieldType::Text)
        );

        schema.add_field(
            Field::new(Uuid::new_v4(), "published".to_string(), FieldType::Boolean)
                .with_options(FieldOptions {
                    default_value: Some(json!(false)),
                    ..Default::default()
                })
        );

        schema.add_field(
            Field::new(Uuid::new_v4(), "author_id".to_string(), FieldType::Relation {
                target_collection: "users".to_string(),
                cascade_delete: false,
            })
            .required()
        );

        Collection::new("posts".to_string(), CollectionType::Base)
            .with_schema(schema)
    }

    #[test]
    fn test_openapi_spec_generation() {
        let generator = OpenApiGenerator::new("http://localhost:8090".to_string());
        let collections = vec![create_test_collection()];
        
        let spec = generator.generate_spec(&collections);
        
        // Verify basic structure
        assert_eq!(spec["openapi"], "3.1.0");
        assert_eq!(spec["info"]["title"], "RustBase API");
        assert_eq!(spec["info"]["version"], "1.0.0");
        
        // Verify server configuration
        assert_eq!(spec["servers"][0]["url"], "http://localhost:8090");
        
        // Verify authentication endpoints exist
        assert!(spec["paths"]["/api/auth/login"].is_object());
        assert!(spec["paths"]["/api/auth/register"].is_object());
        assert!(spec["paths"]["/api/auth/refresh"].is_object());
        
        // Verify collection endpoints exist
        assert!(spec["paths"]["/api/collections/posts/records"].is_object());
        assert!(spec["paths"]["/api/collections/posts/records/{id}"].is_object());
        
        // Verify schemas exist
        assert!(spec["components"]["schemas"]["ErrorResponse"].is_object());
        assert!(spec["components"]["schemas"]["AuthToken"].is_object());
        assert!(spec["components"]["schemas"]["postsRecord"].is_object());
        assert!(spec["components"]["schemas"]["CreatepostsRequest"].is_object());
        
        // Verify security scheme
        assert!(spec["components"]["securitySchemes"]["bearerAuth"].is_object());
    }

    #[test]
    fn test_field_to_json_schema() {
        let generator = OpenApiGenerator::new("http://localhost:8090".to_string());
        
        // Test text field with options
        let text_field = Field::new(
            Uuid::new_v4(),
            "title".to_string(),
            FieldType::Text
        ).with_options(FieldOptions {
            min_length: Some(1),
            max_length: Some(255),
            ..Default::default()
        });
        
        let schema = generator.field_to_json_schema(&text_field);
        assert_eq!(schema["type"], "string");
        assert_eq!(schema["minLength"], 1);
        assert_eq!(schema["maxLength"], 255);
        
        // Test relation field
        let relation_field = Field::new(
            Uuid::new_v4(),
            "author_id".to_string(),
            FieldType::Relation {
                target_collection: "users".to_string(),
                cascade_delete: false,
            }
        );
        
        let schema = generator.field_to_json_schema(&relation_field);
        assert_eq!(schema["type"], "string");
        assert_eq!(schema["format"], "uuid");
        assert!(schema["description"].as_str().unwrap().contains("users"));
        
        // Test boolean field with default
        let bool_field = Field::new(
            Uuid::new_v4(),
            "published".to_string(),
            FieldType::Boolean
        ).with_options(FieldOptions {
            default_value: Some(json!(false)),
            ..Default::default()
        });
        
        let schema = generator.field_to_json_schema(&bool_field);
        assert_eq!(schema["type"], "boolean");
        assert_eq!(schema["default"], false);
    }

    #[test]
    fn test_generate_tags() {
        let generator = OpenApiGenerator::new("http://localhost:8090".to_string());
        let collections = vec![create_test_collection()];
        
        let tags = generator.generate_tags(&collections);
        let tags_array = tags.as_array().unwrap();
        
        // Should have Authentication, Health, and posts Collection tags
        assert_eq!(tags_array.len(), 3);
        
        let tag_names: Vec<&str> = tags_array.iter()
            .map(|tag| tag["name"].as_str().unwrap())
            .collect();
        
        assert!(tag_names.contains(&"Authentication"));
        assert!(tag_names.contains(&"Health"));
        assert!(tag_names.contains(&"posts Collection"));
    }

    #[test]
    fn test_generate_schemas() {
        let generator = OpenApiGenerator::new("http://localhost:8090".to_string());
        let collections = vec![create_test_collection()];
        
        let schemas = generator.generate_schemas(&collections);
        
        // Verify common schemas
        assert!(schemas["ErrorResponse"].is_object());
        assert!(schemas["AuthToken"].is_object());
        assert!(schemas["LoginRequest"].is_object());
        assert!(schemas["User"].is_object());
        
        // Verify collection-specific schemas
        assert!(schemas["postsRecord"].is_object());
        assert!(schemas["CreatepostsRequest"].is_object());
        assert!(schemas["UpdatepostsRequest"].is_object());
        
        // Verify record schema has required fields
        let posts_record = &schemas["postsRecord"];
        let required = posts_record["required"].as_array().unwrap();
        assert!(required.contains(&json!("id")));
        assert!(required.contains(&json!("title")));
        assert!(required.contains(&json!("author_id")));
        assert!(required.contains(&json!("created_at")));
        assert!(required.contains(&json!("updated_at")));
        
        // Verify create request doesn't have system fields
        let create_request = &schemas["CreatepostsRequest"];
        let properties = create_request["properties"].as_object().unwrap();
        assert!(!properties.contains_key("id"));
        assert!(!properties.contains_key("created_at"));
        assert!(!properties.contains_key("updated_at"));
        assert!(properties.contains_key("title"));
        assert!(properties.contains_key("content"));
    }
}