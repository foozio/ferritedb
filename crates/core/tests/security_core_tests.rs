use ferritedb_core::{
    audit::{AuditAction, AuditContext, AuditLogger},
    pii::{PiiRedactionConfig, PiiRedactor, PiiUtils},
};
use serde_json::json;
use sqlx::SqlitePool;
use std::collections::HashSet;
use tempfile::tempdir;
use uuid::Uuid;

async fn create_test_db() -> SqlitePool {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let database_url = format!("sqlite:{}", db_path.display());
    
    let pool = SqlitePool::connect(&database_url).await.unwrap();
    
    // Create audit_log table
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT,
            details_json TEXT,
            ip_address TEXT,
            user_agent TEXT,
            request_id TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#
    )
    .execute(&pool)
    .await
    .unwrap();
    
    pool
}

#[tokio::test]
async fn test_audit_logger_basic_functionality() {
    let pool = create_test_db().await;
    let logger = AuditLogger::new(pool, true);
    
    let user_id = Uuid::new_v4();
    
    // Test logging various actions
    logger.log(
        AuditAction::UserLogin,
        "user",
        Some("user-123"),
        Some(user_id),
        Some(json!({"success": true, "method": "password"})),
        Some("192.168.1.1"),
        Some("Mozilla/5.0"),
        Some("req-abc123"),
    ).await.unwrap();
    
    logger.log(
        AuditAction::RecordCreate,
        "record",
        Some("record-456"),
        Some(user_id),
        Some(json!({"collection": "posts", "title": "New Post"})),
        Some("192.168.1.1"),
        Some("Mozilla/5.0"),
        Some("req-def456"),
    ).await.unwrap();
    
    // Retrieve logs
    let logs = logger.get_audit_logs(
        Some(user_id),
        None,
        None,
        None,
        None,
        10,
        0,
    ).await.unwrap();
    
    assert_eq!(logs.len(), 2);
    
    // Check first log (most recent)
    assert_eq!(logs[0].action.as_str(), "record_create");
    assert_eq!(logs[0].user_id, Some(user_id));
    assert_eq!(logs[0].resource_type, "record");
    assert_eq!(logs[0].resource_id, Some("record-456".to_string()));
    
    // Check second log
    assert_eq!(logs[1].action.as_str(), "user_login");
    assert_eq!(logs[1].user_id, Some(user_id));
    assert_eq!(logs[1].resource_type, "user");
}

#[tokio::test]
async fn test_audit_logger_filtering() {
    let pool = create_test_db().await;
    let logger = AuditLogger::new(pool, true);
    
    let user1 = Uuid::new_v4();
    let user2 = Uuid::new_v4();
    
    // Log actions for different users
    logger.log(
        AuditAction::UserLogin,
        "user",
        None::<String>,
        Some(user1),
        None,
        Some("192.168.1.1"),
        None::<String>,
        None::<String>,
    ).await.unwrap();
    
    logger.log(
        AuditAction::CollectionCreate,
        "collection",
        Some("posts"),
        Some(user2),
        None,
        Some("192.168.1.2"),
        None::<String>,
        None::<String>,
    ).await.unwrap();
    
    // Filter by user1
    let user1_logs = logger.get_audit_logs(
        Some(user1),
        None,
        None,
        None,
        None,
        10,
        0,
    ).await.unwrap();
    
    assert_eq!(user1_logs.len(), 1);
    assert_eq!(user1_logs[0].user_id, Some(user1));
    
    // Filter by action
    let login_logs = logger.get_audit_logs(
        None,
        Some(AuditAction::UserLogin),
        None,
        None,
        None,
        10,
        0,
    ).await.unwrap();
    
    assert_eq!(login_logs.len(), 1);
    assert_eq!(login_logs[0].action.as_str(), "user_login");
}

#[tokio::test]
async fn test_audit_logger_disabled() {
    let pool = create_test_db().await;
    let logger = AuditLogger::new(pool.clone(), false); // Disabled
    
    // Should not log when disabled
    logger.log(
        AuditAction::UserLogin,
        "user",
        None::<String>,
        None,
        None,
        None::<String>,
        None::<String>,
        None::<String>,
    ).await.unwrap();
    
    // Verify no logs were created
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    
    assert_eq!(count, 0);
}

#[tokio::test]
async fn test_audit_context_builder() {
    let user_id = Uuid::new_v4();
    
    let context = AuditContext::new()
        .with_user_id(user_id)
        .with_ip_address("192.168.1.1".to_string())
        .with_user_agent("Mozilla/5.0".to_string())
        .with_request_id("req-123".to_string());
    
    assert_eq!(context.user_id, Some(user_id));
    assert_eq!(context.ip_address, Some("192.168.1.1".to_string()));
    assert_eq!(context.user_agent, Some("Mozilla/5.0".to_string()));
    assert_eq!(context.request_id, Some("req-123".to_string()));
}

#[tokio::test]
async fn test_audit_cleanup() {
    let pool = create_test_db().await;
    let logger = AuditLogger::new(pool.clone(), true);
    
    // Create an old entry by manually inserting with past date
    let old_date = chrono::Utc::now() - chrono::Duration::days(100);
    let old_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO audit_log (id, action, resource_type, created_at) VALUES (?, ?, ?, ?)"
    )
    .bind(&old_id)
    .bind("test_action")
    .bind("test_resource")
    .bind(old_date)
    .execute(&pool)
    .await
    .unwrap();
    
    // Create a recent entry
    logger.log(
        AuditAction::UserLogin,
        "user",
        None::<String>,
        None,
        None,
        None::<String>,
        None::<String>,
        None::<String>,
    ).await.unwrap();
    
    // Cleanup entries older than 30 days
    let deleted_count = logger.cleanup_old_entries(30).await.unwrap();
    assert_eq!(deleted_count, 1);
    
    // Verify only recent entry remains
    let remaining_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    
    assert_eq!(remaining_count, 1);
}

#[test]
fn test_pii_redactor_configuration() {
    let mut config = PiiRedactionConfig::default();
    
    // Test default sensitive fields
    assert!(config.sensitive_fields.contains("password"));
    assert!(config.sensitive_fields.contains("ssn"));
    assert!(config.sensitive_fields.contains("credit_card"));
    
    // Test custom configuration
    config.sensitive_fields.insert("custom_secret".to_string());
    config.redaction_text = "[HIDDEN]".to_string();
    
    let redactor = PiiRedactor::new(config).unwrap();
    
    let mut data = json!({
        "custom_secret": "secret_value",
        "public_data": "visible"
    });
    
    redactor.redact_json(&mut data);
    
    assert_eq!(data["custom_secret"], "[HIDDEN]");
    assert_eq!(data["public_data"], "visible");
}

#[test]
fn test_pii_pattern_detection() {
    let config = PiiRedactionConfig::default();
    let redactor = PiiRedactor::new(config).unwrap();
    
    // Test email detection
    assert!(redactor.contains_pii("Contact: john@example.com"));
    assert!(redactor.contains_pii("Email me at user.name+tag@domain.co.uk"));
    
    // Test phone number detection
    assert!(redactor.contains_pii("Call me at (555) 123-4567"));
    assert!(redactor.contains_pii("Phone: 555.123.4567"));
    assert!(redactor.contains_pii("Mobile: +1-555-123-4567"));
    
    // Test SSN detection
    assert!(redactor.contains_pii("SSN: 123-45-6789"));
    assert!(redactor.contains_pii("Social Security: 123 45 6789"));
    
    // Test credit card detection
    assert!(redactor.contains_pii("Card: 4111-1111-1111-1111")); // Visa
    assert!(redactor.contains_pii("Card: 5555-5555-5555-4444")); // MasterCard
    assert!(redactor.contains_pii("Card: 1234-5678-9012-3456")); // Generic 16-digit
    
    // Test IP address detection
    assert!(redactor.contains_pii("Server IP: 192.168.1.1"));
    assert!(redactor.contains_pii("Connect to 10.0.0.1"));
    
    // Test non-PII text
    assert!(!redactor.contains_pii("This is just normal text"));
    assert!(!redactor.contains_pii("No sensitive information here"));
}

#[test]
fn test_pii_json_redaction_nested() {
    let config = PiiRedactionConfig::default();
    let redactor = PiiRedactor::new(config).unwrap();
    
    let mut data = json!({
        "user": {
            "name": "John Doe",
            "email": "john@example.com",
            "password": "secret123",
            "profile": {
                "phone": "555-123-4567",
                "address": {
                    "street": "123 Main St",
                    "ssn": "123-45-6789"
                }
            }
        },
        "metadata": {
            "created_by": "admin@example.com",
            "api_key": "sk_test_123456"
        }
    });
    
    redactor.redact_json(&mut data);
    
    // Check nested redaction
    assert_eq!(data["user"]["password"], "[REDACTED]");
    assert_eq!(data["metadata"]["api_key"], "[REDACTED]");
    
    // Check PII pattern redaction
    assert_ne!(data["user"]["email"], "john@example.com");
    assert_ne!(data["user"]["profile"]["phone"], "555-123-4567");
    assert_ne!(data["user"]["profile"]["address"]["ssn"], "123-45-6789");
    assert_ne!(data["metadata"]["created_by"], "admin@example.com");
    
    // Check non-sensitive data remains
    assert_eq!(data["user"]["name"], "John Doe");
    assert_eq!(data["user"]["profile"]["address"]["street"], "123 Main St");
}

#[test]
fn test_pii_array_redaction() {
    let config = PiiRedactionConfig::default();
    let redactor = PiiRedactor::new(config).unwrap();
    
    let mut data = json!({
        "users": [
            {
                "name": "John",
                "email": "john@example.com",
                "password": "secret1"
            },
            {
                "name": "Jane",
                "email": "jane@example.com", 
                "password": "secret2"
            }
        ],
        "contacts": ["admin@example.com", "support@example.com"]
    });
    
    redactor.redact_json(&mut data);
    
    // Check array element redaction
    assert_eq!(data["users"][0]["password"], "[REDACTED]");
    assert_eq!(data["users"][1]["password"], "[REDACTED]");
    
    // Check PII in array elements
    assert_ne!(data["users"][0]["email"], "john@example.com");
    assert_ne!(data["users"][1]["email"], "jane@example.com");
    
    // Check string arrays
    assert_ne!(data["contacts"][0], "admin@example.com");
    assert_ne!(data["contacts"][1], "support@example.com");
}

#[test]
fn test_pii_analysis_detailed() {
    let config = PiiRedactionConfig::default();
    let redactor = PiiRedactor::new(config).unwrap();
    
    let text = "Contact John at john@example.com or call (555) 123-4567. His SSN is 123-45-6789 and credit card is 4111-1111-1111-1111.";
    let analysis = redactor.analyze_text(text);
    
    assert!(analysis.contains_pii);
    assert!(analysis.total_matches >= 4); // email, phone, ssn, credit card
    
    // Check that different pattern types are detected
    let pattern_names: Vec<&str> = analysis.detected_patterns
        .iter()
        .map(|p| p.pattern_name.as_str())
        .collect();
    
    assert!(pattern_names.contains(&"email"));
    assert!(pattern_names.contains(&"phone_us"));
    assert!(pattern_names.contains(&"ssn"));
    assert!(pattern_names.contains(&"credit_card"));
}

#[test]
fn test_pii_utils_partial_redaction() {
    // Test email partial redaction
    assert_eq!(PiiUtils::redact_email_partial("john@example.com"), "jo***@example.com");
    assert_eq!(PiiUtils::redact_email_partial("a@test.com"), "***@test.com");
    assert_eq!(PiiUtils::redact_email_partial("invalid-email"), "[REDACTED_EMAIL]");
    
    // Test phone partial redaction
    assert_eq!(PiiUtils::redact_phone_partial("555-123-4567"), "***-***-4567");
    assert_eq!(PiiUtils::redact_phone_partial("(555) 123-4567"), "***-***-4567");
    assert_eq!(PiiUtils::redact_phone_partial("123"), "[REDACTED_PHONE]");
    
    // Test credit card partial redaction
    assert_eq!(PiiUtils::redact_credit_card_partial("4111-1111-1111-1111"), "****-****-****-1111");
    assert_eq!(PiiUtils::redact_credit_card_partial("4111111111111111"), "****-****-****-1111");
    assert_eq!(PiiUtils::redact_credit_card_partial("123"), "[REDACTED_CARD]");
    
    // Test IP partial redaction
    assert_eq!(PiiUtils::redact_ip_partial("192.168.1.1"), "192.***.***.***");
    assert_eq!(PiiUtils::redact_ip_partial("10.0.0.1"), "10.***.***.***");
    assert_eq!(PiiUtils::redact_ip_partial("invalid-ip"), "[REDACTED_IP]");
}

#[test]
fn test_pii_hashmap_redaction() {
    let config = PiiRedactionConfig::default();
    let redactor = PiiRedactor::new(config).unwrap();
    
    let mut data = std::collections::HashMap::new();
    data.insert("username".to_string(), "john_doe".to_string());
    data.insert("password".to_string(), "secret123".to_string());
    data.insert("email".to_string(), "john@example.com".to_string());
    data.insert("phone".to_string(), "555-123-4567".to_string());
    data.insert("description".to_string(), "User profile".to_string());
    
    redactor.redact_hashmap(&mut data);
    
    // Sensitive field should be redacted
    assert_eq!(data["password"], "[REDACTED]");
    
    // PII should be redacted
    assert_ne!(data["email"], "john@example.com");
    assert_ne!(data["phone"], "555-123-4567");
    
    // Non-sensitive data should remain
    assert_eq!(data["username"], "john_doe");
    assert_eq!(data["description"], "User profile");
}

#[test]
fn test_pii_redaction_config_options() {
    let mut config = PiiRedactionConfig::default();
    config.redact_entire_field = true; // Redact entire field instead of just PII parts
    
    let redactor = PiiRedactor::new(config).unwrap();
    
    let mut data = json!({
        "message": "Please contact me at john@example.com for more information"
    });
    
    redactor.redact_json(&mut data);
    
    // With redact_entire_field = true, the entire field should be redacted
    assert_eq!(data["message"], "[REDACTED]");
}

#[test]
fn test_audit_action_serialization() {
    // Test that audit actions serialize correctly
    assert_eq!(AuditAction::UserLogin.as_str(), "user_login");
    assert_eq!(AuditAction::CollectionCreate.as_str(), "collection_create");
    assert_eq!(AuditAction::RecordUpdate.as_str(), "record_update");
    assert_eq!(AuditAction::FileUpload.as_str(), "file_upload");
    assert_eq!(AuditAction::AuthenticationFailure.as_str(), "authentication_failure");
    assert_eq!(AuditAction::Custom("custom_action".to_string()).as_str(), "custom_action");
}

#[test]
fn test_pii_edge_cases() {
    let config = PiiRedactionConfig::default();
    let redactor = PiiRedactor::new(config).unwrap();
    
    // Test empty and null values
    let mut data = json!({
        "empty_string": "",
        "null_value": null,
        "number": 12345,
        "boolean": true,
        "password": "secret"
    });
    
    redactor.redact_json(&mut data);
    
    // Only password should be redacted
    assert_eq!(data["password"], "[REDACTED]");
    assert_eq!(data["empty_string"], "");
    assert_eq!(data["null_value"], serde_json::Value::Null);
    assert_eq!(data["number"], 12345);
    assert_eq!(data["boolean"], true);
    
    // Test malformed data
    let malformed_text = "Not an email: @invalid or phone: 123";
    assert!(!redactor.contains_pii(malformed_text));
}