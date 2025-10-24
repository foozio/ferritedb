use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Pool, QueryBuilder, Row, Sqlite};
use tracing::info;
use uuid::Uuid;

use crate::CoreResult;

/// Audit log entry representing an administrative action or data mutation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub action: AuditAction,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub details: Option<Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Types of actions that can be audited
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    // Authentication actions
    UserLogin,
    UserLogout,
    UserRegistration,
    PasswordChange,
    TokenRefresh,

    // Collection management
    CollectionCreate,
    CollectionUpdate,
    CollectionDelete,
    FieldCreate,
    FieldUpdate,
    FieldDelete,

    // Record operations
    RecordCreate,
    RecordUpdate,
    RecordDelete,
    RecordView,

    // User management
    UserCreate,
    UserUpdate,
    UserDelete,
    RoleChange,

    // File operations
    FileUpload,
    FileDelete,
    FileAccess,

    // System operations
    ConfigurationChange,
    DatabaseMigration,
    SystemStart,
    SystemShutdown,

    // Security events
    AuthenticationFailure,
    AuthorizationFailure,
    SuspiciousActivity,
    RateLimitExceeded,

    // Custom action
    Custom(String),
}

impl AuditAction {
    pub fn as_str(&self) -> &str {
        match self {
            AuditAction::UserLogin => "user_login",
            AuditAction::UserLogout => "user_logout",
            AuditAction::UserRegistration => "user_registration",
            AuditAction::PasswordChange => "password_change",
            AuditAction::TokenRefresh => "token_refresh",
            AuditAction::CollectionCreate => "collection_create",
            AuditAction::CollectionUpdate => "collection_update",
            AuditAction::CollectionDelete => "collection_delete",
            AuditAction::FieldCreate => "field_create",
            AuditAction::FieldUpdate => "field_update",
            AuditAction::FieldDelete => "field_delete",
            AuditAction::RecordCreate => "record_create",
            AuditAction::RecordUpdate => "record_update",
            AuditAction::RecordDelete => "record_delete",
            AuditAction::RecordView => "record_view",
            AuditAction::UserCreate => "user_create",
            AuditAction::UserUpdate => "user_update",
            AuditAction::UserDelete => "user_delete",
            AuditAction::RoleChange => "role_change",
            AuditAction::FileUpload => "file_upload",
            AuditAction::FileDelete => "file_delete",
            AuditAction::FileAccess => "file_access",
            AuditAction::ConfigurationChange => "configuration_change",
            AuditAction::DatabaseMigration => "database_migration",
            AuditAction::SystemStart => "system_start",
            AuditAction::SystemShutdown => "system_shutdown",
            AuditAction::AuthenticationFailure => "authentication_failure",
            AuditAction::AuthorizationFailure => "authorization_failure",
            AuditAction::SuspiciousActivity => "suspicious_activity",
            AuditAction::RateLimitExceeded => "rate_limit_exceeded",
            AuditAction::Custom(action) => action,
        }
    }
}

/// Audit logger service for recording administrative actions and data mutations
#[derive(Debug, Clone)]
pub struct AuditLogger {
    pool: Pool<Sqlite>,
    enabled: bool,
}

impl AuditLogger {
    /// Create a new audit logger
    pub fn new(pool: Pool<Sqlite>, enabled: bool) -> Self {
        Self { pool, enabled }
    }

    /// Log an audit event
    #[allow(clippy::too_many_arguments)]
    pub async fn log(
        &self,
        action: AuditAction,
        resource_type: impl Into<String>,
        resource_id: Option<impl Into<String>>,
        user_id: Option<Uuid>,
        details: Option<Value>,
        ip_address: Option<impl Into<String>>,
        user_agent: Option<impl Into<String>>,
        request_id: Option<impl Into<String>>,
    ) -> CoreResult<()> {
        if !self.enabled {
            return Ok(());
        }

        let entry = AuditLogEntry {
            id: Uuid::new_v4(),
            user_id,
            action: action.clone(),
            resource_type: resource_type.into(),
            resource_id: resource_id.map(|id| id.into()),
            details,
            ip_address: ip_address.map(|ip| ip.into()),
            user_agent: user_agent.map(|ua| ua.into()),
            request_id: request_id.map(|req_id| req_id.into()),
            created_at: Utc::now(),
        };

        // Store in database
        self.store_audit_entry(&entry).await?;

        // Also log to structured logging for real-time monitoring
        info!(
            audit_id = %entry.id,
            user_id = ?entry.user_id,
            action = %action.as_str(),
            resource_type = %entry.resource_type,
            resource_id = ?entry.resource_id,
            ip_address = ?entry.ip_address,
            request_id = ?entry.request_id,
            "Audit log entry created"
        );

        Ok(())
    }

    /// Store audit entry in database
    async fn store_audit_entry(&self, entry: &AuditLogEntry) -> CoreResult<()> {
        let details_json = entry
            .details
            .as_ref()
            .map(|d| serde_json::to_string(d).unwrap_or_default());

        // Use dynamic query to handle both old and new schema
        let query = r#"
            INSERT INTO audit_log (
                id, user_id, action, resource_type, resource_id, 
                details_json, ip_address, user_agent, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#;

        sqlx::query(query)
            .bind(entry.id.to_string())
            .bind(entry.user_id.map(|id| id.to_string()))
            .bind(entry.action.as_str())
            .bind(&entry.resource_type)
            .bind(&entry.resource_id)
            .bind(details_json)
            .bind(&entry.ip_address)
            .bind(&entry.user_agent)
            .bind(entry.created_at)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Retrieve audit log entries with pagination and filtering
    pub async fn get_audit_logs(
        &self,
        user_id: Option<Uuid>,
        action: Option<AuditAction>,
        resource_type: Option<String>,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
        limit: i64,
        offset: i64,
    ) -> CoreResult<Vec<AuditLogEntry>> {
        let mut builder = QueryBuilder::<Sqlite>::new(
            "SELECT id, user_id, action, resource_type, resource_id, details_json, ip_address, user_agent, created_at FROM audit_log WHERE 1=1",
        );

        if let Some(user_id) = user_id {
            builder
                .push(" AND user_id = ")
                .push_bind(user_id.to_string());
        }

        if let Some(action) = action {
            builder
                .push(" AND action = ")
                .push_bind(action.as_str().to_string());
        }

        if let Some(resource_type) = resource_type {
            builder
                .push(" AND resource_type = ")
                .push_bind(resource_type);
        }

        if let Some(start_date) = start_date {
            builder
                .push(" AND created_at >= ")
                .push_bind(start_date.to_rfc3339());
        }

        if let Some(end_date) = end_date {
            builder
                .push(" AND created_at <= ")
                .push_bind(end_date.to_rfc3339());
        }

        builder
            .push(" ORDER BY created_at DESC LIMIT ")
            .push_bind(limit);
        builder.push(" OFFSET ").push_bind(offset);

        let rows = builder.build().fetch_all(&self.pool).await?;

        let mut entries = Vec::new();
        for row in rows {
            let id: String = row.get("id");
            let user_id: Option<String> = row.get("user_id");
            let action: String = row.get("action");
            let resource_type: String = row.get("resource_type");
            let resource_id: Option<String> = row.get("resource_id");
            let details_json: Option<String> = row.get("details_json");
            let ip_address: Option<String> = row.get("ip_address");
            let user_agent: Option<String> = row.get("user_agent");
            let created_at: chrono::NaiveDateTime = row.get("created_at");

            let entry = self.create_audit_entry_from_values(
                id,
                user_id,
                action,
                resource_type,
                resource_id,
                details_json,
                ip_address,
                user_agent,
                None,
                created_at,
            )?;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Create audit entry from database values
    #[allow(clippy::too_many_arguments)]
    fn create_audit_entry_from_values(
        &self,
        id: String,
        user_id: Option<String>,
        action: String,
        resource_type: String,
        resource_id: Option<String>,
        details_json: Option<String>,
        ip_address: Option<String>,
        user_agent: Option<String>,
        request_id: Option<String>,
        created_at: chrono::NaiveDateTime,
    ) -> CoreResult<AuditLogEntry> {
        let action = match action.as_str() {
            "user_login" => AuditAction::UserLogin,
            "user_logout" => AuditAction::UserLogout,
            "user_registration" => AuditAction::UserRegistration,
            "password_change" => AuditAction::PasswordChange,
            "token_refresh" => AuditAction::TokenRefresh,
            "collection_create" => AuditAction::CollectionCreate,
            "collection_update" => AuditAction::CollectionUpdate,
            "collection_delete" => AuditAction::CollectionDelete,
            "field_create" => AuditAction::FieldCreate,
            "field_update" => AuditAction::FieldUpdate,
            "field_delete" => AuditAction::FieldDelete,
            "record_create" => AuditAction::RecordCreate,
            "record_update" => AuditAction::RecordUpdate,
            "record_delete" => AuditAction::RecordDelete,
            "record_view" => AuditAction::RecordView,
            "user_create" => AuditAction::UserCreate,
            "user_update" => AuditAction::UserUpdate,
            "user_delete" => AuditAction::UserDelete,
            "role_change" => AuditAction::RoleChange,
            "file_upload" => AuditAction::FileUpload,
            "file_delete" => AuditAction::FileDelete,
            "file_access" => AuditAction::FileAccess,
            "configuration_change" => AuditAction::ConfigurationChange,
            "database_migration" => AuditAction::DatabaseMigration,
            "system_start" => AuditAction::SystemStart,
            "system_shutdown" => AuditAction::SystemShutdown,
            "authentication_failure" => AuditAction::AuthenticationFailure,
            "authorization_failure" => AuditAction::AuthorizationFailure,
            "suspicious_activity" => AuditAction::SuspiciousActivity,
            "rate_limit_exceeded" => AuditAction::RateLimitExceeded,
            custom => AuditAction::Custom(custom.to_string()),
        };

        let details = if let Some(details_str) = details_json {
            Some(serde_json::from_str(&details_str)?)
        } else {
            None
        };

        let parsed_user_id = if let Some(user_id_str) = user_id {
            Some(Uuid::parse_str(&user_id_str)?)
        } else {
            None
        };

        Ok(AuditLogEntry {
            id: Uuid::parse_str(&id)?,
            user_id: parsed_user_id,
            action,
            resource_type,
            resource_id,
            details,
            ip_address,
            user_agent,
            request_id,
            created_at: DateTime::from_naive_utc_and_offset(created_at, Utc),
        })
    }

    /// Clean up old audit log entries
    pub async fn cleanup_old_entries(&self, retention_days: i64) -> CoreResult<u64> {
        let cutoff_date = Utc::now() - chrono::Duration::days(retention_days);

        let result = sqlx::query("DELETE FROM audit_log WHERE created_at < ?")
            .bind(cutoff_date)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }
}

/// Audit context for collecting audit information from requests
#[derive(Debug, Clone, Default)]
pub struct AuditContext {
    pub user_id: Option<Uuid>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
}

impl AuditContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_user_id(mut self, user_id: Uuid) -> Self {
        self.user_id = Some(user_id);
        self
    }

    pub fn with_ip_address(mut self, ip_address: String) -> Self {
        self.ip_address = Some(ip_address);
        self
    }

    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }
}

/// Macro for easy audit logging
#[macro_export]
macro_rules! audit_log {
    ($logger:expr, $action:expr, $resource_type:expr, $context:expr) => {
        $logger
            .log(
                $action,
                $resource_type,
                None::<String>,
                $context.user_id,
                None,
                $context.ip_address.clone(),
                $context.user_agent.clone(),
                $context.request_id.clone(),
            )
            .await
    };

    ($logger:expr, $action:expr, $resource_type:expr, $resource_id:expr, $context:expr) => {
        $logger
            .log(
                $action,
                $resource_type,
                Some($resource_id),
                $context.user_id,
                None,
                $context.ip_address.clone(),
                $context.user_agent.clone(),
                $context.request_id.clone(),
            )
            .await
    };

    ($logger:expr, $action:expr, $resource_type:expr, $resource_id:expr, $details:expr, $context:expr) => {
        $logger
            .log(
                $action,
                $resource_type,
                Some($resource_id),
                $context.user_id,
                Some($details),
                $context.ip_address.clone(),
                $context.user_agent.clone(),
                $context.request_id.clone(),
            )
            .await
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;
    use tempfile::{tempdir, TempDir};

    async fn create_test_db() -> (TempDir, Database) {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let database_url = format!("sqlite:{}", db_path.display());

        let db = Database::new(&database_url, 5, 30).await.unwrap();
        let pool = db.pool().clone();

        // Create audit_log table with request_id column
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
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        (temp_dir, db)
    }

    #[tokio::test]
    async fn test_audit_logging() {
        let (_dir, db) = create_test_db().await;
        let logger = AuditLogger::new(db.pool().clone(), true);

        let user_id = Uuid::new_v4();
        let context = AuditContext::new()
            .with_user_id(user_id)
            .with_ip_address("127.0.0.1".to_string())
            .with_request_id("req-123".to_string());

        logger
            .log(
                AuditAction::UserLogin,
                "user",
                Some("user-123"),
                context.user_id,
                Some(serde_json::json!({"success": true})),
                context.ip_address.clone(),
                context.user_agent.clone(),
                context.request_id.clone(),
            )
            .await
            .unwrap();

        let logs = logger
            .get_audit_logs(Some(user_id), None, None, None, None, 10, 0)
            .await
            .unwrap();

        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].action.as_str(), "user_login");
        assert_eq!(logs[0].user_id, Some(user_id));

        db.close().await;
    }

    #[tokio::test]
    async fn test_audit_action_serialization() {
        assert_eq!(AuditAction::UserLogin.as_str(), "user_login");
        assert_eq!(AuditAction::CollectionCreate.as_str(), "collection_create");
        assert_eq!(
            AuditAction::Custom("custom_action".to_string()).as_str(),
            "custom_action"
        );
    }

    #[tokio::test]
    async fn test_audit_log_filtering() {
        let (_dir, db) = create_test_db().await;
        let logger = AuditLogger::new(db.pool().clone(), true);

        let user_a = Uuid::new_v4();
        let user_b = Uuid::new_v4();

        logger
            .log(
                AuditAction::UserLogin,
                "user",
                Some("alice"),
                Some(user_a),
                None,
                Some("127.0.0.1"),
                None::<String>,
                Some("req-a"),
            )
            .await
            .unwrap();

        logger
            .log(
                AuditAction::RecordCreate,
                "record",
                Some("post-1"),
                Some(user_b),
                None,
                Some("127.0.0.1"),
                None::<String>,
                Some("req-b"),
            )
            .await
            .unwrap();

        let user_a_logs = logger
            .get_audit_logs(Some(user_a), None, None, None, None, 10, 0)
            .await
            .unwrap();
        assert_eq!(user_a_logs.len(), 1);
        assert_eq!(user_a_logs[0].action.as_str(), "user_login");

        let record_logs = logger
            .get_audit_logs(
                None,
                Some(AuditAction::RecordCreate),
                None,
                None,
                None,
                10,
                0,
            )
            .await
            .unwrap();
        assert_eq!(record_logs.len(), 1);
        assert_eq!(record_logs[0].resource_type, "record");

        let injection_logs = logger
            .get_audit_logs(
                None,
                None,
                Some("user' OR 1=1 --".to_string()),
                None,
                None,
                10,
                0,
            )
            .await
            .unwrap();
        assert!(injection_logs.is_empty());

        db.close().await;
    }

    #[tokio::test]
    async fn test_audit_log_date_filters() {
        let (_dir, db) = create_test_db().await;
        let logger = AuditLogger::new(db.pool().clone(), true);

        logger
            .log(
                AuditAction::UserLogin,
                "user",
                Some("alice"),
                None,
                None,
                Some("127.0.0.1"),
                None::<String>,
                Some("req-old"),
            )
            .await
            .unwrap();

        logger
            .log(
                AuditAction::RecordCreate,
                "record",
                Some("post-1"),
                None,
                None,
                Some("127.0.0.1"),
                None::<String>,
                Some("req-new"),
            )
            .await
            .unwrap();

        let now = Utc::now();
        let older = now - chrono::Duration::days(7);

        sqlx::query("UPDATE audit_log SET created_at = ? WHERE request_id = ?")
            .bind(older)
            .bind("req-old")
            .execute(db.pool())
            .await
            .unwrap();

        sqlx::query("UPDATE audit_log SET created_at = ? WHERE request_id = ?")
            .bind(now)
            .bind("req-new")
            .execute(db.pool())
            .await
            .unwrap();

        let recent = logger
            .get_audit_logs(
                None,
                None,
                None,
                Some(now - chrono::Duration::days(1)),
                None,
                10,
                0,
            )
            .await
            .unwrap();
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].request_id.as_deref(), Some("req-new"));

        let older_only = logger
            .get_audit_logs(
                None,
                None,
                None,
                None,
                Some(now - chrono::Duration::days(1)),
                10,
                0,
            )
            .await
            .unwrap();
        assert_eq!(older_only.len(), 1);
        assert_eq!(older_only[0].request_id.as_deref(), Some("req-old"));

        db.close().await;
    }
}
