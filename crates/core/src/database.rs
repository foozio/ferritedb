use crate::CoreResult;
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
    Pool, Sqlite, SqlitePool,
};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use tracing::info;

pub type DatabasePool = Pool<Sqlite>;

pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Create a new database connection pool
    pub async fn new(
        database_url: &str,
        max_connections: u32,
        connection_timeout: u64,
    ) -> CoreResult<Self> {
        // Ensure the directory exists for SQLite file
        if database_url.starts_with("sqlite:") {
            let path = database_url.strip_prefix("sqlite:").unwrap_or(database_url);
            if let Some(parent) = Path::new(path).parent() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let connect_options = SqliteConnectOptions::from_str(database_url)?
            .create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal);

        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(connection_timeout))
            .connect_with(connect_options)
            .await?;

        info!(
            "Database connection established: {}",
            mask_password_in_uri(database_url)
        );

        Ok(Self { pool })
    }

    /// Get a reference to the connection pool
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Run database migrations
    pub async fn migrate(&self) -> CoreResult<()> {
        info!("Running database migrations...");

        sqlx::migrate!("../../migrations").run(&self.pool).await?;

        info!("Database migrations completed successfully");
        Ok(())
    }

    /// Check if the database is healthy
    pub async fn health_check(&self) -> CoreResult<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    /// Close the database connection pool
    pub async fn close(self) {
        self.pool.close().await;
        info!("Database connection pool closed");
    }
}

impl Clone for Database {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
        }
    }
}

/// Replace any password present in the authority section of a URI with a mask.
fn mask_password_in_uri(uri: &str) -> String {
    const MASK: &str = "****";

    if let Some(scheme_end) = uri.find("://") {
        let user_info_start = scheme_end + 3;

        if user_info_start < uri.len() {
            if let Some(at_rel) = uri[user_info_start..].find('@') {
                let at_index = user_info_start + at_rel;
                if let Some(colon_rel) = uri[user_info_start..at_index].find(':') {
                    let colon_index = user_info_start + colon_rel;

                    let mut masked = String::with_capacity(uri.len());
                    masked.push_str(&uri[..colon_index + 1]);
                    masked.push_str(MASK);
                    masked.push_str(&uri[at_index..]);
                    return masked;
                }
            }
        }
    }

    uri.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_database_creation() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let database_url = format!("sqlite:{}", db_path.display());

        let db = Database::new(&database_url, 5, 30).await.unwrap();

        // Test health check
        db.health_check().await.unwrap();

        db.close().await;
    }

    #[tokio::test]
    async fn test_database_migrations() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("test_migrate.db");
        let database_url = format!("sqlite:{}", db_path.display());

        let db = Database::new(&database_url, 5, 30).await.unwrap();

        // Run migrations
        db.migrate().await.unwrap();

        // Verify tables exist
        let result =
            sqlx::query("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
                .fetch_one(db.pool())
                .await;

        assert!(result.is_ok());

        db.close().await;
    }

    #[test]
    fn test_mask_password_in_uri_with_credentials() {
        let uri = "postgresql://user:supersecret@localhost:5432/db";
        let masked = super::mask_password_in_uri(uri);
        assert_eq!(masked, "postgresql://user:****@localhost:5432/db");
    }

    #[test]
    fn test_mask_password_in_uri_without_password() {
        let uri = "postgresql://user@localhost/db";
        let masked = super::mask_password_in_uri(uri);
        assert_eq!(masked, uri);
    }

    #[test]
    fn test_mask_password_in_uri_sqlite() {
        let uri = "sqlite:data/ferritedb.db";
        let masked = super::mask_password_in_uri(uri);
        assert_eq!(masked, uri);
    }
}
