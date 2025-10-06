use crate::{CoreError, CoreResult};
use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite, SqlitePool};
use std::path::Path;
use std::time::Duration;
use tracing::{info, warn};

pub type DatabasePool = Pool<Sqlite>;

pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Create a new database connection pool
    pub async fn new(database_url: &str, max_connections: u32, connection_timeout: u64) -> CoreResult<Self> {
        // Ensure the directory exists for SQLite file
        if database_url.starts_with("sqlite:") {
            let path = database_url.strip_prefix("sqlite:").unwrap_or(database_url);
            if let Some(parent) = Path::new(path).parent() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(Duration::from_secs(connection_timeout))
            .connect(database_url)
            .await?;

        // Enable foreign key constraints and WAL mode for better performance
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await?;
        
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(&pool)
            .await?;

        info!("Database connection established: {}", database_url);

        Ok(Self { pool })
    }

    /// Get a reference to the connection pool
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Run database migrations
    pub async fn migrate(&self) -> CoreResult<()> {
        info!("Running database migrations...");
        
        sqlx::migrate!("../../migrations")
            .run(&self.pool)
            .await?;
        
        info!("Database migrations completed successfully");
        Ok(())
    }

    /// Check if the database is healthy
    pub async fn health_check(&self) -> CoreResult<()> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_database_creation() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let database_url = format!("sqlite:{}", db_path.display());

        let db = Database::new(&database_url, 5, 30).await.unwrap();
        
        // Test health check
        db.health_check().await.unwrap();
        
        db.close().await;
    }

    #[tokio::test]
    async fn test_database_migrations() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_migrate.db");
        let database_url = format!("sqlite:{}", db_path.display());

        let db = Database::new(&database_url, 5, 30).await.unwrap();
        
        // Run migrations
        db.migrate().await.unwrap();
        
        // Verify tables exist
        let result = sqlx::query("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            .fetch_one(db.pool())
            .await;
        
        assert!(result.is_ok());
        
        db.close().await;
    }
}