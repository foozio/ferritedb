use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CoreConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub features: FeatureFlags,
    #[serde(default)]
    pub telemetry: TelemetryConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub cors_origins: Vec<String>,
    pub rate_limit: RateLimitConfig,
    pub request_timeout: u64,
    pub max_request_size: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8090,
            cors_origins: vec!["*".to_string()],
            rate_limit: RateLimitConfig::default(),
            request_timeout: 30,
            max_request_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    pub requests_per_minute: u32,
    pub burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_minute: 60,
            burst_size: 10,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub connection_timeout: u64,
    pub auto_migrate: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: "sqlite:data/ferritedb.db".to_string(),
            max_connections: 10,
            connection_timeout: 30,
            auto_migrate: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub token_ttl: u64,
    pub refresh_ttl: u64,
    pub password_min_length: usize,
    pub argon2_memory: u32,
    pub argon2_iterations: u32,
    pub argon2_parallelism: u32,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "your-secret-key-change-in-production".to_string(),
            token_ttl: 900,     // 15 minutes
            refresh_ttl: 86400, // 24 hours
            password_min_length: 8,
            argon2_memory: 65536, // 64MB
            argon2_iterations: 3,
            argon2_parallelism: 4,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StorageConfig {
    pub backend: StorageBackend,
    pub local: LocalStorageConfig,
    #[cfg(feature = "s3")]
    pub s3: S3StorageConfig,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: StorageBackend::Local,
            local: LocalStorageConfig::default(),
            #[cfg(feature = "s3")]
            s3: S3StorageConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum StorageBackend {
    Local,
    #[cfg(feature = "s3")]
    S3,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LocalStorageConfig {
    pub base_path: PathBuf,
    pub max_file_size: u64,
}

impl Default for LocalStorageConfig {
    fn default() -> Self {
        Self {
            base_path: PathBuf::from("data/storage"),
            max_file_size: 50 * 1024 * 1024, // 50MB
        }
    }
}

#[cfg(feature = "s3")]
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct S3StorageConfig {
    pub bucket: String,
    pub region: String,
    pub access_key_id: Option<String>,
    pub secret_access_key: Option<String>,
    pub endpoint: Option<String>,
}

#[cfg(feature = "s3")]
impl Default for S3StorageConfig {
    fn default() -> Self {
        Self {
            bucket: "ferritedb-files".to_string(),
            region: "us-east-1".to_string(),
            access_key_id: None,
            secret_access_key: None,
            endpoint: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct FeatureFlags {
    #[cfg(feature = "oauth2")]
    pub oauth2: bool,
    #[cfg(feature = "s3")]
    pub s3_storage: bool,
    #[cfg(feature = "image-transforms")]
    pub image_transforms: bool,
    pub multi_tenant: bool,
    pub full_text_search: bool,
    pub metrics: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TelemetryConfig {
    pub log_level: String,
    pub log_format: String,
    pub metrics_enabled: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            log_level: "info".to_string(),
            log_format: "plain".to_string(),
            metrics_enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_telemetry_config_default() {
        let config = TelemetryConfig::default();
        assert_eq!(config.log_level, "info");
        assert_eq!(config.log_format, "plain");
        assert!(config.metrics_enabled);
    }

    #[test]
    fn test_core_config_with_telemetry() {
        let toml_str = r#"
            [server]
            host = "127.0.0.1"
            port = 8080
            cors_origins = ["*"]
            request_timeout = 30
            max_request_size = 1048576

            [server.rate_limit]
            requests_per_minute = 60
            burst_size = 10

            [database]
            url = "sqlite:test.db"
            max_connections = 5
            connection_timeout = 30
            auto_migrate = true

            [auth]
            jwt_secret = "secret"
            token_ttl = 900
            refresh_ttl = 86400
            password_min_length = 8
            argon2_memory = 4096
            argon2_iterations = 1
            argon2_parallelism = 1

            [storage]
            backend = "Local"

            [storage.local]
            base_path = "data"
            max_file_size = 1024

            [features]
            metrics = true
            multi_tenant = false
            full_text_search = false

            [telemetry]
            log_level = "debug"
            log_format = "json"
            metrics_enabled = false
        "#;

        let config: CoreConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.telemetry.log_level, "debug");
        assert_eq!(config.telemetry.log_format, "json");
        assert!(!config.telemetry.metrics_enabled);
    }
}