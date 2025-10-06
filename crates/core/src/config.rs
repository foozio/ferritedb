use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CoreConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub storage: StorageConfig,
    pub features: FeatureFlags,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            database: DatabaseConfig::default(),
            auth: AuthConfig::default(),
            storage: StorageConfig::default(),
            features: FeatureFlags::default(),
        }
    }
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
            argon2_memory: 65536,    // 64MB
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
            bucket: "rustbase-files".to_string(),
            region: "us-east-1".to_string(),
            access_key_id: None,
            secret_access_key: None,
            endpoint: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
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

impl Default for FeatureFlags {
    fn default() -> Self {
        Self {
            #[cfg(feature = "oauth2")]
            oauth2: false,
            #[cfg(feature = "s3")]
            s3_storage: false,
            #[cfg(feature = "image-transforms")]
            image_transforms: false,
            multi_tenant: false,
            full_text_search: false,
            metrics: false,
        }
    }
}