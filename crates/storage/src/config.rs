use crate::{LocalStorage, StorageBackend, StorageError, StorageResult};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(feature = "s3")]
use crate::S3Storage;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum StorageType {
    Local {
        path: PathBuf,
    },
    #[cfg(feature = "s3")]
    S3 {
        bucket: String,
        region: String,
        access_key_id: Option<String>,
        secret_access_key: Option<String>,
        endpoint: Option<String>,
    },
}

impl Default for StorageType {
    fn default() -> Self {
        Self::Local {
            path: PathBuf::from("data/storage"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(flatten)]
    pub storage_type: StorageType,
    
    /// Maximum file size in bytes (default: 10MB)
    pub max_file_size: u64,
    
    /// Allowed file extensions (empty means all allowed)
    pub allowed_extensions: Vec<String>,
    
    /// Blocked file extensions for security
    pub blocked_extensions: Vec<String>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            storage_type: StorageType::default(),
            max_file_size: 10 * 1024 * 1024, // 10MB
            allowed_extensions: vec![],
            blocked_extensions: vec![
                "exe".to_string(),
                "bat".to_string(),
                "cmd".to_string(),
                "com".to_string(),
                "pif".to_string(),
                "scr".to_string(),
                "vbs".to_string(),
                "js".to_string(),
                "jar".to_string(),
            ],
        }
    }
}

impl StorageConfig {
    /// Create a storage backend from the configuration
    pub async fn create_backend(&self) -> StorageResult<Arc<dyn StorageBackend>> {
        match &self.storage_type {
            StorageType::Local { path } => {
                // Ensure the storage directory exists
                if !path.exists() {
                    tokio::fs::create_dir_all(path).await.map_err(|e| {
                        StorageError::Backend(format!("Failed to create storage directory: {}", e))
                    })?;
                }
                
                Ok(Arc::new(LocalStorage::new(path.clone())))
            }
            
            #[cfg(feature = "s3")]
            StorageType::S3 {
                bucket,
                region,
                access_key_id,
                secret_access_key,
                endpoint,
            } => {
                let mut config_builder = aws_sdk_s3::config::Builder::new()
                    .region(aws_sdk_s3::config::Region::new(region.clone()));
                
                // Set custom endpoint if provided (for S3-compatible services like R2)
                if let Some(endpoint_url) = endpoint {
                    config_builder = config_builder.endpoint_url(endpoint_url);
                }
                
                // Set credentials if provided
                if let (Some(access_key), Some(secret_key)) = (access_key_id, secret_access_key) {
                    let credentials = aws_sdk_s3::config::Credentials::new(
                        access_key,
                        secret_key,
                        None,
                        None,
                        "rustbase-config",
                    );
                    config_builder = config_builder.credentials_provider(credentials);
                }
                
                let config = config_builder.build();
                let client = aws_sdk_s3::Client::from_conf(config);
                
                Ok(Arc::new(S3Storage::new(
                    client,
                    bucket.clone(),
                    region.clone(),
                )))
            }
        }
    }
    
    /// Validate file extension against allowed/blocked lists
    pub fn is_file_allowed(&self, filename: &str) -> bool {
        let extension = std::path::Path::new(filename)
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase());
        
        if let Some(ext) = extension {
            // Check blocked extensions first
            if self.blocked_extensions.contains(&ext) {
                return false;
            }
            
            // If allowed extensions is empty, allow all (except blocked)
            if self.allowed_extensions.is_empty() {
                return true;
            }
            
            // Check if extension is in allowed list
            self.allowed_extensions.contains(&ext)
        } else {
            // Files without extensions are allowed if no restrictions
            self.allowed_extensions.is_empty()
        }
    }
    
    /// Check if file size is within limits
    pub fn is_size_allowed(&self, size: u64) -> bool {
        size <= self.max_file_size
    }
}