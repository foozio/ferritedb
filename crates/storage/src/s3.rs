use crate::{StorageBackend, StorageError, StorageMetadata, StorageResult};
use async_trait::async_trait;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::Client;
use std::time::Duration;
use tracing::{debug, error};

pub struct S3Storage {
    client: Client,
    bucket: String,
    region: String,
}

impl S3Storage {
    pub fn new(client: Client, bucket: String, region: String) -> Self {
        debug!(
            "Initializing S3 storage client for bucket '{}' in region '{}'",
            bucket, region
        );

        Self {
            client,
            bucket,
            region,
        }
    }

    /// Validate and sanitize the S3 object key
    fn validate_key(&self, path: &str) -> StorageResult<String> {
        // Remove leading slashes and normalize
        let clean_path = path.trim_start_matches('/');
        
        // Check for invalid characters or patterns
        if clean_path.is_empty() {
            return Err(StorageError::InvalidPath("Empty path".to_string()));
        }
        
        if clean_path.contains("..") {
            return Err(StorageError::InvalidPath(format!(
                "Path contains invalid sequences: {}", path
            )));
        }
        
        // S3 object keys should not start with a slash
        Ok(clean_path.to_string())
    }

    /// Detect content type from file extension
    fn detect_content_type(&self, path: &str) -> Option<String> {
        let extension = std::path::Path::new(path)
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase());

        match extension.as_deref() {
            Some("jpg") | Some("jpeg") => Some("image/jpeg".to_string()),
            Some("png") => Some("image/png".to_string()),
            Some("gif") => Some("image/gif".to_string()),
            Some("webp") => Some("image/webp".to_string()),
            Some("pdf") => Some("application/pdf".to_string()),
            Some("txt") => Some("text/plain".to_string()),
            Some("json") => Some("application/json".to_string()),
            Some("xml") => Some("application/xml".to_string()),
            Some("csv") => Some("text/csv".to_string()),
            Some("mp4") => Some("video/mp4".to_string()),
            Some("mp3") => Some("audio/mpeg".to_string()),
            Some("zip") => Some("application/zip".to_string()),
            _ => Some("application/octet-stream".to_string()),
        }
    }
}

#[async_trait]
impl StorageBackend for S3Storage {
    async fn store(&self, path: &str, data: &[u8]) -> StorageResult<StorageMetadata> {
        let key = self.validate_key(path)?;
        let content_type = self.detect_content_type(path);
        
        debug!(
            "Storing object in S3: bucket={}, region={}, key={}",
            self.bucket, self.region, key
        );
        
        let mut put_request = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(ByteStream::from(data.to_vec()));
        
        if let Some(ct) = &content_type {
            put_request = put_request.content_type(ct);
        }
        
        let result = put_request.send().await.map_err(|e| {
            error!("Failed to store object in S3: {}", e);
            StorageError::Backend(format!("S3 put_object failed: {}", e))
        })?;
        
        debug!("Stored object in S3: {} bytes, etag: {:?}", data.len(), result.e_tag());
        
        Ok(StorageMetadata {
            size: data.len() as u64,
            content_type,
            etag: result.e_tag().map(|s| s.to_string()),
        })
    }

    async fn retrieve(&self, path: &str) -> StorageResult<Vec<u8>> {
        let key = self.validate_key(path)?;
        
        debug!(
            "Retrieving object from S3: bucket={}, region={}, key={}",
            self.bucket, self.region, key
        );
        
        let result = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| {
                if e.to_string().contains("NoSuchKey") {
                    StorageError::NotFound(path.to_string())
                } else {
                    error!("Failed to retrieve object from S3: {}", e);
                    StorageError::Backend(format!("S3 get_object failed: {}", e))
                }
            })?;
        
        let data = result
            .body
            .collect()
            .await
            .map_err(|e| {
                error!("Failed to read S3 object body: {}", e);
                StorageError::Backend(format!("Failed to read S3 body: {}", e))
            })?
            .into_bytes()
            .to_vec();
        
        debug!("Retrieved object from S3: {} bytes", data.len());
        Ok(data)
    }

    async fn delete(&self, path: &str) -> StorageResult<()> {
        let key = self.validate_key(path)?;
        
        debug!("Deleting object from S3: bucket={}, key={}", self.bucket, key);
        
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| {
                error!("Failed to delete object from S3: {}", e);
                StorageError::Backend(format!("S3 delete_object failed: {}", e))
            })?;
        
        debug!("Deleted object from S3: {}", key);
        Ok(())
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        let key = self.validate_key(path)?;
        
        debug!("Checking if object exists in S3: bucket={}, key={}", self.bucket, key);
        
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(_) => {
                debug!("Object exists in S3: {}", key);
                Ok(true)
            }
            Err(e) => {
                if e.to_string().contains("NotFound") {
                    debug!("Object does not exist in S3: {}", key);
                    Ok(false)
                } else {
                    error!("Failed to check object existence in S3: {}", e);
                    Err(StorageError::Backend(format!("S3 head_object failed: {}", e)))
                }
            }
        }
    }

    async fn generate_url(&self, path: &str, expires_in: Duration) -> StorageResult<String> {
        let key = self.validate_key(path)?;
        
        debug!("Generating presigned URL for S3 object: bucket={}, key={}, expires_in={:?}", 
               self.bucket, key, expires_in);
        
        let presigning_config = aws_sdk_s3::presigning::PresigningConfig::expires_in(expires_in)
            .map_err(|e| {
                error!("Failed to create presigning config: {}", e);
                StorageError::Backend(format!("Invalid presigning duration: {}", e))
            })?;
        
        let presigned_request = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .presigned(presigning_config)
            .await
            .map_err(|e| {
                error!("Failed to generate presigned URL: {}", e);
                StorageError::Backend(format!("S3 presigning failed: {}", e))
            })?;
        
        let url = presigned_request.uri().to_string();
        debug!("Generated presigned URL: {}", url);
        
        Ok(url)
    }
}
