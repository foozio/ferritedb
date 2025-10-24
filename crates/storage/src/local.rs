use crate::{StorageBackend, StorageError, StorageMetadata, StorageResult};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::fs;
use tracing::{debug, warn};

pub struct LocalStorage {
    base_path: PathBuf,
}

impl LocalStorage {
    pub fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    /// Validate and sanitize the storage path to prevent directory traversal
    fn validate_path(&self, path: &str) -> StorageResult<PathBuf> {
        // Remove any leading slashes and normalize the path
        let clean_path = path.trim_start_matches('/');

        // Check for directory traversal attempts
        if clean_path.contains("..") || clean_path.contains("./") {
            return Err(StorageError::InvalidPath(format!(
                "Path contains invalid sequences: {}",
                path
            )));
        }

        // Build the full path
        let full_path = self.base_path.join(clean_path);

        // Ensure the path is within our base directory
        if !full_path.starts_with(&self.base_path) {
            return Err(StorageError::InvalidPath(format!(
                "Path outside base directory: {}",
                path
            )));
        }

        Ok(full_path)
    }

    /// Ensure the parent directory exists
    async fn ensure_parent_dir(&self, file_path: &Path) -> StorageResult<()> {
        if let Some(parent) = file_path.parent() {
            if !parent.exists() {
                debug!("Creating directory: {:?}", parent);
                fs::create_dir_all(parent).await?;
            }
        }
        Ok(())
    }

    /// Detect content type from file extension
    fn detect_content_type(&self, path: &str) -> Option<String> {
        let extension = Path::new(path)
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
impl StorageBackend for LocalStorage {
    async fn store(&self, path: &str, data: &[u8]) -> StorageResult<StorageMetadata> {
        let file_path = self.validate_path(path)?;

        debug!("Storing file at: {:?}", file_path);

        // Ensure parent directory exists
        self.ensure_parent_dir(&file_path).await?;

        // Write the file
        fs::write(&file_path, data).await?;

        // Get file metadata
        let metadata = fs::metadata(&file_path).await?;
        let content_type = self.detect_content_type(path);

        debug!(
            "Stored file: {} bytes, content-type: {:?}",
            metadata.len(),
            content_type
        );

        Ok(StorageMetadata {
            size: metadata.len(),
            content_type,
            etag: None, // Local storage doesn't generate ETags
        })
    }

    async fn retrieve(&self, path: &str) -> StorageResult<Vec<u8>> {
        let file_path = self.validate_path(path)?;

        debug!("Retrieving file from: {:?}", file_path);

        if !file_path.exists() {
            return Err(StorageError::NotFound(path.to_string()));
        }

        let data = fs::read(&file_path).await?;
        debug!("Retrieved file: {} bytes", data.len());

        Ok(data)
    }

    async fn delete(&self, path: &str) -> StorageResult<()> {
        let file_path = self.validate_path(path)?;

        debug!("Deleting file at: {:?}", file_path);

        if !file_path.exists() {
            warn!("Attempted to delete non-existent file: {}", path);
            return Ok(()); // Idempotent operation
        }

        fs::remove_file(&file_path).await?;
        debug!("Deleted file: {:?}", file_path);

        // Try to remove empty parent directories (best effort)
        if let Some(parent) = file_path.parent() {
            if parent != self.base_path {
                if let Ok(mut entries) = fs::read_dir(parent).await {
                    if entries.next_entry().await?.is_none() {
                        // Directory is empty, try to remove it
                        if let Err(e) = fs::remove_dir(parent).await {
                            debug!("Could not remove empty directory {:?}: {}", parent, e);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        let file_path = self.validate_path(path)?;
        Ok(file_path.exists())
    }

    async fn generate_url(&self, path: &str, _expires_in: Duration) -> StorageResult<String> {
        // For local storage, we return a relative URL that the server can handle
        // The actual serving will be handled by the web server
        let clean_path = path.trim_start_matches('/');
        Ok(format!("/api/files/{}", clean_path))
    }
}
