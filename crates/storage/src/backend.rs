use crate::StorageResult;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageMetadata {
    pub size: u64,
    pub content_type: Option<String>,
    pub etag: Option<String>,
}

#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn store(&self, path: &str, data: &[u8]) -> StorageResult<StorageMetadata>;
    async fn retrieve(&self, path: &str) -> StorageResult<Vec<u8>>;
    async fn delete(&self, path: &str) -> StorageResult<()>;
    async fn exists(&self, path: &str) -> StorageResult<bool>;
    async fn generate_url(&self, path: &str, expires_in: Duration) -> StorageResult<String>;
}