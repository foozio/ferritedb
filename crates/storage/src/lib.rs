pub mod backend;
pub mod config;
pub mod error;
pub mod local;

#[cfg(feature = "s3")]
pub mod s3;

#[cfg(feature = "image-transforms")]
pub mod transforms;

#[cfg(test)]
mod tests;

pub use backend::{StorageBackend, StorageMetadata};
pub use config::{StorageConfig, StorageType};
pub use error::{StorageError, StorageResult};
pub use local::LocalStorage;

#[cfg(feature = "s3")]
pub use s3::S3Storage;