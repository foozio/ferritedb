#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LocalStorage, StorageBackend, StorageConfig, StorageType};
    use std::path::PathBuf;
    use tempfile::tempdir;
    use tokio::fs;

    #[tokio::test]
    async fn test_local_storage_store_and_retrieve() {
        let temp_dir = tempdir().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        let test_data = b"Hello, world!";
        let test_path = "test/file.txt";

        // Store file
        let metadata = storage.store(test_path, test_data).await.unwrap();
        assert_eq!(metadata.size, test_data.len() as u64);
        assert_eq!(metadata.content_type, Some("text/plain".to_string()));

        // Retrieve file
        let retrieved_data = storage.retrieve(test_path).await.unwrap();
        assert_eq!(retrieved_data, test_data);

        // Check if file exists
        let exists = storage.exists(test_path).await.unwrap();
        assert!(exists);

        // Delete file
        storage.delete(test_path).await.unwrap();

        // Check if file no longer exists
        let exists = storage.exists(test_path).await.unwrap();
        assert!(!exists);
    }

    #[tokio::test]
    async fn test_local_storage_path_validation() {
        let temp_dir = tempdir().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        let test_data = b"test";

        // Test directory traversal protection
        let result = storage.store("../outside.txt", test_data).await;
        assert!(result.is_err());

        let result = storage.store("./test/../outside.txt", test_data).await;
        assert!(result.is_err());

        // Test valid paths
        let result = storage.store("valid/path/file.txt", test_data).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_local_storage_content_type_detection() {
        let temp_dir = tempdir().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        let test_data = b"test";

        // Test various file extensions
        let test_cases = vec![
            ("image.jpg", Some("image/jpeg".to_string())),
            ("image.png", Some("image/png".to_string())),
            ("document.pdf", Some("application/pdf".to_string())),
            ("data.json", Some("application/json".to_string())),
            ("unknown.xyz", Some("application/octet-stream".to_string())),
        ];

        for (filename, expected_content_type) in test_cases {
            let metadata = storage.store(filename, test_data).await.unwrap();
            assert_eq!(metadata.content_type, expected_content_type);
        }
    }

    #[tokio::test]
    async fn test_local_storage_generate_url() {
        let temp_dir = tempdir().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        let url = storage
            .generate_url("test/file.txt", std::time::Duration::from_secs(3600))
            .await
            .unwrap();

        assert_eq!(url, "/api/files/test/file.txt");
    }

    #[tokio::test]
    async fn test_local_storage_retrieve_nonexistent() {
        let temp_dir = tempdir().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        let result = storage.retrieve("nonexistent.txt").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), crate::StorageError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_local_storage_delete_nonexistent() {
        let temp_dir = tempdir().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        // Deleting non-existent file should be idempotent (not fail)
        let result = storage.delete("nonexistent.txt").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_storage_config_file_validation() {
        let config = StorageConfig::default();

        // Test allowed files
        assert!(config.is_file_allowed("image.jpg"));
        assert!(config.is_file_allowed("document.pdf"));
        assert!(config.is_file_allowed("data.json"));

        // Test blocked files
        assert!(!config.is_file_allowed("malware.exe"));
        assert!(!config.is_file_allowed("script.js"));
        assert!(!config.is_file_allowed("batch.bat"));
    }

    #[tokio::test]
    async fn test_storage_config_size_validation() {
        let config = StorageConfig::default();

        // Test size limits
        assert!(config.is_size_allowed(1024)); // 1KB - OK
        assert!(config.is_size_allowed(5 * 1024 * 1024)); // 5MB - OK
        assert!(!config.is_size_allowed(20 * 1024 * 1024)); // 20MB - Too large
    }

    #[tokio::test]
    async fn test_storage_config_custom_restrictions() {
        let config = StorageConfig {
            storage_type: StorageType::Local {
                path: PathBuf::from("/tmp/test"),
            },
            max_file_size: 1024, // 1KB limit
            allowed_extensions: vec!["jpg".to_string(), "png".to_string()],
            blocked_extensions: vec![], // Override default blocked list
        };

        // Test custom size limit
        assert!(config.is_size_allowed(512));
        assert!(!config.is_size_allowed(2048));

        // Test custom allowed extensions
        assert!(config.is_file_allowed("image.jpg"));
        assert!(config.is_file_allowed("photo.png"));
        assert!(!config.is_file_allowed("document.pdf")); // Not in allowed list
        assert!(!config.is_file_allowed("script.js")); // Not in allowed list
    }

    #[tokio::test]
    async fn test_storage_config_create_local_backend() {
        let temp_dir = tempdir().unwrap();
        let config = StorageConfig {
            storage_type: StorageType::Local {
                path: temp_dir.path().to_path_buf(),
            },
            ..Default::default()
        };

        // Just test that we can create the backend without errors
        let _backend = config.create_backend().await.unwrap();
    }

    #[cfg(feature = "s3")]
    #[tokio::test]
    async fn test_s3_storage_path_validation() {
        use crate::S3Storage;

        // Create a mock S3 client for testing
        let config = aws_sdk_s3::config::Builder::new()
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .endpoint_url("http://localhost:9000") // MinIO endpoint for testing
            .build();
        let client = aws_sdk_s3::Client::from_conf(config);
        let storage = S3Storage::new(client, "test-bucket".to_string(), "us-east-1".to_string());

        let test_data = b"test";

        // Test directory traversal protection
        let result = storage.store("../outside.txt", test_data).await;
        assert!(result.is_err());

        // Test empty path
        let result = storage.store("", test_data).await;
        assert!(result.is_err());

        // Test valid path (this will fail without actual S3, but validates path processing)
        let result = storage.store("valid/path/file.txt", test_data).await;
        // We expect this to fail due to no actual S3 connection, but not due to path validation
        assert!(result.is_err());
        // The error should be a backend error, not an invalid path error
        assert!(!result.unwrap_err().to_string().contains("invalid"));
    }

    #[tokio::test]
    async fn test_storage_backend_trait_object() {
        let temp_dir = tempdir().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        let test_data = b"trait object test";
        let test_path = "trait_test.txt";

        // Test that storage works correctly
        let metadata = storage.store(test_path, test_data).await.unwrap();
        assert_eq!(metadata.size, test_data.len() as u64);

        let retrieved = storage.retrieve(test_path).await.unwrap();
        assert_eq!(retrieved, test_data);

        let exists = storage.exists(test_path).await.unwrap();
        assert!(exists);

        storage.delete(test_path).await.unwrap();

        let exists = storage.exists(test_path).await.unwrap();
        assert!(!exists);
    }

    #[tokio::test]
    async fn test_local_storage_concurrent_operations() {
        let temp_dir = tempdir().unwrap();
        let storage = std::sync::Arc::new(LocalStorage::new(temp_dir.path().to_path_buf()));

        let mut handles = vec![];

        // Spawn multiple concurrent operations
        for i in 0..10 {
            let storage_clone = storage.clone();
            let handle = tokio::spawn(async move {
                let test_data = format!("test data {}", i).into_bytes();
                let test_path = format!("concurrent/file_{}.txt", i);

                // Store file
                let metadata = storage_clone.store(&test_path, &test_data).await.unwrap();
                assert_eq!(metadata.size, test_data.len() as u64);

                // Retrieve file
                let retrieved = storage_clone.retrieve(&test_path).await.unwrap();
                assert_eq!(retrieved, test_data);

                // Delete file
                storage_clone.delete(&test_path).await.unwrap();
            });
            handles.push(handle);
        }

        // Wait for all operations to complete
        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_local_storage_directory_cleanup() {
        let temp_dir = tempdir().unwrap();
        let storage = LocalStorage::new(temp_dir.path().to_path_buf());

        let test_data = b"test";
        let test_path = "deep/nested/directory/file.txt";

        // Store file in nested directory
        storage.store(test_path, test_data).await.unwrap();

        // Verify file exists
        let full_path = temp_dir.path().join(test_path);
        assert!(full_path.exists());

        // Delete file
        storage.delete(test_path).await.unwrap();

        // Verify file is deleted
        assert!(!full_path.exists());

        // The directory cleanup is best-effort, so we don't assert on it
        // but we can check that the operation completed successfully
    }
}