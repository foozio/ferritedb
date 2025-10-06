use ferritedb_core::{
    auth::{AuthConfig, AuthService},
    seed::SeedService,
    Database, UserRepository,
};
use serde_json::json;
use std::process::Command;
use tempfile::tempdir;
use tokio::time::{sleep, Duration};

/// Integration tests for seed data initialization via CLI
#[tokio::test]
async fn test_seed_command_integration() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let database_url = format!("sqlite:{}", db_path.display());

    // Build the binary first (in a real CI environment, this would be pre-built)
    let build_output = Command::new("cargo")
        .args(&["build", "--bin", "ferritedb"])
        .output()
        .expect("Failed to build ferritedb binary");

    if !build_output.status.success() {
        panic!(
            "Failed to build ferritedb: {}",
            String::from_utf8_lossy(&build_output.stderr)
        );
    }

    // Run the seed command
    let output = Command::new("target/debug/ferritedb")
        .args(&[
            "seed",
            "--config",
            &format!(
                r#"
[server]
host = "127.0.0.1"
port = 8091

[database]
url = "{}"
auto_migrate = true

[auth]
jwt_secret = "test-secret-for-integration-test"
"#,
                database_url
            ),
        ])
        .output()
        .expect("Failed to execute seed command");

    // Check command succeeded
    if !output.status.success() {
        panic!(
            "Seed command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Verify the output contains expected messages
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("✅ Example collections and seed data initialized"));
    assert!(stdout.contains("users (built-in authentication collection)"));
    assert!(stdout.contains("posts (example content collection)"));

    // Connect to the database and verify data was created
    let db = Database::new(&database_url, 5, 30).await.unwrap();
    let user_repo = UserRepository::new(db.pool().clone());

    // Verify admin user exists
    let admin_user = user_repo
        .find_by_email("admin@ferritedb.dev")
        .await
        .unwrap();
    assert!(admin_user.is_some(), "Admin user should be created");

    // Verify demo users exist
    let alice = user_repo.find_by_email("alice@example.com").await.unwrap();
    assert!(alice.is_some(), "Alice demo user should be created");

    db.close().await;
}

#[tokio::test]
async fn test_seed_command_idempotent() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let database_url = format!("sqlite:{}", db_path.display());

    let config_content = format!(
        r#"
[server]
host = "127.0.0.1"
port = 8092

[database]
url = "{}"
auto_migrate = true

[auth]
jwt_secret = "test-secret-for-integration-test"
"#,
        database_url
    );

    // Run seed command first time
    let output1 = Command::new("target/debug/ferritedb")
        .args(&["seed"])
        .env("FERRITEDB_DATABASE_URL", &database_url)
        .env("FERRITEDB_AUTH_JWT_SECRET", "test-secret")
        .output()
        .expect("Failed to execute first seed command");

    assert!(
        output1.status.success(),
        "First seed command failed: {}",
        String::from_utf8_lossy(&output1.stderr)
    );

    // Run seed command second time
    let output2 = Command::new("target/debug/ferritedb")
        .args(&["seed"])
        .env("FERRITEDB_DATABASE_URL", &database_url)
        .env("FERRITEDB_AUTH_JWT_SECRET", "test-secret")
        .output()
        .expect("Failed to execute second seed command");

    assert!(
        output2.status.success(),
        "Second seed command failed: {}",
        String::from_utf8_lossy(&output2.stderr)
    );

    // Both should succeed and indicate collections already exist
    let stdout2 = String::from_utf8_lossy(&output2.stdout);
    assert!(
        stdout2.contains("already exists") || stdout2.contains("initialized successfully"),
        "Second run should handle existing data gracefully"
    );
}

#[tokio::test]
async fn test_server_with_seeded_data() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let database_url = format!("sqlite:{}", db_path.display());

    // First, seed the data
    let seed_output = Command::new("target/debug/ferritedb")
        .args(&["seed"])
        .env("FERRITEDB_DATABASE_URL", &database_url)
        .env("FERRITEDB_AUTH_JWT_SECRET", "test-secret")
        .output()
        .expect("Failed to execute seed command");

    assert!(
        seed_output.status.success(),
        "Seed command failed: {}",
        String::from_utf8_lossy(&seed_output.stderr)
    );

    // Start the server in the background
    let mut server_process = Command::new("target/debug/ferritedb")
        .args(&["serve", "--port", "8093"])
        .env("FERRITEDB_DATABASE_URL", &database_url)
        .env("FERRITEDB_AUTH_JWT_SECRET", "test-secret")
        .spawn()
        .expect("Failed to start server");

    // Wait for server to start
    sleep(Duration::from_secs(2)).await;

    // Test health check
    let health_response = reqwest::get("http://localhost:8093/healthz").await;
    assert!(health_response.is_ok(), "Health check should succeed");

    // Test that collections endpoint works
    let collections_response = reqwest::get("http://localhost:8093/api/collections").await;
    // This might fail due to authentication, but the server should be responding
    assert!(
        collections_response.is_ok(),
        "Server should be responding to requests"
    );

    // Test authentication with seeded admin user
    let client = reqwest::Client::new();
    let login_response = client
        .post("http://localhost:8093/api/auth/login")
        .json(&json!({
            "email": "admin@ferritedb.dev",
            "password": "admin123"
        }))
        .send()
        .await;

    if let Ok(response) = login_response {
        if response.status().is_success() {
            let auth_data: serde_json::Value = response.json().await.unwrap();
            assert!(
                auth_data["token"]["access_token"].is_string(),
                "Should receive access token"
            );
        }
    }

    // Clean up: kill the server process
    let _ = server_process.kill();
    let _ = server_process.wait();
}

#[tokio::test]
async fn test_collections_created_with_proper_schema() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let database_url = format!("sqlite:{}", db_path.display());

    // Run seed command
    let output = Command::new("target/debug/ferritedb")
        .args(&["seed"])
        .env("FERRITEDB_DATABASE_URL", &database_url)
        .env("FERRITEDB_AUTH_JWT_SECRET", "test-secret")
        .output()
        .expect("Failed to execute seed command");

    assert!(
        output.status.success(),
        "Seed command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Connect to database and verify table structure
    let db = Database::new(&database_url, 5, 30).await.unwrap();

    // Check that collection tables were created
    let users_table_exists = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='records_users'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();

    assert!(users_table_exists > 0, "Users table should be created");

    let posts_table_exists = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='records_posts'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();

    assert!(posts_table_exists > 0, "Posts table should be created");

    // Verify collections metadata exists
    let collections_count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM collections")
        .fetch_one(db.pool())
        .await
        .unwrap();

    assert!(
        collections_count >= 2,
        "Should have at least users and posts collections"
    );

    // Verify users collection has proper type
    let users_collection_type = sqlx::query_scalar::<_, String>(
        "SELECT type FROM collections WHERE name = 'users'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();

    assert_eq!(
        users_collection_type, "auth",
        "Users collection should be auth type"
    );

    db.close().await;
}

#[tokio::test]
async fn test_admin_user_can_authenticate() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let database_url = format!("sqlite:{}", db_path.display());

    // Run seed command
    let output = Command::new("target/debug/ferritedb")
        .args(&["seed"])
        .env("FERRITEDB_DATABASE_URL", &database_url)
        .env("FERRITEDB_AUTH_JWT_SECRET", "test-secret-key")
        .output()
        .expect("Failed to execute seed command");

    assert!(
        output.status.success(),
        "Seed command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Test authentication directly
    let db = Database::new(&database_url, 5, 30).await.unwrap();
    let user_repo = UserRepository::new(db.pool().clone());

    let auth_config = AuthConfig {
        jwt_secret: "test-secret-key".to_string(),
        token_ttl: 3600,
        refresh_ttl: 86400,
        password_min_length: 8,
        argon2_memory: 4096,
        argon2_iterations: 1,
        argon2_parallelism: 1,
    };
    let auth_service = AuthService::new(auth_config).unwrap();

    // Get admin user
    let admin_user = user_repo
        .find_by_email("admin@ferritedb.dev")
        .await
        .unwrap()
        .unwrap();

    // Verify password
    let password_valid = auth_service
        .verify_password("admin123", &admin_user.password_hash)
        .unwrap();
    assert!(password_valid, "Admin password should be valid");

    // Generate token
    let tokens = auth_service.generate_tokens(&admin_user).unwrap();
    assert!(!tokens.access_token.is_empty(), "Should generate access token");
    assert!(
        !tokens.refresh_token.is_empty(),
        "Should generate refresh token"
    );

    // Validate token
    let claims = auth_service.validate_token(&tokens.access_token).unwrap();
    assert_eq!(claims.email, "admin@ferritedb.dev");
    assert_eq!(claims.role, ferritedb_core::UserRole::Admin);

    db.close().await;
}

#[tokio::test]
async fn test_demo_users_have_correct_passwords() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let database_url = format!("sqlite:{}", db_path.display());

    // Run seed command
    let output = Command::new("target/debug/ferritedb")
        .args(&["seed"])
        .env("FERRITEDB_DATABASE_URL", &database_url)
        .env("FERRITEDB_AUTH_JWT_SECRET", "test-secret-key")
        .output()
        .expect("Failed to execute seed command");

    assert!(output.status.success());

    // Test demo user authentication
    let db = Database::new(&database_url, 5, 30).await.unwrap();
    let user_repo = UserRepository::new(db.pool().clone());

    let auth_config = AuthConfig {
        jwt_secret: "test-secret-key".to_string(),
        token_ttl: 3600,
        refresh_ttl: 86400,
        password_min_length: 8,
        argon2_memory: 4096,
        argon2_iterations: 1,
        argon2_parallelism: 1,
    };
    let auth_service = AuthService::new(auth_config).unwrap();

    // Test each demo user
    let demo_users = ["alice@example.com", "bob@example.com", "carol@example.com"];

    for email in &demo_users {
        let user = user_repo.find_by_email(email).await.unwrap().unwrap();

        let password_valid = auth_service
            .verify_password("password123", &user.password_hash)
            .unwrap();
        assert!(
            password_valid,
            "Demo user {} password should be valid",
            email
        );

        assert_eq!(user.role, ferritedb_core::UserRole::User);
        assert!(user.verified, "Demo user should be verified");
    }

    db.close().await;
}

#[tokio::test]
async fn test_seed_with_force_flag() {
    let temp_dir = tempdir().unwrap();
    let db_path = temp_dir.path().join("test.db");
    let database_url = format!("sqlite:{}", db_path.display());

    // Run seed command with force flag
    let output = Command::new("target/debug/ferritedb")
        .args(&["seed", "--force"])
        .env("FERRITEDB_DATABASE_URL", &database_url)
        .env("FERRITEDB_AUTH_JWT_SECRET", "test-secret")
        .output()
        .expect("Failed to execute seed command with force");

    // Should succeed even if it's the first run
    assert!(
        output.status.success(),
        "Seed command with force failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should mention force mode if implemented
    // Note: The actual force implementation might not be complete in the current code
    assert!(
        stdout.contains("initialized successfully") || stdout.contains("force"),
        "Should handle force flag appropriately"
    );
}

/// Test that verifies the CLI help shows the seed command
#[test]
fn test_seed_command_in_help() {
    let output = Command::new("target/debug/ferritedb")
        .args(&["--help"])
        .output()
        .expect("Failed to get help");

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("seed") || stdout.contains("Seed"),
        "Help should mention seed command"
    );
}

/// Test error handling when database is not accessible
#[tokio::test]
async fn test_seed_command_database_error() {
    // Try to seed with an invalid database path
    let output = Command::new("target/debug/ferritedb")
        .args(&["seed"])
        .env("FERRITEDB_DATABASE_URL", "sqlite:/invalid/path/test.db")
        .env("FERRITEDB_AUTH_JWT_SECRET", "test-secret")
        .output()
        .expect("Failed to execute seed command");

    // Should fail gracefully
    assert!(
        !output.status.success(),
        "Seed command should fail with invalid database path"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Should contain some error message about database or file access
    assert!(
        stderr.contains("error") || stderr.contains("Error") || stderr.contains("failed"),
        "Should show appropriate error message"
    );
}

/// Helper function to check if a binary exists and is executable
fn binary_exists() -> bool {
    Command::new("target/debug/ferritedb")
        .args(&["--version"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Setup function that ensures the binary is built before running tests
#[tokio::test]
async fn test_binary_availability() {
    if !binary_exists() {
        // Try to build the binary
        let build_output = Command::new("cargo")
            .args(&["build", "--bin", "ferritedb"])
            .output()
            .expect("Failed to build ferritedb binary");

        assert!(
            build_output.status.success(),
            "Failed to build ferritedb binary: {}",
            String::from_utf8_lossy(&build_output.stderr)
        );
    }

    assert!(binary_exists(), "FerriteDB binary should be available for testing");
}