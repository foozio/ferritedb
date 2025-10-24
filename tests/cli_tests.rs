use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::{tempdir, TempDir};

/// Helper function to get the path to the ferritedb binary
fn ferritedb_binary() -> PathBuf {
    let mut path = env::current_exe().unwrap();
    path.pop(); // Remove test binary name
    if path.ends_with("deps") {
        path.pop(); // Remove deps directory
    }
    path.push("ferritedb");
    path
}

const CLI_TEST_ENV: &str = "RUN_CLI_INTEGRATION_TESTS";

struct TempTestDir {
    _dir: TempDir,
    path: PathBuf,
}

impl TempTestDir {
    fn new() -> Self {
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().to_path_buf();
        Self { _dir: dir, path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

fn cli_tests_enabled(test_name: &str) -> bool {
    if env::var(CLI_TEST_ENV).is_err() {
        println!(
            "Skipping {}. Set {}=1 to execute CLI integration tests.",
            test_name, CLI_TEST_ENV
        );
        return false;
    }
    true
}

/// Helper function to create a temporary database configuration
fn create_temp_config(db_path: &str) -> String {
    format!(
        r#"
[database]
url = "sqlite:{}"
max_connections = 5
connection_timeout = 30
auto_migrate = true

[auth]
jwt_secret = "test-secret-key-for-testing-only-do-not-use-in-production"
token_ttl = 900
refresh_ttl = 86400
password_min_length = 8
argon2_memory = 4096
argon2_iterations = 1
argon2_parallelism = 1

[storage]
backend = "Local"

[storage.local]
base_path = "data/storage"
max_file_size = 10485760

[features]
oauth2 = false
s3_storage = false
image_transforms = false
multi_tenant = false
full_text_search = false
metrics = false

[server]
host = "127.0.0.1"
port = 8090
request_timeout = 30
max_request_size = 1048576
cors_origins = ["*"]

[server.rate_limit]
requests_per_minute = 60
burst_size = 10
"#,
        db_path
    )
}

fn run_migrate_run(config_path: &Path) {
    let output = Command::new(ferritedb_binary())
        .args(["--config", config_path.to_str().unwrap(), "migrate", "run"])
        .output()
        .expect("Failed to execute ferritedb migrate run");

    if !output.status.success() {
        panic!(
            "migrate run command failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn test_migrate_run_command() {
    if !cli_tests_enabled("migrate run command") {
        return;
    }

    let temp_dir = TempTestDir::new();
    let db_path = temp_dir.path().join("test.db");
    let config_path = temp_dir.path().join("config.toml");

    // Create config file
    std::fs::write(&config_path, create_temp_config(&db_path.to_string_lossy())).unwrap();

    // Run migration
    let output = Command::new(ferritedb_binary())
        .args(["--config", config_path.to_str().unwrap(), "migrate", "run"])
        .output()
        .expect("Failed to execute ferritedb migrate run");

    // Check that the command succeeded
    if !output.status.success() {
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        panic!("migrate run command failed");
    }

    // Verify database file was created
    assert!(db_path.exists(), "Database file should be created");

    // Verify output contains success message
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Migrations completed successfully"),
        "Should contain success message"
    );
}

#[test]
fn test_migrate_status_command() {
    if !cli_tests_enabled("migrate status command") {
        return;
    }

    let temp_dir = TempTestDir::new();
    let db_path = temp_dir.path().join("test.db");
    let config_path = temp_dir.path().join("config.toml");

    // Create config file
    std::fs::write(&config_path, create_temp_config(&db_path.to_string_lossy())).unwrap();

    // First run migrations
    let _output = Command::new(ferritedb_binary())
        .args(["--config", config_path.to_str().unwrap(), "migrate", "run"])
        .output()
        .expect("Failed to execute ferritedb migrate run");

    // Check migration status
    let output = Command::new(ferritedb_binary())
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "migrate",
            "status",
        ])
        .output()
        .expect("Failed to execute ferritedb migrate status");

    // Check that the command succeeded
    if !output.status.success() {
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        panic!("migrate status command failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Applied migrations") || stdout.contains("Database connection is healthy"),
        "Should show migration status"
    );
}

#[test]
fn test_admin_create_command() {
    if !cli_tests_enabled("admin create command") {
        return;
    }

    let temp_dir = TempTestDir::new();
    let db_path = temp_dir.path().join("test.db");
    let config_path = temp_dir.path().join("config.toml");

    // Create config file
    std::fs::write(&config_path, create_temp_config(&db_path.to_string_lossy())).unwrap();

    run_migrate_run(&config_path);

    // Create admin user with password provided via command line
    let output = Command::new(ferritedb_binary())
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "admin",
            "create",
            "admin@example.com",
            "--password",
            "AdminPass123!",
        ])
        .output()
        .expect("Failed to execute ferritedb admin create");

    // Check that the command succeeded
    if !output.status.success() {
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        panic!("admin create command failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Admin user created successfully"),
        "Should contain success message"
    );
    assert!(
        stdout.contains("admin@example.com"),
        "Should contain admin email"
    );
}

#[test]
fn test_admin_list_command() {
    if !cli_tests_enabled("admin list command") {
        return;
    }

    let temp_dir = TempTestDir::new();
    let db_path = temp_dir.path().join("test.db");
    let config_path = temp_dir.path().join("config.toml");

    // Create config file
    std::fs::write(&config_path, create_temp_config(&db_path.to_string_lossy())).unwrap();

    run_migrate_run(&config_path);

    // First create an admin user
    let _create_output = Command::new(ferritedb_binary())
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "admin",
            "create",
            "admin@example.com",
            "--password",
            "AdminPass123!",
        ])
        .output()
        .expect("Failed to execute ferritedb admin create");

    // List users
    let output = Command::new(ferritedb_binary())
        .args(["--config", config_path.to_str().unwrap(), "admin", "list"])
        .output()
        .expect("Failed to execute ferritedb admin list");

    // Check that the command succeeded
    if !output.status.success() {
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        panic!("admin list command failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("admin@example.com"),
        "Should list the created admin user"
    );
    assert!(
        stdout.contains("Found 1 users") || stdout.contains("admin"),
        "Should show user count or admin role"
    );
}

#[test]
fn test_gen_jwt_command() {
    if !cli_tests_enabled("gen jwt command") {
        return;
    }

    let temp_dir = TempTestDir::new();
    let db_path = temp_dir.path().join("test.db");
    let config_path = temp_dir.path().join("config.toml");

    // Create config file
    std::fs::write(&config_path, create_temp_config(&db_path.to_string_lossy())).unwrap();

    run_migrate_run(&config_path);

    // First create an admin user
    let _create_output = Command::new(ferritedb_binary())
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "admin",
            "create",
            "admin@example.com",
            "--password",
            "AdminPass123!",
        ])
        .output()
        .expect("Failed to execute ferritedb admin create");

    // Generate JWT for the user
    let output = Command::new(ferritedb_binary())
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "gen-jwt",
            "admin@example.com",
            "--expires",
            "3600",
        ])
        .output()
        .expect("Failed to execute ferritedb gen-jwt");

    // Check that the command succeeded
    if !output.status.success() {
        eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
        panic!("gen-jwt command failed");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("JWT tokens generated successfully"),
        "Should contain success message"
    );
    assert!(
        stdout.contains("Access Token:"),
        "Should contain access token"
    );
    assert!(
        stdout.contains("Refresh Token:"),
        "Should contain refresh token"
    );
    assert!(
        stdout.contains("admin@example.com"),
        "Should contain user email"
    );
}

#[test]
fn test_import_export_json_data() {
    if !cli_tests_enabled("import export json") {
        return;
    }

    let temp_dir = TempTestDir::new();
    let db_path = temp_dir.path().join("test.db");
    let config_path = temp_dir.path().join("config.toml");
    let import_file = temp_dir.path().join("test_data.json");
    let _export_file = temp_dir.path().join("exported_data.json");

    // Create config file
    std::fs::write(&config_path, create_temp_config(&db_path.to_string_lossy())).unwrap();

    run_migrate_run(&config_path);

    // Create test data file
    let test_data = serde_json::json!([
        {
            "title": "Test Post 1",
            "content": "This is test content 1",
            "published": true
        },
        {
            "title": "Test Post 2",
            "content": "This is test content 2",
            "published": false
        }
    ]);
    std::fs::write(
        &import_file,
        serde_json::to_string_pretty(&test_data).unwrap(),
    )
    .unwrap();

    // First we need to create the collection (this would normally be done via API)
    // For now, we'll skip the import test since it requires a collection to exist
    // This test demonstrates the command structure

    let output = Command::new(ferritedb_binary())
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "import",
            "posts",
            import_file.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute ferritedb import");

    // The command should fail because the collection doesn't exist
    // but it should fail gracefully with a proper error message
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain error about collection not found
    assert!(
        stderr.contains("Collection 'posts' not found")
            || stdout.contains("Collection 'posts' not found"),
        "Should show collection not found error"
    );
}

#[test]
fn test_import_csv_data() {
    if !cli_tests_enabled("import csv data") {
        return;
    }

    let temp_dir = TempTestDir::new();
    let db_path = temp_dir.path().join("test.db");
    let config_path = temp_dir.path().join("config.toml");
    let import_file = temp_dir.path().join("test_data.csv");

    // Create config file
    std::fs::write(&config_path, create_temp_config(&db_path.to_string_lossy())).unwrap();

    run_migrate_run(&config_path);

    // Create test CSV file
    let csv_data = "title,content,published\nTest Post 1,This is test content 1,true\nTest Post 2,This is test content 2,false";
    std::fs::write(&import_file, csv_data).unwrap();

    let output = Command::new(ferritedb_binary())
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "import",
            "posts",
            import_file.to_str().unwrap(),
        ])
        .output()
        .expect("Failed to execute ferritedb import");

    // The command should fail because the collection doesn't exist
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain error about collection not found
    assert!(
        stderr.contains("Collection 'posts' not found")
            || stdout.contains("Collection 'posts' not found"),
        "Should show collection not found error"
    );
}

#[test]
fn test_export_nonexistent_collection() {
    if !cli_tests_enabled("export nonexistent collection") {
        return;
    }

    let temp_dir = TempTestDir::new();
    let db_path = temp_dir.path().join("test.db");
    let config_path = temp_dir.path().join("config.toml");

    // Create config file
    std::fs::write(&config_path, create_temp_config(&db_path.to_string_lossy())).unwrap();

    run_migrate_run(&config_path);

    let output = Command::new(ferritedb_binary())
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "export",
            "nonexistent_collection",
        ])
        .output()
        .expect("Failed to execute ferritedb export");

    // The command should fail because the collection doesn't exist
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain error about collection not found
    assert!(
        stderr.contains("Collection 'nonexistent_collection' not found")
            || stdout.contains("Collection 'nonexistent_collection' not found"),
        "Should show collection not found error"
    );
}

#[test]
fn test_gen_jwt_nonexistent_user() {
    if !cli_tests_enabled("gen jwt nonexistent user") {
        return;
    }

    let temp_dir = TempTestDir::new();
    let db_path = temp_dir.path().join("test.db");
    let config_path = temp_dir.path().join("config.toml");

    // Create config file
    std::fs::write(&config_path, create_temp_config(&db_path.to_string_lossy())).unwrap();

    run_migrate_run(&config_path);

    let output = Command::new(ferritedb_binary())
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "gen-jwt",
            "nonexistent@example.com",
        ])
        .output()
        .expect("Failed to execute ferritedb gen-jwt");

    // The command should fail because the user doesn't exist
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain error about user not found
    assert!(
        stderr.contains("User 'nonexistent@example.com' not found")
            || stdout.contains("User 'nonexistent@example.com' not found"),
        "Should show user not found error"
    );
}

#[test]
fn test_admin_create_duplicate_user() {
    if !cli_tests_enabled("admin create duplicate user") {
        return;
    }

    let temp_dir = TempTestDir::new();
    let db_path = temp_dir.path().join("test.db");
    let config_path = temp_dir.path().join("config.toml");

    // Create config file
    std::fs::write(&config_path, create_temp_config(&db_path.to_string_lossy())).unwrap();

    // Create first admin user
    let _output1 = Command::new(ferritedb_binary())
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "admin",
            "create",
            "admin@example.com",
            "--password",
            "AdminPass123!",
        ])
        .output()
        .expect("Failed to execute ferritedb admin create");

    // Try to create the same user again
    let output2 = Command::new(ferritedb_binary())
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "admin",
            "create",
            "admin@example.com",
            "--password",
            "AdminPass123!",
        ])
        .output()
        .expect("Failed to execute ferritedb admin create");

    // The second command should fail
    assert!(!output2.status.success(), "Second admin create should fail");

    let stderr = String::from_utf8_lossy(&output2.stderr);
    let stdout = String::from_utf8_lossy(&output2.stdout);

    // Should contain error about user already existing
    assert!(
        stderr.contains("already exists") || stdout.contains("already exists"),
        "Should show user already exists error"
    );
}

#[test]
fn test_migrate_revert_command() {
    if !cli_tests_enabled("migrate revert command") {
        return;
    }

    let temp_dir = TempTestDir::new();
    let db_path = temp_dir.path().join("test.db");
    let config_path = temp_dir.path().join("config.toml");

    // Create config file
    std::fs::write(&config_path, create_temp_config(&db_path.to_string_lossy())).unwrap();

    // First run migrations
    let _output = Command::new(ferritedb_binary())
        .args(["--config", config_path.to_str().unwrap(), "migrate", "run"])
        .output()
        .expect("Failed to execute ferritedb migrate run");

    // Try to revert migration
    let output = Command::new(ferritedb_binary())
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "migrate",
            "revert",
        ])
        .output()
        .expect("Failed to execute ferritedb migrate revert");

    // The command should fail with a message about not supporting automatic rollback
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain message about rollback not being supported
    assert!(
        stderr.contains("not supported") || stdout.contains("not supported"),
        "Should show rollback not supported message"
    );
}
