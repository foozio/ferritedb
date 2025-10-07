#![allow(dead_code)]

use std::process::Command;
use std::time::Duration;
use tokio::time::sleep;
use reqwest::Client;
use serde_json::json;

/// Integration tests for Docker deployment
/// 
/// These tests verify that FerriteDB works correctly when deployed via Docker,
/// including container health checks, API functionality, and proper shutdown.
/// 
/// Prerequisites:
/// - Docker must be installed and running
/// - Port 8090 must be available
/// - Internet connection for pulling base images

#[tokio::test]
#[ignore] // Run with --ignored flag for Docker tests
async fn test_docker_container_build_and_health() {
    // Build the Docker image
    let build_output = Command::new("docker")
        .args(["build", "-t", "ferritedb:test", "."])
        .output()
        .expect("Failed to execute docker build");

    assert!(
        build_output.status.success(),
        "Docker build failed: {}",
        String::from_utf8_lossy(&build_output.stderr)
    );

    // Start the container
    let run_output = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name", "ferritedb-test",
            "-p", "8090:8090",
            "-e", "FERRITEDB_AUTH_JWT_SECRET=test-secret-for-integration-tests",
            "ferritedb:test"
        ])
        .output()
        .expect("Failed to start Docker container");

    assert!(
        run_output.status.success(),
        "Failed to start container: {}",
        String::from_utf8_lossy(&run_output.stderr)
    );

    let container_id = String::from_utf8_lossy(&run_output.stdout).trim().to_string();

    // Wait for container to start
    sleep(Duration::from_secs(10)).await;

    // Test health check endpoint
    let client = Client::new();
    let health_response = client
        .get("http://localhost:8090/healthz")
        .timeout(Duration::from_secs(5))
        .send()
        .await;

    assert!(health_response.is_ok(), "Health check failed");
    let health_response = health_response.unwrap();
    assert_eq!(health_response.status(), 200);

    // Test readiness check
    let ready_response = client
        .get("http://localhost:8090/readyz")
        .timeout(Duration::from_secs(5))
        .send()
        .await;

    assert!(ready_response.is_ok(), "Readiness check failed");
    let ready_response = ready_response.unwrap();
    assert_eq!(ready_response.status(), 200);

    // Cleanup: Stop and remove container
    let _ = Command::new("docker")
        .args(["stop", &container_id])
        .output();
    
    let _ = Command::new("docker")
        .args(["rm", &container_id])
        .output();
}

#[tokio::test]
#[ignore] // Run with --ignored flag for Docker tests
async fn test_docker_container_api_functionality() {
    // Start container with test configuration
    let run_output = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name", "ferritedb-api-test",
            "-p", "8091:8090",
            "-e", "FERRITEDB_AUTH_JWT_SECRET=test-secret-for-api-tests",
            "-e", "FERRITEDB_SERVER_PORT=8090",
            "ferritedb:test"
        ])
        .output()
        .expect("Failed to start Docker container");

    assert!(run_output.status.success());
    let container_id = String::from_utf8_lossy(&run_output.stdout).trim().to_string();

    // Wait for container to be ready
    sleep(Duration::from_secs(15)).await;

    let client = Client::new();
    let base_url = "http://localhost:8091";

    // Test admin user creation via API
    let register_response = client
        .post(format!("{}/api/auth/register", base_url))
        .json(&json!({
            "email": "admin@test.com",
            "password": "test123456",
            "role": "admin"
        }))
        .send()
        .await;

    assert!(register_response.is_ok(), "Failed to register admin user");
    let register_response = register_response.unwrap();
    assert_eq!(register_response.status(), 201);

    // Test login
    let login_response = client
        .post(format!("{}/api/auth/login", base_url))
        .json(&json!({
            "email": "admin@test.com",
            "password": "test123456"
        }))
        .send()
        .await;

    assert!(login_response.is_ok(), "Failed to login");
    let login_response = login_response.unwrap();
    assert_eq!(login_response.status(), 200);

    let login_data: serde_json::Value = login_response.json().await.unwrap();
    let token = login_data["token"].as_str().unwrap();

    // Test collection creation
    let collection_response = client
        .post(format!("{}/api/collections", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({
            "name": "test_collection",
            "schema": {
                "fields": [
                    {
                        "name": "title",
                        "type": "text",
                        "required": true
                    },
                    {
                        "name": "content",
                        "type": "text",
                        "required": false
                    }
                ]
            }
        }))
        .send()
        .await;

    assert!(collection_response.is_ok(), "Failed to create collection");
    let collection_response = collection_response.unwrap();
    assert_eq!(collection_response.status(), 201);

    // Test record creation
    let record_response = client
        .post(format!("{}/api/collections/test_collection/records", base_url))
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({
            "title": "Test Record",
            "content": "This is a test record created in Docker"
        }))
        .send()
        .await;

    assert!(record_response.is_ok(), "Failed to create record");
    let record_response = record_response.unwrap();
    assert_eq!(record_response.status(), 201);

    // Cleanup
    let _ = Command::new("docker")
        .args(["stop", &container_id])
        .output();
    
    let _ = Command::new("docker")
        .args(["rm", &container_id])
        .output();
}

#[tokio::test]
#[ignore] // Run with --ignored flag for Docker tests
async fn test_docker_compose_development_setup() {
    // Test docker-compose development setup
    let compose_up = Command::new("docker-compose")
        .args(["-f", "docker-compose.dev.yml", "up", "-d", "ferritedb-dev"])
        .output()
        .expect("Failed to run docker-compose up");

    assert!(
        compose_up.status.success(),
        "Docker compose up failed: {}",
        String::from_utf8_lossy(&compose_up.stderr)
    );

    // Wait for service to be ready
    sleep(Duration::from_secs(20)).await;

    let client = Client::new();

    // Test health endpoint
    let health_response = client
        .get("http://localhost:8090/healthz")
        .timeout(Duration::from_secs(10))
        .send()
        .await;

    assert!(health_response.is_ok(), "Health check failed in compose setup");
    assert_eq!(health_response.unwrap().status(), 200);

    // Test admin interface is accessible
    let admin_response = client
        .get("http://localhost:8090/admin")
        .timeout(Duration::from_secs(10))
        .send()
        .await;

    assert!(admin_response.is_ok(), "Admin interface not accessible");
    let admin_response = admin_response.unwrap();
    assert!(admin_response.status().is_success());

    // Cleanup
    let _ = Command::new("docker-compose")
        .args(["-f", "docker-compose.dev.yml", "down", "-v"])
        .output();
}

#[tokio::test]
#[ignore] // Run with --ignored flag for Docker tests
async fn test_docker_container_graceful_shutdown() {
    // Start container
    let run_output = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name", "ferritedb-shutdown-test",
            "-p", "8092:8090",
            "-e", "FERRITEDB_AUTH_JWT_SECRET=test-secret-shutdown",
            "ferritedb:test"
        ])
        .output()
        .expect("Failed to start container");

    assert!(run_output.status.success());
    let container_id = String::from_utf8_lossy(&run_output.stdout).trim().to_string();

    // Wait for container to be ready
    sleep(Duration::from_secs(10)).await;

    let client = Client::new();

    // Verify container is healthy
    let health_response = client
        .get("http://localhost:8092/healthz")
        .send()
        .await;
    assert!(health_response.is_ok());

    // Send SIGTERM to container (graceful shutdown)
    let stop_output = Command::new("docker")
        .args(["stop", &container_id])
        .output()
        .expect("Failed to stop container");

    assert!(stop_output.status.success(), "Failed to gracefully stop container");

    // Verify container stopped cleanly
    let inspect_output = Command::new("docker")
        .args(["inspect", &container_id, "--format", "{{.State.ExitCode}}"])
        .output()
        .expect("Failed to inspect container");

    let exit_code_output = String::from_utf8_lossy(&inspect_output.stdout);
    let exit_code = exit_code_output.trim();
    assert_eq!(exit_code, "0", "Container did not exit cleanly");

    // Cleanup
    let _ = Command::new("docker")
        .args(["rm", &container_id])
        .output();
}

#[tokio::test]
#[ignore] // Run with --ignored flag for Docker tests
async fn test_docker_volume_persistence() {
    // Create a named volume
    let volume_create = Command::new("docker")
        .args(["volume", "create", "ferritedb-test-data"])
        .output()
        .expect("Failed to create volume");

    assert!(volume_create.status.success());

    // Start container with volume
    let run_output = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name", "ferritedb-persistence-test",
            "-p", "8093:8090",
            "-v", "ferritedb-test-data:/app/data",
            "-e", "FERRITEDB_AUTH_JWT_SECRET=test-secret-persistence",
            "ferritedb:test"
        ])
        .output()
        .expect("Failed to start container");

    assert!(run_output.status.success());
    let container_id = String::from_utf8_lossy(&run_output.stdout).trim().to_string();

    // Wait for container to be ready
    sleep(Duration::from_secs(15)).await;

    let client = Client::new();

    // Create some data
    let register_response = client
        .post("http://localhost:8093/api/auth/register")
        .json(&json!({
            "email": "persistence@test.com",
            "password": "test123456",
            "role": "admin"
        }))
        .send()
        .await;

    assert!(register_response.is_ok());

    // Stop container
    let _ = Command::new("docker")
        .args(["stop", &container_id])
        .output();

    let _ = Command::new("docker")
        .args(["rm", &container_id])
        .output();

    // Start new container with same volume
    let run_output2 = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name", "ferritedb-persistence-test-2",
            "-p", "8093:8090",
            "-v", "ferritedb-test-data:/app/data",
            "-e", "FERRITEDB_AUTH_JWT_SECRET=test-secret-persistence",
            "ferritedb:test"
        ])
        .output()
        .expect("Failed to start second container");

    assert!(run_output2.status.success());
    let container_id2 = String::from_utf8_lossy(&run_output2.stdout).trim().to_string();

    // Wait for container to be ready
    sleep(Duration::from_secs(15)).await;

    // Try to login with previously created user
    let login_response = client
        .post("http://localhost:8093/api/auth/login")
        .json(&json!({
            "email": "persistence@test.com",
            "password": "test123456"
        }))
        .send()
        .await;

    assert!(login_response.is_ok(), "Data was not persisted across container restarts");
    assert_eq!(login_response.unwrap().status(), 200);

    // Cleanup
    let _ = Command::new("docker")
        .args(["stop", &container_id2])
        .output();

    let _ = Command::new("docker")
        .args(["rm", &container_id2])
        .output();

    let _ = Command::new("docker")
        .args(["volume", "rm", "ferritedb-test-data"])
        .output();
}

/// Helper function to check if Docker is available
fn docker_available() -> bool {
    Command::new("docker")
        .args(["--version"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Helper function to check if docker-compose is available
fn docker_compose_available() -> bool {
    Command::new("docker-compose")
        .args(["--version"])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

#[test]
fn test_docker_prerequisites() {
    assert!(docker_available(), "Docker is not available. Please install Docker to run these tests.");
    assert!(docker_compose_available(), "docker-compose is not available. Please install docker-compose to run these tests.");
}

/// Test Docker image security configuration
#[tokio::test]
#[ignore]
async fn test_docker_security_configuration() {
    // Start container and check security settings
    let run_output = Command::new("docker")
        .args([
            "run",
            "-d",
            "--name", "ferritedb-security-test",
            "-p", "8094:8090",
            "-e", "FERRITEDB_AUTH_JWT_SECRET=test-secret-security",
            "ferritedb:test"
        ])
        .output()
        .expect("Failed to start container");

    assert!(run_output.status.success());
    let container_id = String::from_utf8_lossy(&run_output.stdout).trim().to_string();

    // Check that container runs as non-root user
    let user_check = Command::new("docker")
        .args(["exec", &container_id, "whoami"])
        .output()
        .expect("Failed to check user");

    let user_output = String::from_utf8_lossy(&user_check.stdout);
    let user = user_output.trim();
    assert_ne!(user, "root", "Container should not run as root user");

    // Check file permissions
    let permissions_check = Command::new("docker")
        .args(["exec", &container_id, "ls", "-la", "/app/data"])
        .output()
        .expect("Failed to check permissions");

    assert!(permissions_check.status.success());

    // Cleanup
    let _ = Command::new("docker")
        .args(["stop", &container_id])
        .output();

    let _ = Command::new("docker")
        .args(["rm", &container_id])
        .output();
}

#[cfg(test)]
mod test_helpers {
    use super::*;

    /// Setup function for Docker tests
    pub async fn setup_test_environment() {
        // Ensure test image is built
        let build_output = Command::new("docker")
            .args(["build", "-t", "ferritedb:test", "."])
            .output()
            .expect("Failed to build test image");

        assert!(build_output.status.success(), "Failed to build Docker image for tests");
    }

    /// Cleanup function for Docker tests
    pub async fn cleanup_test_environment() {
        // Remove any leftover test containers
        let _ = Command::new("docker")
            .args(["ps", "-aq", "--filter", "name=ferritedb-*-test"])
            .output()
            .and_then(|output| {
                let container_ids = String::from_utf8_lossy(&output.stdout);
                if !container_ids.trim().is_empty() {
                    Command::new("docker")
                        .args(["rm", "-f"])
                        .args(container_ids.trim().split('\n'))
                        .output()
                } else {
                    Ok(output)
                }
            });

        // Remove test volumes
        let _ = Command::new("docker")
            .args(["volume", "ls", "-q", "--filter", "name=ferritedb-test-*"])
            .output()
            .and_then(|output| {
                let volume_names = String::from_utf8_lossy(&output.stdout);
                if !volume_names.trim().is_empty() {
                    Command::new("docker")
                        .args(["volume", "rm"])
                        .args(volume_names.trim().split('\n'))
                        .output()
                } else {
                    Ok(output)
                }
            });
    }
}
