use std::process::Command;
use std::env;

/// Test runner for deployment integration tests
/// 
/// This module provides utilities for running deployment tests and
/// validating the deployment infrastructure.

#[test]
fn test_deployment_script_exists() {
    let script_path = "scripts/test-deployment.sh";
    assert!(
        std::path::Path::new(script_path).exists(),
        "Deployment test script should exist at {}",
        script_path
    );
}

#[test]
fn test_deployment_script_executable() {
    let script_path = "scripts/test-deployment.sh";
    
    // Check if script is executable (Unix-like systems)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(script_path)
            .expect("Failed to get script metadata");
        let permissions = metadata.permissions();
        assert!(
            permissions.mode() & 0o111 != 0,
            "Deployment script should be executable"
        );
    }
}

#[test]
#[ignore] // Run with --ignored for actual deployment testing
fn test_run_deployment_tests_quick() {
    // Run the deployment test script in quick mode
    let output = Command::new("./scripts/test-deployment.sh")
        .args(&["--quick"])
        .output()
        .expect("Failed to execute deployment test script");

    if !output.status.success() {
        eprintln!("Deployment test stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("Deployment test stderr: {}", String::from_utf8_lossy(&output.stderr));
        panic!("Deployment tests failed");
    }

    println!("Deployment tests output: {}", String::from_utf8_lossy(&output.stdout));
}

#[test]
#[ignore] // Run with --ignored for full deployment testing
fn test_run_full_deployment_tests() {
    // Only run in CI or when explicitly requested
    if env::var("CI").is_err() && env::var("RUN_DEPLOYMENT_TESTS").is_err() {
        println!("Skipping full deployment tests. Set RUN_DEPLOYMENT_TESTS=1 to run.");
        return;
    }

    // Run the full deployment test suite
    let output = Command::new("./scripts/test-deployment.sh")
        .output()
        .expect("Failed to execute deployment test script");

    if !output.status.success() {
        eprintln!("Deployment test stdout: {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("Deployment test stderr: {}", String::from_utf8_lossy(&output.stderr));
        panic!("Full deployment tests failed");
    }

    println!("Full deployment tests completed successfully");
}

/// Test Docker prerequisites
#[test]
fn test_docker_prerequisites() {
    // Check if Docker is available
    let docker_check = Command::new("docker")
        .args(&["--version"])
        .output();

    match docker_check {
        Ok(output) if output.status.success() => {
            println!("Docker version: {}", String::from_utf8_lossy(&output.stdout));
        }
        _ => {
            println!("Docker not available - deployment tests will be skipped");
            return;
        }
    }

    // Check if docker-compose is available
    let compose_check = Command::new("docker-compose")
        .args(&["--version"])
        .output();

    match compose_check {
        Ok(output) if output.status.success() => {
            println!("Docker Compose version: {}", String::from_utf8_lossy(&output.stdout));
        }
        _ => {
            println!("Docker Compose not available - some deployment tests will be skipped");
        }
    }
}

/// Validate deployment configuration files
#[test]
fn test_deployment_configuration_files() {
    let required_files = [
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.dev.yml",
        ".dockerignore",
        "ferritedb.dev.toml",
    ];

    for file in &required_files {
        assert!(
            std::path::Path::new(file).exists(),
            "Required deployment file {} should exist",
            file
        );

        let content = std::fs::read_to_string(file)
            .expect(&format!("Failed to read {}", file));
        
        assert!(
            !content.trim().is_empty(),
            "Deployment file {} should not be empty",
            file
        );
    }
}

/// Test GitHub Actions workflow files
#[test]
fn test_github_actions_workflows() {
    let workflow_files = [
        ".github/workflows/ci.yml",
        ".github/workflows/release.yml",
    ];

    for file in &workflow_files {
        assert!(
            std::path::Path::new(file).exists(),
            "GitHub Actions workflow {} should exist",
            file
        );

        let content = std::fs::read_to_string(file)
            .expect(&format!("Failed to read {}", file));

        // Basic YAML validation
        assert!(content.contains("name:"), "Workflow should have a name");
        assert!(content.contains("on:"), "Workflow should have triggers");
        assert!(content.contains("jobs:"), "Workflow should have jobs");
    }
}

/// Test project documentation completeness
#[test]
fn test_project_documentation_completeness() {
    let required_docs = [
        ("README.md", vec!["# FerriteDB", "## 🚀 Quick Start"]),
        ("CONTRIBUTING.md", vec!["# Contributing", "## Development Setup", "## Pull Request"]),
        ("SECURITY.md", vec!["# Security Policy", "## Reporting", "## Supported Versions"]),
        ("OPERATIONS.md", vec!["# Operations", "## Deployment", "## Monitoring"]),
        ("CHANGELOG.md", vec!["# Changelog", "[Unreleased]"]),
        ("LICENSE", vec!["MIT License", "Permission is hereby granted"]),
    ];

    for (file, required_sections) in &required_docs {
        assert!(
            std::path::Path::new(file).exists(),
            "Documentation file {} should exist",
            file
        );

        let content = std::fs::read_to_string(file)
            .expect(&format!("Failed to read {}", file));

        for section in required_sections {
            assert!(
                content.contains(section),
                "Documentation file {} should contain section: {}",
                file,
                section
            );
        }
    }
}

/// Test issue and PR templates
#[test]
fn test_github_templates() {
    let template_files = [
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/ISSUE_TEMPLATE/feature_request.yml",
        ".github/ISSUE_TEMPLATE/question.yml",
        ".github/ISSUE_TEMPLATE/config.yml",
        ".github/pull_request_template.md",
    ];

    for file in &template_files {
        assert!(
            std::path::Path::new(file).exists(),
            "GitHub template {} should exist",
            file
        );

        let content = std::fs::read_to_string(file)
            .expect(&format!("Failed to read {}", file));
        
        assert!(
            !content.trim().is_empty(),
            "GitHub template {} should not be empty",
            file
        );
    }
}

/// Validate Cargo.toml workspace configuration
#[test]
fn test_cargo_workspace_configuration() {
    let cargo_toml = std::fs::read_to_string("Cargo.toml")
        .expect("Failed to read Cargo.toml");

    // Parse as TOML to validate syntax
    let parsed: toml::Value = toml::from_str(&cargo_toml)
        .expect("Cargo.toml should be valid TOML");

    // Check for workspace or package configuration
    assert!(
        parsed.get("workspace").is_some() || parsed.get("package").is_some(),
        "Cargo.toml should have either workspace or package configuration"
    );

    // If it's a workspace, check for members
    if let Some(workspace) = parsed.get("workspace") {
        assert!(
            workspace.get("members").is_some(),
            "Workspace should have members"
        );
    }
}

/// Test that all crates in workspace have proper configuration
#[test]
fn test_workspace_crates_configuration() {
    let crate_dirs = [
        "crates/core",
        "crates/server", 
        "crates/storage",
        "crates/rules",
        "crates/sdk-rs",
    ];

    for crate_dir in &crate_dirs {
        let cargo_toml_path = format!("{}/Cargo.toml", crate_dir);
        
        if std::path::Path::new(&cargo_toml_path).exists() {
            let content = std::fs::read_to_string(&cargo_toml_path)
                .expect(&format!("Failed to read {}", cargo_toml_path));

            let parsed: toml::Value = toml::from_str(&content)
                .expect(&format!("{} should be valid TOML", cargo_toml_path));

            // Check for package configuration
            assert!(
                parsed.get("package").is_some(),
                "{} should have package configuration",
                cargo_toml_path
            );

            let package = parsed.get("package").unwrap();
            assert!(
                package.get("name").is_some(),
                "{} should have package name",
                cargo_toml_path
            );
        }
    }
}

#[cfg(test)]
mod integration_helpers {
    use super::*;

    /// Helper to run a command and capture output
    pub fn run_command(cmd: &str, args: &[&str]) -> Result<String, String> {
        let output = Command::new(cmd)
            .args(args)
            .output()
            .map_err(|e| format!("Failed to execute {}: {}", cmd, e))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            Err(String::from_utf8_lossy(&output.stderr).to_string())
        }
    }

    /// Helper to check if a command is available
    pub fn command_available(cmd: &str) -> bool {
        Command::new(cmd)
            .args(&["--version"])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }

    /// Helper to wait for a service to be ready
    pub async fn wait_for_service(url: &str, timeout_secs: u64) -> Result<(), String> {
        use std::time::{Duration, Instant};
        use tokio::time::sleep;

        let client = reqwest::Client::new();
        let start = Instant::now();
        let timeout = Duration::from_secs(timeout_secs);

        while start.elapsed() < timeout {
            match client.get(url).send().await {
                Ok(response) if response.status().is_success() => {
                    return Ok(());
                }
                _ => {
                    sleep(Duration::from_secs(2)).await;
                }
            }
        }

        Err(format!("Service at {} did not become ready within {} seconds", url, timeout_secs))
    }
}
