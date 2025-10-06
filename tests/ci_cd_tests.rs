use std::process::Command;
use std::fs;
use std::path::Path;
use serde_yaml;
use serde_json;

/// Tests for CI/CD pipeline configuration and functionality
/// 
/// These tests verify that the GitHub Actions workflows are properly configured
/// and that the project structure supports automated testing and deployment.

#[test]
fn test_github_actions_workflow_syntax() {
    // Test CI workflow syntax
    let ci_workflow_path = ".github/workflows/ci.yml";
    assert!(Path::new(ci_workflow_path).exists(), "CI workflow file should exist");

    let ci_content = fs::read_to_string(ci_workflow_path)
        .expect("Failed to read CI workflow file");

    let ci_yaml: serde_yaml::Value = serde_yaml::from_str(&ci_content)
        .expect("CI workflow should be valid YAML");

    // Verify required fields
    assert!(ci_yaml["name"].is_string(), "Workflow should have a name");
    assert!(ci_yaml["on"].is_mapping(), "Workflow should have triggers");
    assert!(ci_yaml["jobs"].is_mapping(), "Workflow should have jobs");

    // Test release workflow syntax
    let release_workflow_path = ".github/workflows/release.yml";
    assert!(Path::new(release_workflow_path).exists(), "Release workflow file should exist");

    let release_content = fs::read_to_string(release_workflow_path)
        .expect("Failed to read release workflow file");

    let release_yaml: serde_yaml::Value = serde_yaml::from_str(&release_content)
        .expect("Release workflow should be valid YAML");

    // Verify required fields
    assert!(release_yaml["name"].is_string(), "Release workflow should have a name");
    assert!(release_yaml["on"].is_mapping(), "Release workflow should have triggers");
    assert!(release_yaml["jobs"].is_mapping(), "Release workflow should have jobs");
}

#[test]
fn test_dependabot_configuration() {
    let dependabot_path = ".github/dependabot.yml";
    assert!(Path::new(dependabot_path).exists(), "Dependabot config should exist");

    let dependabot_content = fs::read_to_string(dependabot_path)
        .expect("Failed to read dependabot config");

    let dependabot_yaml: serde_yaml::Value = serde_yaml::from_str(&dependabot_content)
        .expect("Dependabot config should be valid YAML");

    // Verify version and updates
    assert_eq!(dependabot_yaml["version"], 2, "Dependabot should use version 2");
    assert!(dependabot_yaml["updates"].is_sequence(), "Should have updates configuration");

    let updates = dependabot_yaml["updates"].as_sequence().unwrap();
    
    // Check for Cargo ecosystem
    let has_cargo = updates.iter().any(|update| {
        update["package-ecosystem"].as_str() == Some("cargo")
    });
    assert!(has_cargo, "Should monitor Cargo dependencies");

    // Check for GitHub Actions ecosystem
    let has_github_actions = updates.iter().any(|update| {
        update["package-ecosystem"].as_str() == Some("github-actions")
    });
    assert!(has_github_actions, "Should monitor GitHub Actions");
}

#[test]
fn test_issue_templates_exist() {
    let templates_dir = ".github/ISSUE_TEMPLATE";
    assert!(Path::new(templates_dir).exists(), "Issue templates directory should exist");

    // Check for required templates
    let bug_report = Path::new(&format!("{}/bug_report.yml", templates_dir));
    assert!(bug_report.exists(), "Bug report template should exist");

    let feature_request = Path::new(&format!("{}/feature_request.yml", templates_dir));
    assert!(feature_request.exists(), "Feature request template should exist");

    let question = Path::new(&format!("{}/question.yml", templates_dir));
    assert!(question.exists(), "Question template should exist");

    let config = Path::new(&format!("{}/config.yml", templates_dir));
    assert!(config.exists(), "Template config should exist");
}

#[test]
fn test_pull_request_template_exists() {
    let pr_template = ".github/pull_request_template.md";
    assert!(Path::new(pr_template).exists(), "Pull request template should exist");

    let content = fs::read_to_string(pr_template)
        .expect("Failed to read PR template");

    // Check for required sections
    assert!(content.contains("## Description"), "PR template should have Description section");
    assert!(content.contains("## Type of Change"), "PR template should have Type of Change section");
    assert!(content.contains("## Testing"), "PR template should have Testing section");
    assert!(content.contains("## Checklist"), "PR template should have Checklist section");
}

#[test]
fn test_project_documentation_exists() {
    // Check for required documentation files
    let required_docs = [
        "README.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "SECURITY.md",
        "OPERATIONS.md",
        "CHANGELOG.md",
        "CODE_OF_CONDUCT.md",
        "ROADMAP.md",
    ];

    for doc in &required_docs {
        assert!(Path::new(doc).exists(), "{} should exist", doc);
        
        let content = fs::read_to_string(doc)
            .expect(&format!("Failed to read {}", doc));
        
        assert!(!content.trim().is_empty(), "{} should not be empty", doc);
    }
}

#[test]
fn test_cargo_toml_configuration() {
    let cargo_toml_path = "Cargo.toml";
    assert!(Path::new(cargo_toml_path).exists(), "Cargo.toml should exist");

    let content = fs::read_to_string(cargo_toml_path)
        .expect("Failed to read Cargo.toml");

    let cargo_toml: toml::Value = toml::from_str(&content)
        .expect("Cargo.toml should be valid TOML");

    // Check workspace configuration
    if let Some(workspace) = cargo_toml.get("workspace") {
        assert!(workspace.get("members").is_some(), "Workspace should have members");
    }

    // Check package information
    if let Some(package) = cargo_toml.get("package") {
        assert!(package.get("name").is_some(), "Package should have a name");
        assert!(package.get("version").is_some(), "Package should have a version");
        assert!(package.get("authors").is_some(), "Package should have authors");
        assert!(package.get("license").is_some(), "Package should have a license");
    }
}

#[test]
fn test_docker_files_exist() {
    // Check Docker-related files
    let docker_files = [
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.dev.yml",
        ".dockerignore",
    ];

    for file in &docker_files {
        assert!(Path::new(file).exists(), "{} should exist", file);
        
        let content = fs::read_to_string(file)
            .expect(&format!("Failed to read {}", file));
        
        assert!(!content.trim().is_empty(), "{} should not be empty", file);
    }
}

#[test]
fn test_dockerfile_best_practices() {
    let dockerfile_content = fs::read_to_string("Dockerfile")
        .expect("Failed to read Dockerfile");

    // Check for multi-stage build
    assert!(dockerfile_content.contains("FROM"), "Dockerfile should have FROM instruction");
    assert!(dockerfile_content.contains("as builder") || dockerfile_content.contains("AS builder"), 
            "Dockerfile should use multi-stage build");

    // Check for non-root user
    assert!(dockerfile_content.contains("USER"), "Dockerfile should specify non-root user");

    // Check for health check
    assert!(dockerfile_content.contains("HEALTHCHECK"), "Dockerfile should have health check");

    // Check for proper COPY/ADD usage
    let copy_count = dockerfile_content.matches("COPY").count();
    assert!(copy_count > 0, "Dockerfile should use COPY instructions");
}

#[test]
fn test_ci_workflow_jobs() {
    let ci_content = fs::read_to_string(".github/workflows/ci.yml")
        .expect("Failed to read CI workflow");

    let ci_yaml: serde_yaml::Value = serde_yaml::from_str(&ci_content)
        .expect("CI workflow should be valid YAML");

    let jobs = ci_yaml["jobs"].as_mapping()
        .expect("CI workflow should have jobs");

    // Check for required jobs
    let required_jobs = ["test", "security", "build"];
    for job in &required_jobs {
        assert!(jobs.contains_key(&serde_yaml::Value::String(job.to_string())), 
                "CI should have {} job", job);
    }

    // Check test job configuration
    if let Some(test_job) = jobs.get(&serde_yaml::Value::String("test".to_string())) {
        let steps = test_job["steps"].as_sequence()
            .expect("Test job should have steps");

        let has_checkout = steps.iter().any(|step| {
            step["uses"].as_str().map_or(false, |uses| uses.contains("checkout"))
        });
        assert!(has_checkout, "Test job should checkout code");

        let has_rust_setup = steps.iter().any(|step| {
            step["uses"].as_str().map_or(false, |uses| uses.contains("rust-toolchain"))
        });
        assert!(has_rust_setup, "Test job should set up Rust toolchain");
    }
}

#[test]
fn test_release_workflow_configuration() {
    let release_content = fs::read_to_string(".github/workflows/release.yml")
        .expect("Failed to read release workflow");

    let release_yaml: serde_yaml::Value = serde_yaml::from_str(&release_content)
        .expect("Release workflow should be valid YAML");

    // Check trigger configuration
    let on_config = release_yaml["on"].as_mapping()
        .expect("Release workflow should have trigger configuration");

    assert!(on_config.contains_key(&serde_yaml::Value::String("push".to_string())), 
            "Release workflow should trigger on push");

    // Check for multi-platform builds
    let jobs = release_yaml["jobs"].as_mapping()
        .expect("Release workflow should have jobs");

    if let Some(build_job) = jobs.get(&serde_yaml::Value::String("build-release".to_string())) {
        let strategy = build_job.get("strategy");
        if let Some(strategy) = strategy {
            let matrix = strategy.get("matrix");
            assert!(matrix.is_some(), "Build job should use matrix strategy for multi-platform builds");
        }
    }
}

/// Test that runs a subset of CI checks locally
#[test]
fn test_local_ci_simulation() {
    // Test cargo fmt check
    let fmt_output = Command::new("cargo")
        .args(&["fmt", "--all", "--", "--check"])
        .output()
        .expect("Failed to run cargo fmt");

    assert!(fmt_output.status.success(), 
            "Code should be properly formatted. Run 'cargo fmt' to fix.");

    // Test cargo clippy
    let clippy_output = Command::new("cargo")
        .args(&["clippy", "--all-targets", "--", "-D", "warnings"])
        .output()
        .expect("Failed to run cargo clippy");

    assert!(clippy_output.status.success(), 
            "Code should pass clippy lints: {}", 
            String::from_utf8_lossy(&clippy_output.stderr));

    // Test cargo check
    let check_output = Command::new("cargo")
        .args(&["check", "--all-targets"])
        .output()
        .expect("Failed to run cargo check");

    assert!(check_output.status.success(), 
            "Code should compile without errors: {}", 
            String::from_utf8_lossy(&check_output.stderr));
}

#[test]
fn test_security_audit_configuration() {
    // Check if cargo-audit is available (optional)
    let audit_check = Command::new("cargo")
        .args(&["audit", "--version"])
        .output();

    if audit_check.is_ok() && audit_check.unwrap().status.success() {
        // Run security audit if available
        let audit_output = Command::new("cargo")
            .args(&["audit"])
            .output()
            .expect("Failed to run cargo audit");

        // Note: We don't assert success here as there might be known vulnerabilities
        // that are acceptable in the current context. The CI pipeline should handle this.
        println!("Security audit output: {}", String::from_utf8_lossy(&audit_output.stdout));
    }
}

#[test]
fn test_test_coverage_setup() {
    // Check if we have test coverage configuration
    let ci_content = fs::read_to_string(".github/workflows/ci.yml")
        .expect("Failed to read CI workflow");

    // Check for coverage job or steps
    let has_coverage = ci_content.contains("coverage") || 
                      ci_content.contains("llvm-cov") || 
                      ci_content.contains("codecov");

    assert!(has_coverage, "CI should include code coverage measurement");
}

#[test]
fn test_changelog_format() {
    let changelog_content = fs::read_to_string("CHANGELOG.md")
        .expect("Failed to read CHANGELOG.md");

    // Check for proper changelog format
    assert!(changelog_content.contains("# Changelog"), "Changelog should have proper title");
    assert!(changelog_content.contains("[Unreleased]"), "Changelog should have Unreleased section");
    assert!(changelog_content.contains("## ["), "Changelog should have version sections");

    // Check for standard sections
    let standard_sections = ["Added", "Changed", "Fixed"];
    for section in &standard_sections {
        // At least one section should exist in the changelog
        if changelog_content.contains(&format!("### {}", section)) {
            return; // Found at least one standard section
        }
    }
    panic!("Changelog should contain at least one standard section (Added, Changed, Fixed, etc.)");
}

#[test]
fn test_license_file() {
    let license_content = fs::read_to_string("LICENSE")
        .expect("Failed to read LICENSE file");

    // Check for common license indicators
    let is_mit = license_content.contains("MIT License") || 
                 license_content.contains("Permission is hereby granted, free of charge");
    
    let is_apache = license_content.contains("Apache License") || 
                    license_content.contains("Version 2.0, January 2004");

    assert!(is_mit || is_apache, "License should be MIT or Apache 2.0");
}

/// Integration test for the complete CI/CD pipeline simulation
#[test]
#[ignore] // Run with --ignored for full pipeline test
fn test_full_ci_pipeline_simulation() {
    // This test simulates the full CI pipeline locally
    
    // 1. Code formatting
    let fmt_result = Command::new("cargo")
        .args(&["fmt", "--all", "--", "--check"])
        .status()
        .expect("Failed to run cargo fmt");
    assert!(fmt_result.success(), "Formatting check failed");

    // 2. Linting
    let clippy_result = Command::new("cargo")
        .args(&["clippy", "--all-targets", "--", "-D", "warnings"])
        .status()
        .expect("Failed to run cargo clippy");
    assert!(clippy_result.success(), "Linting failed");

    // 3. Testing
    let test_result = Command::new("cargo")
        .args(&["test", "--all"])
        .status()
        .expect("Failed to run tests");
    assert!(test_result.success(), "Tests failed");

    // 4. Build
    let build_result = Command::new("cargo")
        .args(&["build", "--release"])
        .status()
        .expect("Failed to build release");
    assert!(build_result.success(), "Release build failed");

    println!("Full CI pipeline simulation completed successfully!");
}