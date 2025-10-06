#!/bin/bash
# FerriteDB Deployment Testing Script

# This script runs comprehensive deployment tests including:
# - Docker container builds and health checks
# - Docker Compose development environment
# - CI/CD pipeline validation
# - Security and performance checks

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_IMAGE="ferritedb:deployment-test"
TEST_TIMEOUT=300 # 5 minutes

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up test resources..."
    
    # Stop and remove test containers
    docker ps -aq --filter "name=ferritedb-deploy-test*" | xargs -r docker rm -f
    
    # Remove test volumes
    docker volume ls -q --filter "name=ferritedb-deploy-test*" | xargs -r docker volume rm
    
    # Stop docker-compose if running
    if [ -f "$PROJECT_ROOT/docker-compose.dev.yml" ]; then
        cd "$PROJECT_ROOT"
        docker-compose -f docker-compose.dev.yml down -v --remove-orphans 2>/dev/null || true
    fi
    
    log_info "Cleanup completed"
}

# Set up trap for cleanup
trap cleanup EXIT

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "docker-compose is not installed or not in PATH"
        exit 1
    fi
    
    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    # Check Rust/Cargo
    if ! command -v cargo &> /dev/null; then
        log_error "Cargo is not installed or not in PATH"
        exit 1
    fi
    
    log_success "All prerequisites are available"
}

# Test Docker build
test_docker_build() {
    log_info "Testing Docker build..."
    
    cd "$PROJECT_ROOT"
    
    # Build the Docker image
    if docker build -t "$TEST_IMAGE" .; then
        log_success "Docker build completed successfully"
    else
        log_error "Docker build failed"
        return 1
    fi
    
    # Check image size (should be reasonable)
    IMAGE_SIZE=$(docker images "$TEST_IMAGE" --format "table {{.Size}}" | tail -n 1)
    log_info "Built image size: $IMAGE_SIZE"
    
    # Basic image inspection
    docker inspect "$TEST_IMAGE" > /dev/null
    log_success "Docker image inspection passed"
}

# Test container startup and health
test_container_health() {
    log_info "Testing container health..."
    
    # Start container
    CONTAINER_ID=$(docker run -d \
        --name "ferritedb-deploy-test-health" \
        -p "8090:8090" \
        -e "FERRITEDB_AUTH_JWT_SECRET=test-secret-$(date +%s)" \
        "$TEST_IMAGE")
    
    log_info "Started container: $CONTAINER_ID"
    
    # Wait for container to be ready
    log_info "Waiting for container to be ready..."
    local attempts=0
    local max_attempts=30
    
    while [ $attempts -lt $max_attempts ]; do
        if curl -f -s http://localhost:8090/healthz > /dev/null 2>&1; then
            log_success "Container health check passed"
            break
        fi
        
        attempts=$((attempts + 1))
        sleep 2
        
        if [ $attempts -eq $max_attempts ]; then
            log_error "Container failed to become healthy within timeout"
            docker logs "ferritedb-deploy-test-health"
            return 1
        fi
    done
    
    # Test readiness endpoint
    if curl -f -s http://localhost:8090/readyz > /dev/null; then
        log_success "Container readiness check passed"
    else
        log_error "Container readiness check failed"
        return 1
    fi
    
    # Test basic API functionality
    log_info "Testing basic API functionality..."
    
    # Test user registration
    REGISTER_RESPONSE=$(curl -s -w "%{http_code}" -o /tmp/register_response.json \
        -X POST http://localhost:8090/api/auth/register \
        -H "Content-Type: application/json" \
        -d '{"email":"test@example.com","password":"test123456","role":"admin"}')
    
    if [ "$REGISTER_RESPONSE" = "201" ]; then
        log_success "User registration test passed"
    else
        log_error "User registration test failed (HTTP $REGISTER_RESPONSE)"
        cat /tmp/register_response.json
        return 1
    fi
    
    # Test login
    LOGIN_RESPONSE=$(curl -s -w "%{http_code}" -o /tmp/login_response.json \
        -X POST http://localhost:8090/api/auth/login \
        -H "Content-Type: application/json" \
        -d '{"email":"test@example.com","password":"test123456"}')
    
    if [ "$LOGIN_RESPONSE" = "200" ]; then
        log_success "User login test passed"
    else
        log_error "User login test failed (HTTP $LOGIN_RESPONSE)"
        cat /tmp/login_response.json
        return 1
    fi
    
    # Stop container
    docker stop "ferritedb-deploy-test-health" > /dev/null
    log_success "Container health tests completed"
}

# Test Docker Compose setup
test_docker_compose() {
    log_info "Testing Docker Compose setup..."
    
    cd "$PROJECT_ROOT"
    
    # Start services
    if docker-compose -f docker-compose.dev.yml up -d ferritedb-dev; then
        log_success "Docker Compose services started"
    else
        log_error "Failed to start Docker Compose services"
        return 1
    fi
    
    # Wait for service to be ready
    log_info "Waiting for Docker Compose service to be ready..."
    local attempts=0
    local max_attempts=30
    
    while [ $attempts -lt $max_attempts ]; do
        if curl -f -s http://localhost:8090/healthz > /dev/null 2>&1; then
            log_success "Docker Compose service health check passed"
            break
        fi
        
        attempts=$((attempts + 1))
        sleep 3
        
        if [ $attempts -eq $max_attempts ]; then
            log_error "Docker Compose service failed to become healthy"
            docker-compose -f docker-compose.dev.yml logs ferritedb-dev
            return 1
        fi
    done
    
    # Test admin interface accessibility
    ADMIN_RESPONSE=$(curl -s -w "%{http_code}" -o /dev/null http://localhost:8090/admin)
    if [ "$ADMIN_RESPONSE" = "200" ] || [ "$ADMIN_RESPONSE" = "302" ]; then
        log_success "Admin interface accessibility test passed"
    else
        log_error "Admin interface not accessible (HTTP $ADMIN_RESPONSE)"
        return 1
    fi
    
    # Stop services
    docker-compose -f docker-compose.dev.yml down -v > /dev/null
    log_success "Docker Compose tests completed"
}

# Test container security
test_container_security() {
    log_info "Testing container security..."
    
    # Start container for security tests
    CONTAINER_ID=$(docker run -d \
        --name "ferritedb-deploy-test-security" \
        -e "FERRITEDB_AUTH_JWT_SECRET=test-secret-security" \
        "$TEST_IMAGE")
    
    # Check that container runs as non-root
    USER_CHECK=$(docker exec "$CONTAINER_ID" whoami)
    if [ "$USER_CHECK" != "root" ]; then
        log_success "Container runs as non-root user ($USER_CHECK)"
    else
        log_error "Container is running as root user"
        return 1
    fi
    
    # Check file permissions
    PERMISSIONS_CHECK=$(docker exec "$CONTAINER_ID" ls -la /app/data 2>/dev/null || echo "directory not found")
    if [[ "$PERMISSIONS_CHECK" != *"directory not found"* ]]; then
        log_success "Data directory permissions check passed"
    else
        log_warning "Data directory not found (may be created on first run)"
    fi
    
    # Stop container
    docker stop "$CONTAINER_ID" > /dev/null
    log_success "Container security tests completed"
}

# Test volume persistence
test_volume_persistence() {
    log_info "Testing volume persistence..."
    
    # Create test volume
    docker volume create ferritedb-deploy-test-volume > /dev/null
    
    # Start first container with volume
    CONTAINER1_ID=$(docker run -d \
        --name "ferritedb-deploy-test-persist1" \
        -p "8091:8090" \
        -v "ferritedb-deploy-test-volume:/app/data" \
        -e "FERRITEDB_AUTH_JWT_SECRET=test-secret-persist" \
        "$TEST_IMAGE")
    
    # Wait for container to be ready
    local attempts=0
    while [ $attempts -lt 20 ]; do
        if curl -f -s http://localhost:8091/healthz > /dev/null 2>&1; then
            break
        fi
        attempts=$((attempts + 1))
        sleep 2
    done
    
    # Create test data
    curl -s -X POST http://localhost:8091/api/auth/register \
        -H "Content-Type: application/json" \
        -d '{"email":"persist@test.com","password":"test123456","role":"admin"}' > /dev/null
    
    # Stop first container
    docker stop "$CONTAINER1_ID" > /dev/null
    docker rm "$CONTAINER1_ID" > /dev/null
    
    # Start second container with same volume
    CONTAINER2_ID=$(docker run -d \
        --name "ferritedb-deploy-test-persist2" \
        -p "8091:8090" \
        -v "ferritedb-deploy-test-volume:/app/data" \
        -e "FERRITEDB_AUTH_JWT_SECRET=test-secret-persist" \
        "$TEST_IMAGE")
    
    # Wait for container to be ready
    attempts=0
    while [ $attempts -lt 20 ]; do
        if curl -f -s http://localhost:8091/healthz > /dev/null 2>&1; then
            break
        fi
        attempts=$((attempts + 1))
        sleep 2
    done
    
    # Test if data persisted
    LOGIN_RESPONSE=$(curl -s -w "%{http_code}" -o /dev/null \
        -X POST http://localhost:8091/api/auth/login \
        -H "Content-Type: application/json" \
        -d '{"email":"persist@test.com","password":"test123456"}')
    
    if [ "$LOGIN_RESPONSE" = "200" ]; then
        log_success "Volume persistence test passed"
    else
        log_error "Volume persistence test failed - data not persisted"
        return 1
    fi
    
    # Cleanup
    docker stop "$CONTAINER2_ID" > /dev/null
    docker rm "$CONTAINER2_ID" > /dev/null
    docker volume rm "ferritedb-deploy-test-volume" > /dev/null
    
    log_success "Volume persistence tests completed"
}

# Test CI/CD configuration
test_ci_cd_config() {
    log_info "Testing CI/CD configuration..."
    
    cd "$PROJECT_ROOT"
    
    # Run CI/CD tests
    if cargo test ci_cd_tests --test ci_cd_tests; then
        log_success "CI/CD configuration tests passed"
    else
        log_error "CI/CD configuration tests failed"
        return 1
    fi
    
    # Test local CI simulation
    log_info "Running local CI simulation..."
    
    # Format check
    if cargo fmt --all -- --check; then
        log_success "Code formatting check passed"
    else
        log_error "Code formatting check failed"
        return 1
    fi
    
    # Clippy check
    if cargo clippy --all-targets -- -D warnings; then
        log_success "Clippy linting check passed"
    else
        log_error "Clippy linting check failed"
        return 1
    fi
    
    # Build check
    if cargo check --all-targets; then
        log_success "Build check passed"
    else
        log_error "Build check failed"
        return 1
    fi
    
    log_success "CI/CD configuration tests completed"
}

# Performance baseline test
test_performance_baseline() {
    log_info "Running performance baseline test..."
    
    # Start container for performance testing
    CONTAINER_ID=$(docker run -d \
        --name "ferritedb-deploy-test-perf" \
        -p "8092:8090" \
        -e "FERRITEDB_AUTH_JWT_SECRET=test-secret-perf" \
        "$TEST_IMAGE")
    
    # Wait for container to be ready
    local attempts=0
    while [ $attempts -lt 20 ]; do
        if curl -f -s http://localhost:8092/healthz > /dev/null 2>&1; then
            break
        fi
        attempts=$((attempts + 1))
        sleep 2
    done
    
    # Simple performance test with curl
    log_info "Testing response times..."
    
    # Test health endpoint response time
    HEALTH_TIME=$(curl -w "%{time_total}" -s -o /dev/null http://localhost:8092/healthz)
    log_info "Health endpoint response time: ${HEALTH_TIME}s"
    
    # Test multiple concurrent requests
    log_info "Testing concurrent requests..."
    for i in {1..10}; do
        curl -s http://localhost:8092/healthz > /dev/null &
    done
    wait
    
    log_success "Basic performance test completed"
    
    # Stop container
    docker stop "$CONTAINER_ID" > /dev/null
}

# Main test runner
run_tests() {
    local test_functions=(
        "check_prerequisites"
        "test_docker_build"
        "test_container_health"
        "test_docker_compose"
        "test_container_security"
        "test_volume_persistence"
        "test_ci_cd_config"
        "test_performance_baseline"
    )
    
    local failed_tests=()
    local total_tests=${#test_functions[@]}
    local passed_tests=0
    
    log_info "Starting deployment tests..."
    log_info "Total tests to run: $total_tests"
    echo
    
    for test_func in "${test_functions[@]}"; do
        log_info "Running: $test_func"
        
        if $test_func; then
            passed_tests=$((passed_tests + 1))
            log_success "$test_func completed successfully"
        else
            failed_tests+=("$test_func")
            log_error "$test_func failed"
        fi
        
        echo "----------------------------------------"
    done
    
    # Summary
    echo
    log_info "Test Summary:"
    log_info "Total tests: $total_tests"
    log_success "Passed: $passed_tests"
    
    if [ ${#failed_tests[@]} -eq 0 ]; then
        log_success "All deployment tests passed!"
        return 0
    else
        log_error "Failed: ${#failed_tests[@]}"
        log_error "Failed tests: ${failed_tests[*]}"
        return 1
    fi
}

# Script usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  --quick        Run only essential tests (faster)"
    echo "  --ci           Run in CI mode (non-interactive)"
    echo
    echo "Examples:"
    echo "  $0                 # Run all tests"
    echo "  $0 --quick         # Run essential tests only"
    echo "  $0 --ci            # Run in CI mode"
}

# Parse command line arguments
QUICK_MODE=false
CI_MODE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        --quick)
            QUICK_MODE=true
            shift
            ;;
        --ci)
            CI_MODE=true
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Set CI-specific configurations
if [ "$CI_MODE" = true ]; then
    log_info "Running in CI mode"
    # Reduce timeouts for CI
    TEST_TIMEOUT=180
fi

# Run tests
if [ "$QUICK_MODE" = true ]; then
    log_info "Running in quick mode (essential tests only)"
    # Run only essential tests
    check_prerequisites
    test_docker_build
    test_container_health
    test_ci_cd_config
    log_success "Quick deployment tests completed!"
else
    # Run all tests
    run_tests
fi