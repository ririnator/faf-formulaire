#!/bin/bash

# FAF Production Deployment Script
# Automated deployment with health checks and rollback capabilities

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../../" && pwd)"
DEPLOYMENT_DIR="$PROJECT_ROOT/deployment/production"
BACKUP_DIR="/var/backups/faf/deployments"
LOG_FILE="/var/log/faf/deployment.log"

# Load environment variables
if [ -f "$DEPLOYMENT_DIR/config/.env.production" ]; then
    source "$DEPLOYMENT_DIR/config/.env.production"
fi

# Default values
ENVIRONMENT="${ENVIRONMENT:-production}"
BACKUP_BEFORE_DEPLOY="${BACKUP_BEFORE_DEPLOY:-true}"
RUN_TESTS="${RUN_TESTS:-true}"
HEALTH_CHECK_TIMEOUT="${HEALTH_CHECK_TIMEOUT:-300}"
ROLLBACK_ON_FAILURE="${ROLLBACK_ON_FAILURE:-true}"

# Deployment metadata
DEPLOYMENT_ID="deploy-$(date +%Y%m%d-%H%M%S)"
START_TIME=$(date +%s)

log() {
    local level=$1
    shift
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [$level] $*" | tee -a "$LOG_FILE"
}

log_info() {
    log "INFO" "${BLUE}$*${NC}"
}

log_success() {
    log "SUCCESS" "${GREEN}$*${NC}"
}

log_warning() {
    log "WARNING" "${YELLOW}$*${NC}"
}

log_error() {
    log "ERROR" "${RED}$*${NC}"
}

cleanup() {
    local exit_code=$?
    
    if [ $exit_code -ne 0 ]; then
        log_error "Deployment failed with exit code $exit_code"
        
        if [ "$ROLLBACK_ON_FAILURE" = "true" ] && [ -n "$PREVIOUS_DEPLOYMENT" ]; then
            log_warning "Initiating automatic rollback..."
            rollback_deployment "$PREVIOUS_DEPLOYMENT"
        fi
    fi
    
    # Clean up temporary files
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf "$TEMP_DIR"
    fi
    
    exit $exit_code
}

trap cleanup EXIT

show_help() {
    cat << EOF
FAF Production Deployment Script

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --environment <env>     Target environment (default: production)
    --skip-backup          Skip pre-deployment backup
    --skip-tests           Skip test execution
    --skip-health-check    Skip health check after deployment
    --force                Force deployment without confirmations
    --rollback <id>        Rollback to specific deployment
    --list-deployments     List available deployments
    --help                 Show this help message

EXAMPLES:
    $0                                    # Full deployment with all checks
    $0 --skip-tests --force              # Quick deployment without tests
    $0 --rollback deploy-20231215-143022 # Rollback to specific deployment

EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --skip-backup)
                BACKUP_BEFORE_DEPLOY="false"
                shift
                ;;
            --skip-tests)
                RUN_TESTS="false"
                shift
                ;;
            --skip-health-check)
                SKIP_HEALTH_CHECK="true"
                shift
                ;;
            --force)
                FORCE="true"
                shift
                ;;
            --rollback)
                ROLLBACK_ID="$2"
                shift 2
                ;;
            --list-deployments)
                list_deployments
                exit 0
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

validate_environment() {
    log_info "Validating deployment environment..."
    
    # Check if running as root or with sudo
    if [[ $EUID -eq 0 ]]; then
        log_warning "Running as root. Consider using a dedicated deployment user."
    fi
    
    # Check required commands
    local required_commands=("docker" "docker-compose" "git" "curl" "jq")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command not found: $cmd"
            exit 1
        fi
    done
    
    # Check disk space
    local available_space=$(df /var/lib/docker --output=avail | tail -n1)
    if [ "$available_space" -lt 5242880 ]; then  # 5GB in KB
        log_error "Insufficient disk space. At least 5GB required."
        exit 1
    fi
    
    # Validate environment configuration
    if [ "$ENVIRONMENT" = "production" ]; then
        node "$DEPLOYMENT_DIR/config/production-validation.js"
    fi
    
    log_success "Environment validation completed"
}

pre_deployment_backup() {
    if [ "$BACKUP_BEFORE_DEPLOY" != "true" ]; then
        log_info "Skipping pre-deployment backup"
        return
    fi
    
    log_info "Creating pre-deployment backup..."
    
    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    
    # Run backup system
    node "$DEPLOYMENT_DIR/backup/backup-cli.js" backup
    
    if [ $? -eq 0 ]; then
        log_success "Pre-deployment backup completed"
    else
        log_error "Pre-deployment backup failed"
        exit 1
    fi
}

run_tests() {
    if [ "$RUN_TESTS" != "true" ]; then
        log_info "Skipping tests"
        return
    fi
    
    log_info "Running tests..."
    
    cd "$PROJECT_ROOT"
    
    # Run backend tests
    cd backend
    npm test
    
    # Run frontend tests
    cd ../frontend
    npm test
    
    cd "$PROJECT_ROOT"
    
    log_success "All tests passed"
}

get_current_deployment() {
    if [ -f "/var/lib/faf/current_deployment" ]; then
        cat "/var/lib/faf/current_deployment"
    fi
}

stop_current_services() {
    log_info "Stopping current services..."
    
    cd "$DEPLOYMENT_DIR"
    
    if docker-compose -f docker/docker-compose.production.yml ps &>/dev/null; then
        docker-compose -f docker/docker-compose.production.yml down --timeout 30
    fi
    
    log_success "Services stopped"
}

deploy_new_version() {
    log_info "Deploying new version..."
    
    cd "$DEPLOYMENT_DIR"
    
    # Create deployment metadata
    create_deployment_metadata
    
    # Build and start services
    docker-compose -f docker/docker-compose.production.yml build --no-cache
    docker-compose -f docker/docker-compose.production.yml up -d
    
    # Wait for services to start
    sleep 30
    
    log_success "New version deployed"
}

create_deployment_metadata() {
    local metadata_dir="/var/lib/faf/deployments/$DEPLOYMENT_ID"
    mkdir -p "$metadata_dir"
    
    # Create metadata file
    cat > "$metadata_dir/metadata.json" << EOF
{
    "id": "$DEPLOYMENT_ID",
    "timestamp": "$(date -Iseconds)",
    "environment": "$ENVIRONMENT",
    "git_commit": "$(git rev-parse HEAD)",
    "git_branch": "$(git rev-parse --abbrev-ref HEAD)",
    "deployer": "$USER",
    "hostname": "$(hostname)",
    "backup_id": "$BACKUP_ID",
    "docker_images": $(docker-compose -f docker/docker-compose.production.yml images --format json | jq -s '.')
}
EOF
    
    # Save current deployment reference
    echo "$DEPLOYMENT_ID" > "/var/lib/faf/current_deployment"
    
    log_info "Deployment metadata created: $metadata_dir"
}

health_check() {
    if [ "$SKIP_HEALTH_CHECK" = "true" ]; then
        log_info "Skipping health check"
        return
    fi
    
    log_info "Performing health check..."
    
    local max_attempts=$((HEALTH_CHECK_TIMEOUT / 10))
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        log_info "Health check attempt $attempt/$max_attempts"
        
        # Check application health
        if curl -f -s "http://localhost:${PORT:-3000}/health" > /dev/null; then
            log_success "Application health check passed"
            break
        fi
        
        if [ $attempt -eq $max_attempts ]; then
            log_error "Health check failed after $max_attempts attempts"
            return 1
        fi
        
        sleep 10
        ((attempt++))
    done
    
    # Additional checks
    check_database_connectivity
    check_ssl_certificates
    
    log_success "All health checks passed"
}

check_database_connectivity() {
    log_info "Checking database connectivity..."
    
    # Use MongoDB health check
    if docker exec faf-mongodb mongosh --eval "db.adminCommand('ping')" > /dev/null 2>&1; then
        log_success "Database connectivity check passed"
    else
        log_error "Database connectivity check failed"
        return 1
    fi
}

check_ssl_certificates() {
    if [ "$HTTPS" != "true" ]; then
        return
    fi
    
    log_info "Checking SSL certificates..."
    
    local domain="${COOKIE_DOMAIN:-localhost}"
    
    if openssl s_client -connect "${domain}:443" -servername "$domain" < /dev/null 2>/dev/null | \
       openssl x509 -checkend 86400 > /dev/null; then
        log_success "SSL certificate check passed"
    else
        log_warning "SSL certificate check failed or certificate expires within 24 hours"
    fi
}

post_deployment_tasks() {
    log_info "Running post-deployment tasks..."
    
    # Clear application caches
    docker exec faf-app node -e "
        // Clear any application caches here
        console.log('Application caches cleared');
    " || true
    
    # Update monitoring configurations
    docker restart faf-monitoring || true
    
    # Send deployment notification
    send_deployment_notification
    
    log_success "Post-deployment tasks completed"
}

send_deployment_notification() {
    local webhook_url="$DEPLOYMENT_WEBHOOK_URL"
    
    if [ -n "$webhook_url" ]; then
        local payload=$(cat << EOF
{
    "text": "✅ FAF deployment completed successfully",
    "deployment_id": "$DEPLOYMENT_ID",
    "environment": "$ENVIRONMENT",
    "timestamp": "$(date -Iseconds)",
    "deployer": "$USER"
}
EOF
        )
        
        curl -X POST -H "Content-Type: application/json" -d "$payload" "$webhook_url" || true
    fi
}

rollback_deployment() {
    local rollback_id="$1"
    
    if [ -z "$rollback_id" ]; then
        log_error "Rollback ID not specified"
        return 1
    fi
    
    log_info "Rolling back to deployment: $rollback_id"
    
    local metadata_file="/var/lib/faf/deployments/$rollback_id/metadata.json"
    
    if [ ! -f "$metadata_file" ]; then
        log_error "Deployment metadata not found: $metadata_file"
        return 1
    fi
    
    # Stop current services
    stop_current_services
    
    # Restore from backup if available
    local backup_id=$(jq -r '.backup_id' "$metadata_file")
    if [ "$backup_id" != "null" ] && [ -n "$backup_id" ]; then
        log_info "Restoring from backup: $backup_id"
        node "$DEPLOYMENT_DIR/backup/backup-cli.js" restore "$backup_id" --yes
    fi
    
    # Update current deployment reference
    echo "$rollback_id" > "/var/lib/faf/current_deployment"
    
    # Restart services
    deploy_new_version
    
    log_success "Rollback completed successfully"
}

list_deployments() {
    log_info "Available deployments:"
    
    if [ ! -d "/var/lib/faf/deployments" ]; then
        log_info "No deployments found"
        return
    fi
    
    local current=$(get_current_deployment)
    
    for deployment in /var/lib/faf/deployments/*/; do
        if [ -d "$deployment" ]; then
            local id=$(basename "$deployment")
            local metadata_file="$deployment/metadata.json"
            
            if [ -f "$metadata_file" ]; then
                local timestamp=$(jq -r '.timestamp' "$metadata_file")
                local deployer=$(jq -r '.deployer' "$metadata_file")
                local current_marker=""
                
                if [ "$id" = "$current" ]; then
                    current_marker=" (current)"
                fi
                
                echo "  $id - $timestamp by $deployer$current_marker"
            else
                echo "  $id - (metadata missing)"
            fi
        fi
    done
}

show_deployment_summary() {
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    
    log_success "=========================="
    log_success "Deployment completed successfully!"
    log_success "Deployment ID: $DEPLOYMENT_ID"
    log_success "Duration: ${duration}s"
    log_success "Environment: $ENVIRONMENT"
    log_success "=========================="
}

main() {
    log_info "Starting FAF production deployment..."
    log_info "Deployment ID: $DEPLOYMENT_ID"
    
    # Parse command line arguments
    parse_arguments "$@"
    
    # Handle rollback request
    if [ -n "$ROLLBACK_ID" ]; then
        rollback_deployment "$ROLLBACK_ID"
        exit 0
    fi
    
    # Get current deployment for potential rollback
    PREVIOUS_DEPLOYMENT=$(get_current_deployment)
    
    # Create log directory
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Main deployment flow
    validate_environment
    
    if [ "$FORCE" != "true" ]; then
        echo -n "Continue with deployment to $ENVIRONMENT? (y/N): "
        read -r confirm
        if [[ ! $confirm =~ ^[Yy]$ ]]; then
            log_info "Deployment cancelled by user"
            exit 0
        fi
    fi
    
    pre_deployment_backup
    run_tests
    stop_current_services
    deploy_new_version
    health_check
    post_deployment_tasks
    show_deployment_summary
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi