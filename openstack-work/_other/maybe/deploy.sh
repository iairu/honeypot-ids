#!/bin/bash
set -e

# Honeypot IDS System Deployment Script
# This script automates the setup and deployment of the honeypot system with Snort IDS integration

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="honeypot-ids-system"
LOG_FILE="$SCRIPT_DIR/deployment.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
        "DEBUG")
            echo -e "${BLUE}[DEBUG]${NC} $message"
            ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check system requirements
check_requirements() {
    log "INFO" "Checking system requirements..."
    
    # Check if running as root
    if [[ $EUID -eq 0 ]]; then
        log "WARN" "Running as root. This is not recommended for security reasons."
        read -p "Continue anyway? (y/N): " continue_root
        if [[ ! $continue_root =~ ^[Yy]$ ]]; then
            log "ERROR" "Deployment cancelled."
            exit 1
        fi
    fi
    
    # Check Docker
    if ! command_exists docker; then
        log "ERROR" "Docker is not installed. Please install Docker first."
        log "INFO" "Installation guide: https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command_exists docker-compose && ! docker compose version >/dev/null 2>&1; then
        log "ERROR" "Docker Compose is not installed. Please install Docker Compose first."
        log "INFO" "Installation guide: https://docs.docker.com/compose/install/"
        exit 1
    fi
    
    # Check available memory
    local available_mem=$(free -m | awk 'NR==2{print $7}')
    if [[ $available_mem -lt 4096 ]]; then
        log "WARN" "Available memory ($available_mem MB) is less than recommended 4GB"
        log "WARN" "System may experience performance issues"
    fi
    
    # Check available disk space
    local available_space=$(df "$SCRIPT_DIR" | awk 'NR==2{print $4}')
    local available_gb=$((available_space / 1024 / 1024))
    if [[ $available_gb -lt 20 ]]; then
        log "WARN" "Available disk space (${available_gb}GB) is less than recommended 20GB"
        log "WARN" "Logs and data may fill up disk space quickly"
    fi
    
    log "INFO" "System requirements check completed"
}

# Create necessary directories
create_directories() {
    log "INFO" "Creating necessary directories..."
    
    local directories=(
        "honeypot_eshop_files"
        "honeypot_database_data"
        "snort_logs"
        "redis_data"
        "redis_config"
        "ssl_certificates"
        "fluent_bit_config"
        "threat_intel_data"
        "nginx_logs"
    )
    
    for dir in "${directories[@]}"; do
        if [[ ! -d "$SCRIPT_DIR/$dir" ]]; then
            mkdir -p "$SCRIPT_DIR/$dir"
            log "INFO" "Created directory: $dir"
        fi
    done
    
    # Set proper permissions
    chmod 755 "$SCRIPT_DIR/snort_logs"
    chmod 755 "$SCRIPT_DIR/redis_data"
    chmod 755 "$SCRIPT_DIR/nginx_logs"
    
    log "INFO" "Directory creation completed"
}

# Generate environment file
generate_env_file() {
    log "INFO" "Generating environment file..."
    
    if [[ -f "$SCRIPT_DIR/.env" ]]; then
        log "WARN" ".env file already exists. Backing up to .env.backup"
        cp "$SCRIPT_DIR/.env" "$SCRIPT_DIR/.env.backup"
    fi
    
    # Generate random passwords
    local redis_password=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    local mysql_root_password=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    local mysql_prod_password=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    local mysql_honeypot_password=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)
    
    cat > "$SCRIPT_DIR/.env" << EOF
# Honeypot IDS System Environment Configuration
# Generated on $(date)

# Redis Configuration
REDIS_HOST=session_store
REDIS_PORT=6379
REDIS_PASSWORD=$redis_password

# Production Database
MYSQL_ROOT_PASSWORD=$mysql_root_password
MYSQL_PROD_PASSWORD=$mysql_prod_password

# Honeypot Database
MYSQL_HONEYPOT_PASSWORD=$mysql_honeypot_password

# Session Manager Configuration
SESSION_MANAGER_URL=http://session_manager:3001
LOG_LEVEL=info
NODE_ENV=production

# Snort Configuration
SNORT_LOG_PATH=/var/log/snort
SNORT_INTERFACE=eth0

# Security Configuration
ALLOWED_ORIGINS=http://localhost,https://localhost

# Threat Intelligence
UPDATE_INTERVAL=3600

# Nginx Configuration
SERVER_NAME=localhost
SSL_CERTIFICATE_PATH=/etc/ssl/certs/server.crt
SSL_CERTIFICATE_KEY_PATH=/etc/ssl/certs/server.key
EOF
    
    log "INFO" "Environment file generated successfully"
    log "WARN" "Please review and modify .env file as needed"
}

# Generate SSL certificates
generate_ssl_certificates() {
    log "INFO" "Generating SSL certificates..."
    
    local ssl_dir="$SCRIPT_DIR/ssl_certificates"
    local cert_file="$ssl_dir/server.crt"
    local key_file="$ssl_dir/server.key"
    
    if [[ -f "$cert_file" && -f "$key_file" ]]; then
        log "INFO" "SSL certificates already exist, skipping generation"
        return 0
    fi
    
    # Generate self-signed certificate
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$key_file" \
        -out "$cert_file" \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
        >/dev/null 2>&1
    
    if [[ $? -eq 0 ]]; then
        chmod 600 "$key_file"
        chmod 644 "$cert_file"
        log "INFO" "SSL certificates generated successfully"
    else
        log "WARN" "Failed to generate SSL certificates. HTTPS will not be available."
    fi
}

# Setup Redis configuration
setup_redis_config() {
    log "INFO" "Setting up Redis configuration..."
    
    cat > "$SCRIPT_DIR/redis_config/redis.conf" << EOF
# Redis Configuration for Honeypot IDS System

# Network
bind 0.0.0.0
port 6379

# Security
requirepass $(grep REDIS_PASSWORD "$SCRIPT_DIR/.env" | cut -d'=' -f2)

# Memory Management
maxmemory 2gb
maxmemory-policy allkeys-lru

# Persistence
save 900 1
save 300 10
save 60 10000
appendonly yes
appendfsync everysec

# Logging
loglevel notice

# Performance
tcp-keepalive 300
timeout 0

# Security enhancements
protected-mode yes
EOF
    
    log "INFO" "Redis configuration completed"
}

# Setup Fluent Bit configuration
setup_fluent_bit_config() {
    log "INFO" "Setting up Fluent Bit configuration..."
    
    mkdir -p "$SCRIPT_DIR/fluent_bit_config"
    
    cat > "$SCRIPT_DIR/fluent_bit_config/fluent-bit.conf" << EOF
[SERVICE]
    Flush         1
    Log_Level     info
    Daemon        off
    Parsers_File  parsers.conf

[INPUT]
    Name              tail
    Path              /var/log/suricata/fast.log
    Tag               suricata.alerts
    Refresh_Interval  5

[INPUT]
    Name              tail
    Path              /var/log/nginx/security.log
    Tag               nginx.security
    Refresh_Interval  5

[FILTER]
    Name              parser
    Match             suricata.alerts
    Key_Name          log
    Parser            suricata_alert

[OUTPUT]
    Name              stdout
    Match             *
    Format            json_lines
EOF

    cat > "$SCRIPT_DIR/fluent_bit_config/parsers.conf" << EOF
[PARSER]
    Name        suricata_alert
    Format      regex
    Regex       ^(?<timestamp>\d+\/\d+\/\d+\-\d+:\d+:\d+\.\d+)\s+\[\*\*\]\s+\[(?<priority>\d+):(?<sid>\d+):\d+\]\s+(?<message>.*?)\s+\[Classification:\s+(?<classification>[^\]]+)\].*?(?<src_ip>\d+\.\d+\.\d+\.\d+):(?<src_port>\d+)\s+\-\>\s+(?<dst_ip>\d+\.\d+\.\d+\.\d+):(?<dst_port>\d+)
    Time_Key    timestamp
    Time_Format %m/%d/%Y-%H:%M:%S.%L
EOF
    
    log "INFO" "Fluent Bit configuration completed"
}

# Install npm dependencies for session manager
install_session_manager_deps() {
    log "INFO" "Installing Node.js dependencies for session manager..."
    
    local session_dir="$SCRIPT_DIR/session_manager"
    
    if [[ ! -f "$session_dir/package.json" ]]; then
        log "WARN" "package.json not found in session_manager directory"
        return 1
    fi
    
    cd "$session_dir"
    if command_exists npm; then
        npm install --production >/dev/null 2>&1
        log "INFO" "Node.js dependencies installed successfully"
    else
        log "WARN" "npm not found. Dependencies will be installed in Docker container"
    fi
    cd "$SCRIPT_DIR"
}

# Build Docker images
build_docker_images() {
    log "INFO" "Building Docker images..."
    
    # Use docker-compose or docker compose based on availability
    local compose_cmd=""
    if command_exists docker-compose; then
        compose_cmd="docker-compose"
    elif docker compose version >/dev/null 2>&1; then
        compose_cmd="docker compose"
    else
        log "ERROR" "Neither docker-compose nor docker compose is available"
        exit 1
    fi
    
    log "INFO" "Building images with $compose_cmd..."
    
    # Build images without cache for clean build
    $compose_cmd build --no-cache 2>&1 | tee -a "$LOG_FILE"
    
    if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
        log "INFO" "Docker images built successfully"
    else
        log "ERROR" "Failed to build Docker images"
        exit 1
    fi
}

# Start services
start_services() {
    log "INFO" "Starting services..."
    
    local compose_cmd=""
    if command_exists docker-compose; then
        compose_cmd="docker-compose"
    else
        compose_cmd="docker compose"
    fi
    
    # Start services with proper dependency order
    log "INFO" "Starting initialization service..."
    $compose_cmd up -d init_setup 2>&1 | tee -a "$LOG_FILE"
    
    # Wait for init to complete
    log "INFO" "Waiting for initialization to complete..."
    $compose_cmd logs -f init_setup | tee -a "$LOG_FILE" &
    LOGS_PID=$!
    
    while ! $compose_cmd ps init_setup | grep -q "Exit 0"; do
        if $compose_cmd ps init_setup | grep -q "Exit"; then
            log "ERROR" "Initialization failed"
            kill $LOGS_PID 2>/dev/null || true
            exit 1
        fi
        sleep 5
    done
    kill $LOGS_PID 2>/dev/null || true
    
    log "INFO" "Starting databases..."
    $compose_cmd up -d production_database honeypot_database 2>&1 | tee -a "$LOG_FILE"
    
    # Wait for databases to be healthy
    log "INFO" "Waiting for databases to be healthy..."
    wait_for_healthy "production_database" 60
    wait_for_healthy "honeypot_database" 60
    
    log "INFO" "Starting core services..."
    $compose_cmd up -d session_store session_manager 2>&1 | tee -a "$LOG_FILE"
    
    # Wait for session services
    wait_for_healthy "session_store" 30
    wait_for_healthy "session_manager" 60
    
    log "INFO" "Starting WordPress instances..."
    $compose_cmd up -d production_eshop honeypot_eshop 2>&1 | tee -a "$LOG_FILE"
    
    # Wait for WordPress instances
    wait_for_healthy "production_eshop" 120
    wait_for_healthy "honeypot_eshop" 120
    
    log "INFO" "Starting security services..."
    $compose_cmd up -d snort_ids 2>&1 | tee -a "$LOG_FILE"
    wait_for_healthy "snort_ids" 60
    
    log "INFO" "Starting reverse proxy..."
    $compose_cmd up -d reverse_proxy 2>&1 | tee -a "$LOG_FILE"
    wait_for_healthy "reverse_proxy" 60
    
    log "INFO" "Starting remaining services..."
    $compose_cmd up -d 2>&1 | tee -a "$LOG_FILE"
    
    if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
        log "INFO" "All services started successfully"
    else
        log "ERROR" "Failed to start some services"
        exit 1
    fi
    
    # Final health check
    log "INFO" "Performing final health checks..."
    check_service_health
}

# Wait for service to be healthy
wait_for_healthy() {
    local service_name=$1
    local timeout=${2:-60}
    local compose_cmd=""
    
    if command_exists docker-compose; then
        compose_cmd="docker-compose"
    else
        compose_cmd="docker compose"
    fi
    
    log "INFO" "Waiting for $service_name to be healthy (timeout: ${timeout}s)..."
    
    local count=0
    while [[ $count -lt $timeout ]]; do
        if $compose_cmd ps $service_name | grep -q "healthy"; then
            log "INFO" "$service_name is healthy"
            return 0
        fi
        
        if $compose_cmd ps $service_name | grep -q "unhealthy"; then
            log "WARN" "$service_name is unhealthy, checking logs..."
            $compose_cmd logs --tail=10 $service_name | tee -a "$LOG_FILE"
        fi
        
        sleep 5
        count=$((count + 5))
    done
    
    log "WARN" "$service_name did not become healthy within ${timeout}s"
    return 1
}

# Check service health
check_service_health() {
    log "INFO" "Checking service health..."
    
    local compose_cmd=""
    if command_exists docker-compose; then
        compose_cmd="docker-compose"
    else
        compose_cmd="docker compose"
    fi
    
    # Check session manager health
    local session_health=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3001/health 2>/dev/null || echo "000")
    if [[ "$session_health" == "200" ]]; then
        log "INFO" "Session Manager: Healthy (HTTP $session_health)"
    else
        log "WARN" "Session Manager: Not responding (HTTP $session_health)"
    fi
    
    # Check Redis connectivity
    local redis_container=$($compose_cmd ps -q session_store)
    if [[ -n "$redis_container" ]] && docker exec "$redis_container" redis-cli ping >/dev/null 2>&1; then
        log "INFO" "Redis: Healthy"
    else
        log "WARN" "Redis: Not responding"
    fi
    
    # Check if Suricata is running
    if $compose_cmd ps suricata_ids | grep -q "Up"; then
        log "INFO" "Suricata IDS: Running"
        # Check if Suricata is actually generating logs
        if [[ -f "$SCRIPT_DIR/suricata_logs/fast.log" ]]; then
            log "INFO" "Suricata IDS: Log file created"
        else
            log "WARN" "Suricata IDS: No log file found yet"
        fi
    else
        log "WARN" "Suricata IDS: Not running"
    fi
    
    # Check reverse proxy
    local nginx_health=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/nginx-health 2>/dev/null || echo "000")
    if [[ "$nginx_health" == "200" ]]; then
        log "INFO" "Reverse Proxy: Healthy (HTTP $nginx_health)"
    else
        log "WARN" "Reverse Proxy: Not responding (HTTP $nginx_health)"
    fi
    
    # Check WordPress instances
    local prod_wp=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null || echo "000")
    if [[ "$prod_wp" =~ ^[23] ]]; then
        log "INFO" "Production WordPress: Accessible (HTTP $prod_wp)"
    else
        log "WARN" "Production WordPress: Not accessible (HTTP $prod_wp)"
    fi
    
    # Check SSL certificates
    if [[ -f "$SCRIPT_DIR/ssl_certificates/server.crt" ]] && [[ -f "$SCRIPT_DIR/ssl_certificates/server.key" ]]; then
        log "INFO" "SSL Certificates: Present"
    else
        log "WARN" "SSL Certificates: Missing"
    fi
    
    # Check file synchronization
    if [[ -d "$SCRIPT_DIR/honeypot_eshop_files" ]] && [[ -n "$(ls -A $SCRIPT_DIR/honeypot_eshop_files 2>/dev/null)" ]]; then
        log "INFO" "File Synchronization: WordPress files copied to honeypot"
    else
        log "WARN" "File Synchronization: Honeypot files directory empty"
    fi
}

# Setup WordPress instances
setup_wordpress() {
    log "INFO" "Setting up WordPress instances..."
    
    # Wait for databases to be ready
    log "INFO" "Waiting for databases to initialize..."
    sleep 45
    
    local compose_cmd=""
    if command_exists docker-compose; then
        compose_cmd="docker-compose"
    else
        compose_cmd="docker compose"
    fi
    
    # # Install WordPress CLI in production instance
    # $compose_cmd exec -T production_eshop bash -c "
    #     curl -O https://raw.githubusercontent.com/wp-cli/wp-cli/v2.8.1/utils/wp-completion.bash 2>/dev/null || true
    #     curl -o wp-cli.phar https://raw.githubusercontent.com/wp-cli/wp-cli/v2.8.1/phar/wp-cli.phar 2>/dev/null || true
    #     chmod +x wp-cli.phar
    #     mv wp-cli.phar /usr/local/bin/wp
    #     
    #     # Install WordPress if not already installed
    #     if ! wp core is-installed 2>/dev/null; then
    #         wp core install --url=http://localhost --title='Production Site' --admin_user=admin --admin_password=admin123 --admin_email=admin@localhost.local --skip-email || true
    #     fi
    # " 2>/dev/null || log "WARN" "WordPress CLI setup failed for production instance"
    # 
    # # Setup honeypot instance with vulnerable plugins
    # $compose_cmd exec -T honeypot_eshop bash -c "
    #     curl -O https://raw.githubusercontent.com/wp-cli/wp-cli/v2.8.1/utils/wp-completion.bash 2>/dev/null || true
    #     curl -o wp-cli.phar https://raw.githubusercontent.com/wp-cli/wp-cli/v2.8.1/phar/wp-cli.phar 2>/dev/null || true
    #     chmod +x wp-cli.phar
    #     mv wp-cli.phar /usr/local/bin/wp
    #     
    #     # Install WordPress if not already installed
    #     if ! wp core is-installed 2>/dev/null; then
    #         wp core install --url=http://localhost:8080 --title='Honeypot Site' --admin_user=admin --admin_password=admin123 --admin_email=admin@honeypot.local --skip-email || true
    #         
    #         # Install WooCommerce and other plugins (will be vulnerable versions in real deployment)
    #         wp plugin install woocommerce --activate || true
    #     fi
    # " 2>/dev/null || log "WARN" "WordPress CLI setup failed for honeypot instance"
    
    log "INFO" "WordPress setup completed"
}

# Display deployment summary
display_summary() {
    log "INFO" "Deployment completed successfully!"
    
    echo ""
    echo -e "${GREEN}=== Honeypot IDS System Deployment Summary ===${NC}"
    echo ""
    echo -e "${BLUE}Services:${NC}"
    echo "  - Reverse Proxy (Nginx + OpenResty): http://localhost"
    echo "  - Session Manager API: http://localhost:3001"
    echo "  - Session Manager Health: http://localhost:3001/health"
    echo "  - Production WordPress: Accessible via intelligent routing"
    echo "  - Honeypot WordPress: Accessible when suspicious activity detected"
    echo ""
    echo -e "${BLUE}Configuration Files:${NC}"
    echo "  - Environment: .env"
    echo "  - Docker Compose: docker-compose.yml"
    echo "  - Nginx Config: reverse_proxy_enhanced/nginx.conf"
    echo "  - Snort Rules: snort_rules/local.rules"
    echo ""
    echo -e "${BLUE}Log Files:${NC}"
    echo "  - Deployment: $LOG_FILE"
    echo "  - Snort Alerts: snort_logs/alert_fast"
    echo "  - Nginx Security: nginx_logs/security.log"
    echo "  - Session Manager: session_manager logs"
    echo ""
    echo -e "${BLUE}Useful Commands:${NC}"
    echo "  - View logs: docker-compose logs -f [service_name]"
    echo "  - Stop system: docker-compose down"
    echo "  - Restart: docker-compose restart [service_name]"
    echo "  - View Suricata alerts: tail -f suricata_logs/fast.log"
    echo "  - Check session analytics: curl http://localhost:3001/analytics/sessions"
    echo "  - Check service health: docker-compose ps"
    echo "  - Force file sync: docker-compose restart file_sync"
    echo "  - Regenerate SSL: docker-compose up -d --force-recreate init_setup"
    echo ""
    echo -e "${YELLOW}Important Security Notes:${NC}"
    echo "  - Change default passwords in .env file"
    echo "  - Replace self-signed SSL certificates for production use"
    echo "  - Review and customize Suricata rules for your environment"
    echo "  - Monitor log files regularly for security events"
    echo "  - Files are automatically copied from production to honeypot on startup"
    echo "  - SSL certificates are regenerated on each deployment"
    echo "  - Health checks ensure proper service startup order"
    echo ""
    echo -e "${GREEN}System is ready for testing and monitoring!${NC}"
}

# Cleanup function
cleanup() {
    log "INFO" "Performing cleanup..."
    
    # Remove temporary files if any
    rm -f "$SCRIPT_DIR"/temp_* 2>/dev/null || true
    
    log "INFO" "Cleanup completed"
}

# Error handler
error_handler() {
    local line_no=$1
    log "ERROR" "An error occurred on line $line_no. Check $LOG_FILE for details."
    cleanup
    exit 1
}

# Main deployment function
main() {
    echo -e "${BLUE}Starting Honeypot IDS System Deployment...${NC}"
    echo "Log file: $LOG_FILE"
    echo ""
    
    # Set error handler
    trap 'error_handler $LINENO' ERR
    
    # Check if we're in the right directory
    if [[ ! -f "$SCRIPT_DIR/docker-compose.yml" ]]; then
        log "ERROR" "docker-compose.yml not found. Please run this script from the project root directory."
        exit 1
    fi
    
    # Run deployment steps
    check_requirements
    create_directories
    generate_env_file
    generate_ssl_certificates
    setup_redis_config
    setup_fluent_bit_config
    install_session_manager_deps
    build_docker_images
    start_services
    setup_wordpress
    
    # Display summary
    display_summary
    
    # Cleanup
    cleanup
    
    log "INFO" "Deployment script completed successfully"
}

# Script options
case "${1:-}" in
    --help|-h)
        echo "Honeypot IDS System Deployment Script"
        echo ""
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --check        Check system requirements only"
        echo "  --rebuild      Force rebuild of all Docker images"
        echo "  --clean        Clean up all containers and data (destructive)"
        echo ""
        echo "Examples:"
        echo "  $0              # Full deployment"
        echo "  $0 --check      # Check requirements only"
        echo "  $0 --rebuild    # Rebuild and redeploy"
        ;;
    --check)
        check_requirements
        ;;
    --rebuild)
        log "INFO" "Rebuilding system..."
        docker-compose down 2>/dev/null || docker compose down 2>/dev/null || true
        docker system prune -f
        main
        ;;
    --clean)
        echo -e "${RED}WARNING: This will remove all containers, images, and data!${NC}"
        read -p "Are you sure? Type 'yes' to confirm: " confirm
        if [[ "$confirm" == "yes" ]]; then
            log "INFO" "Cleaning up system..."
            docker-compose down -v 2>/dev/null || docker compose down -v 2>/dev/null || true
            docker system prune -af --volumes
            rm -rf snort_logs/* redis_data/* nginx_logs/* 2>/dev/null || true
            log "INFO" "Cleanup completed"
        else
            log "INFO" "Cleanup cancelled"
        fi
        ;;
    *)
        main
        ;;
esac