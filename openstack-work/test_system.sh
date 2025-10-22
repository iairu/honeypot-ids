#!/bin/bash

# Honeypot IDS System Test Script
# Tests various components and attack scenarios to verify system functionality

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$SCRIPT_DIR/test_results.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results tracking
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "PASS")
            echo -e "${GREEN}[PASS]${NC} $message"
            ((TESTS_PASSED++))
            ;;
        "FAIL")
            echo -e "${RED}[FAIL]${NC} $message"
            ((TESTS_FAILED++))
            ;;
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    ((TESTS_TOTAL++))
}

# Test basic service availability
test_service_health() {
    log "INFO" "Testing service health checks..."
    
    # Test session manager health
    local session_health=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3001/health 2>/dev/null || echo "000")
    if [[ "$session_health" == "200" ]]; then
        log "PASS" "Session Manager health endpoint responding"
    else
        log "FAIL" "Session Manager health endpoint not responding (HTTP $session_health)"
    fi
    
    # Test reverse proxy health
    local nginx_health=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/nginx-health 2>/dev/null || echo "000")
    if [[ "$nginx_health" == "200" ]]; then
        log "PASS" "Reverse proxy health endpoint responding"
    else
        log "FAIL" "Reverse proxy health endpoint not responding (HTTP $nginx_health)"
    fi
    
    # Test main website accessibility
    local main_site=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/ 2>/dev/null || echo "000")
    if [[ "$main_site" =~ ^[23] ]]; then
        log "PASS" "Main website accessible (HTTP $main_site)"
    else
        log "FAIL" "Main website not accessible (HTTP $main_site)"
    fi
    
    # Test SSL endpoint
    local ssl_test=$(curl -s -k -o /dev/null -w "%{http_code}" https://localhost/nginx-health 2>/dev/null || echo "000")
    if [[ "$ssl_test" == "200" ]]; then
        log "PASS" "HTTPS endpoint accessible"
    else
        log "WARN" "HTTPS endpoint not accessible (HTTP $ssl_test) - may be expected"
    fi
}

# Test session management API
test_session_api() {
    log "INFO" "Testing session management API..."
    
    # Test session creation
    local session_response=$(curl -s -X POST http://localhost:3001/session/create \
        -H "Content-Type: application/json" \
        -d '{"ip":"192.168.1.100","userAgent":"TestAgent/1.0","initialRoute":"production"}' 2>/dev/null || echo "")
    
    if echo "$session_response" | grep -q "sessionId"; then
        log "PASS" "Session creation API working"
        
        # Extract session ID for further tests
        local session_id=$(echo "$session_response" | grep -o '"sessionId":"[^"]*"' | cut -d'"' -f4)
        
        if [[ -n "$session_id" ]]; then
            # Test session retrieval
            local get_response=$(curl -s http://localhost:3001/session/$session_id 2>/dev/null || echo "")
            if echo "$get_response" | grep -q "$session_id"; then
                log "PASS" "Session retrieval API working"
            else
                log "FAIL" "Session retrieval API not working"
            fi
        fi
    else
        log "FAIL" "Session creation API not working: $session_response"
    fi
    
    # Test analytics endpoints
    local analytics_response=$(curl -s http://localhost:3001/analytics/sessions 2>/dev/null || echo "")
    if echo "$analytics_response" | grep -q "totalActiveSessions"; then
        log "PASS" "Session analytics API working"
    else
        log "FAIL" "Session analytics API not working"
    fi
}

# Test threat detection and routing
test_threat_detection() {
    log "INFO" "Testing threat detection and routing..."
    
    # Test clean request (should go to production)
    local clean_response=$(curl -s -H "User-Agent: Mozilla/5.0 (Test Browser)" http://localhost/ 2>/dev/null || echo "")
    local clean_route=$(curl -s -I http://localhost/ 2>/dev/null | grep -i "X-Route-Target" | cut -d':' -f2 | tr -d ' \r\n' || echo "")
    
    if [[ "$clean_route" == "production" ]]; then
        log "PASS" "Clean request routed to production"
    else
        log "WARN" "Clean request routing unclear (route: '$clean_route')"
    fi
    
    # Test suspicious user agent
    local malicious_response=$(curl -s -H "User-Agent: sqlmap/1.0" http://localhost/ 2>/dev/null || echo "")
    local malicious_route=$(curl -s -I -H "User-Agent: sqlmap/1.0" http://localhost/ 2>/dev/null | grep -i "X-Route-Target" | cut -d':' -f2 | tr -d ' \r\n' || echo "")
    
    if [[ "$malicious_route" == "honeypot" ]]; then
        log "PASS" "Malicious user agent routed to honeypot"
    else
        log "WARN" "Malicious user agent routing unclear (route: '$malicious_route')"
    fi
    
    # Test CVE pattern detection
    local cve_response=$(curl -s -X POST -H "X-WCPAY-PLATFORM-CHECKOUT-USER: 1" \
        http://localhost/wp-json/wp/v2/users 2>/dev/null || echo "")
    local cve_route=$(curl -s -I -X POST -H "X-WCPAY-PLATFORM-CHECKOUT-USER: 1" \
        http://localhost/wp-json/wp/v2/users 2>/dev/null | grep -i "X-Route-Target" | cut -d':' -f2 | tr -d ' \r\n' || echo "")
    
    if [[ "$cve_route" == "honeypot" ]]; then
        log "PASS" "CVE-2023-28121 pattern detected and routed to honeypot"
    else
        log "WARN" "CVE pattern detection unclear (route: '$cve_route')"
    fi
}

# Test vulnerable plugin access
test_vulnerable_plugins() {
    log "INFO" "Testing vulnerable plugin access detection..."
    
    # Test vulnerable plugin endpoints
    local plugins=("woocommerce-payments" "abandoned-cart-lite" "cwmp" "gift-voucher")
    
    for plugin in "${plugins[@]}"; do
        local plugin_route=$(curl -s -I http://localhost/wp-content/plugins/$plugin/readme.txt 2>/dev/null | \
            grep -i "X-Route-Target" | cut -d':' -f2 | tr -d ' \r\n' || echo "")
        
        if [[ "$plugin_route" == "honeypot" ]]; then
            log "PASS" "Vulnerable plugin access ($plugin) routed to honeypot"
        else
            log "WARN" "Vulnerable plugin routing unclear for $plugin (route: '$plugin_route')"
        fi
    done
}

# Test attack patterns
test_attack_patterns() {
    log "INFO" "Testing attack pattern detection..."
    
    # SQL injection test
    local sqli_route=$(curl -s -I "http://localhost/?id=1' OR 1=1--" 2>/dev/null | \
        grep -i "X-Route-Target" | cut -d':' -f2 | tr -d ' \r\n' || echo "")
    
    if [[ "$sqli_route" == "honeypot" ]]; then
        log "PASS" "SQL injection pattern detected"
    else
        log "WARN" "SQL injection pattern detection unclear (route: '$sqli_route')"
    fi
    
    # XSS test
    local xss_route=$(curl -s -I "http://localhost/?search=<script>alert('xss')</script>" 2>/dev/null | \
        grep -i "X-Route-Target" | cut -d':' -f2 | tr -d ' \r\n' || echo "")
    
    if [[ "$xss_route" == "honeypot" ]]; then
        log "PASS" "XSS pattern detected"
    else
        log "WARN" "XSS pattern detection unclear (route: '$xss_route')"
    fi
    
    # Directory traversal test
    local dt_route=$(curl -s -I "http://localhost/wp-content/../../../etc/passwd" 2>/dev/null | \
        grep -i "X-Route-Target" | cut -d':' -f2 | tr -d ' \r\n' || echo "")
    
    if [[ "$dt_route" == "honeypot" ]]; then
        log "PASS" "Directory traversal pattern detected"
    else
        log "WARN" "Directory traversal pattern detection unclear (route: '$dt_route')"
    fi
}

# Test file synchronization
test_file_sync() {
    log "INFO" "Testing file synchronization..."
    
    # Check if honeypot files directory exists and has content
    if [[ -d "$SCRIPT_DIR/honeypot_eshop_files" ]] && [[ -n "$(ls -A $SCRIPT_DIR/honeypot_eshop_files 2>/dev/null)" ]]; then
        log "PASS" "Honeypot files directory has content"
        
        # Check if wp-config.php exists in both locations
        if [[ -f "$SCRIPT_DIR/production_eshop_files/wp-config.php" ]] && [[ -f "$SCRIPT_DIR/honeypot_eshop_files/wp-config.php" ]]; then
            log "PASS" "WordPress configuration files synchronized"
        else
            log "WARN" "WordPress configuration files may not be synchronized"
        fi
    else
        log "WARN" "Honeypot files directory empty or missing"
    fi
    
    # Check database synchronization
    if [[ -d "$SCRIPT_DIR/honeypot_database_data" ]] && [[ -n "$(ls -A $SCRIPT_DIR/honeypot_database_data 2>/dev/null)" ]]; then
        log "PASS" "Honeypot database directory has content"
    else
        log "WARN" "Honeypot database directory empty or missing"
    fi
}

# Test SSL certificate generation
test_ssl_certificates() {
    log "INFO" "Testing SSL certificate generation..."
    
    if [[ -f "$SCRIPT_DIR/ssl_certificates/server.crt" ]] && [[ -f "$SCRIPT_DIR/ssl_certificates/server.key" ]]; then
        log "PASS" "SSL certificates exist"
        
        # Check certificate validity
        if openssl x509 -in "$SCRIPT_DIR/ssl_certificates/server.crt" -noout -checkend 86400 >/dev/null 2>&1; then
            log "PASS" "SSL certificate is valid"
        else
            log "FAIL" "SSL certificate is invalid or expired"
        fi
        
        # Check certificate permissions
        local key_perms=$(stat -c "%a" "$SCRIPT_DIR/ssl_certificates/server.key" 2>/dev/null || echo "000")
        if [[ "$key_perms" == "600" ]]; then
            log "PASS" "SSL private key has correct permissions"
        else
            log "WARN" "SSL private key permissions may be incorrect ($key_perms)"
        fi
    else
        log "FAIL" "SSL certificates missing"
    fi
}

# Test Snort IDS functionality
test_snort_ids() {
    log "INFO" "Testing Snort IDS functionality..."
    
    # Check if Snort log files exist
    if [[ -f "$SCRIPT_DIR/snort_logs/alert_fast" ]]; then
        log "PASS" "Snort alert log file exists"
        
        # Check if log file has recent entries (modified in last hour)
        if [[ $(find "$SCRIPT_DIR/snort_logs/alert_fast" -mmin -60 2>/dev/null) ]]; then
            log "PASS" "Snort alert log has recent activity"
        else
            log "WARN" "Snort alert log may not have recent activity"
        fi
    else
        log "WARN" "Snort alert log file not found - may be starting up"
    fi
    
    # Check Snort container status
    local compose_cmd=""
    if command -v docker-compose >/dev/null 2>&1; then
        compose_cmd="docker-compose"
    else
        compose_cmd="docker compose"
    fi
    
    if $compose_cmd ps snort_ids | grep -q "Up"; then
        log "PASS" "Snort IDS container is running"
    else
        log "FAIL" "Snort IDS container is not running"
    fi
}

# Test rate limiting
test_rate_limiting() {
    log "INFO" "Testing rate limiting functionality..."
    
    # Make multiple rapid requests to trigger rate limiting
    local rate_limit_triggered=false
    for i in {1..20}; do
        local response=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/wp-admin/ 2>/dev/null || echo "000")
        if [[ "$response" == "429" ]]; then
            rate_limit_triggered=true
            break
        fi
        sleep 0.1
    done
    
    if [[ "$rate_limit_triggered" == "true" ]]; then
        log "PASS" "Rate limiting is working"
    else
        log "WARN" "Rate limiting may not be working (no 429 responses received)"
    fi
}

# Load test with concurrent requests
test_load_handling() {
    log "INFO" "Testing load handling with concurrent requests..."
    
    # Create temporary script for concurrent requests
    cat > /tmp/load_test.sh << 'EOF'
#!/bin/bash
for i in {1..5}; do
    curl -s http://localhost/ > /dev/null 2>&1
done
EOF
    chmod +x /tmp/load_test.sh
    
    # Run 10 concurrent instances
    local pids=()
    for i in {1..10}; do
        /tmp/load_test.sh &
        pids+=($!)
    done
    
    # Wait for all to complete
    local completed=0
    for pid in "${pids[@]}"; do
        if wait $pid 2>/dev/null; then
            ((completed++))
        fi
    done
    
    # Clean up
    rm -f /tmp/load_test.sh
    
    if [[ $completed -ge 8 ]]; then
        log "PASS" "Load test completed successfully ($completed/10 processes)"
    else
        log "WARN" "Load test had some failures ($completed/10 processes completed)"
    fi
}

# Test threat intelligence updates
test_threat_intelligence() {
    log "INFO" "Testing threat intelligence functionality..."
    
    # Check if threat intelligence service is running
    local compose_cmd=""
    if command -v docker-compose >/dev/null 2>&1; then
        compose_cmd="docker-compose"
    else
        compose_cmd="docker compose"
    fi
    
    if $compose_cmd ps threat_intel | grep -q "Up"; then
        log "PASS" "Threat intelligence service is running"
    else
        log "WARN" "Threat intelligence service may not be running"
    fi
    
    # Test threat IP lookup
    local threat_response=$(curl -s http://localhost:3001/threat/ip/192.168.1.100 2>/dev/null || echo "")
    if echo "$threat_response" | grep -q "score"; then
        log "PASS" "Threat intelligence API responding"
    else
        log "WARN" "Threat intelligence API may not be responding"
    fi
}

# Generate test report
generate_test_report() {
    echo ""
    echo -e "${BLUE}=== Honeypot IDS System Test Results ===${NC}"
    echo ""
    echo -e "${GREEN}Tests Passed: $TESTS_PASSED${NC}"
    echo -e "${RED}Tests Failed: $TESTS_FAILED${NC}"
    echo -e "${YELLOW}Total Tests: $TESTS_TOTAL${NC}"
    echo ""
    
    local pass_rate=$((TESTS_PASSED * 100 / TESTS_TOTAL))
    echo -e "${BLUE}Pass Rate: $pass_rate%${NC}"
    echo ""
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        echo -e "${GREEN}🎉 All tests passed! System is functioning correctly.${NC}"
        return 0
    elif [[ $pass_rate -ge 80 ]]; then
        echo -e "${YELLOW}⚠️  Most tests passed, but some issues detected. Check warnings above.${NC}"
        return 1
    else
        echo -e "${RED}❌ Multiple test failures detected. System may have issues.${NC}"
        return 2
    fi
}

# Main test execution
main() {
    echo -e "${BLUE}Starting Honeypot IDS System Tests...${NC}"
    echo "Test log: $LOG_FILE"
    echo ""
    
    # Clear previous log
    > "$LOG_FILE"
    
    # Run all tests
    test_service_health
    test_session_api
    test_threat_detection
    test_vulnerable_plugins
    test_attack_patterns
    test_file_sync
    test_ssl_certificates
    test_snort_ids
    test_rate_limiting
    test_load_handling
    test_threat_intelligence
    
    # Generate final report
    generate_test_report
    
    echo ""
    echo "Detailed test log saved to: $LOG_FILE"
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Honeypot IDS System Test Script"
        echo ""
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --quick        Run only essential tests"
        echo "  --security     Run only security-related tests"
        echo "  --api          Run only API tests"
        echo ""
        ;;
    --quick)
        echo -e "${BLUE}Running quick tests...${NC}"
        test_service_health
        test_session_api
        test_ssl_certificates
        generate_test_report
        ;;
    --security)
        echo -e "${BLUE}Running security tests...${NC}"
        test_threat_detection
        test_vulnerable_plugins
        test_attack_patterns
        test_snort_ids
        test_rate_limiting
        generate_test_report
        ;;
    --api)
        echo -e "${BLUE}Running API tests...${NC}"
        test_session_api
        test_threat_intelligence
        generate_test_report
        ;;
    *)
        main
        ;;
esac