# WordPress SQL Proxy Routing Architecture

## Overview

This document describes the implementation of SQL-level routing between production and honeypot databases based on threat analysis performed at the HTTP layer. This enables a **single WordPress frontend** to dynamically route database queries to separate backend databases depending on the threat score of each request.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                         Internet Traffic                         │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│              Nginx Reverse Proxy + Lua Threat Analysis          │
│  - Analyzes request patterns (CVE, SQLi, XSS, User-Agent)       │
│  - Calculates threat score via Redis session data               │
│  - Makes routing decision: production or honeypot                │
│  - Sets X-DB-Target header for WordPress                        │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                  Single WordPress Instance                       │
│  - Reads X-DB-Target header from Nginx                          │
│  - Custom db.php drop-in intercepts database connection         │
│  - Dynamically selects database host based on threat decision   │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    │                       │
                    ▼                       ▼
    ┌───────────────────────┐   ┌───────────────────────┐
    │  Production Database  │   │   Honeypot Database   │
    │   (Clean Data)        │   │   (Dummy/Trap Data)   │
    │   MySQL 5.7           │   │   MySQL 5.7           │
    └───────────────────────┘   └───────────────────────┘
```

## Request Flow

### 1. HTTP Request Analysis (Nginx Lua)

When a request arrives at the reverse proxy:

```lua
-- In reverse_proxy_enhanced/lua/router.lua

-- Analyze request for threats
local threat_result = threat_analyzer.analyze_request(uri, headers, remote_ip)

-- Get or create session
local session_data = session_handler.get_or_create_session()

-- Make routing decision based on threat score
local routing_decision = router.decide_route(session_data, threat_result, remote_ip)

-- Set X-DB-Target header for WordPress to read
ngx.req.set_header("X-DB-Target", routing_decision.target)
-- routing_decision.target is either "production" or "honeypot"
```

### 2. WordPress Database Connection (wp-content/db.php)

WordPress's custom database handler reads the header and connects accordingly:

```php
<?php
// In production_eshop_files/wp-content/db.php

class Honeypot_Routing_WPDB extends wpdb {
    public function db_connect($allow_bail = true) {
        // Read routing decision from Nginx header
        $db_target = $_SERVER['HTTP_X_DB_TARGET'] ?? 'production';

        // Override database host based on routing
        if ($db_target === 'honeypot') {
            $this->dbhost = 'honeypot_database:3306';
        } else {
            $this->dbhost = 'production_database:3306';
        }

        // Connect to selected database
        return parent::db_connect($allow_bail);
    }
}
```

### 3. SQL Query Execution

All subsequent SQL queries in that request use the selected database connection:

```
Clean Request Flow:
User → Nginx (threat_score: 0) → X-DB-Target: production → WordPress → Production DB

Malicious Request Flow:
Attacker → Nginx (threat_score: 85) → X-DB-Target: honeypot → WordPress → Honeypot DB
```

## Threat Detection Triggers

The following patterns trigger honeypot database routing:

### High-Priority Triggers (Immediate Honeypot Routing)

| Trigger | Threat Score | Description |
|---------|--------------|-------------|
| CVE Pattern Match | 40+ per CVE | Known WordPress vulnerability patterns |
| SQL Injection | 20-30 | `UNION SELECT`, `OR 1=1`, `DROP TABLE` |
| Malicious User-Agent | 50 | sqlmap, nikto, nmap, wpscan, etc. |
| Admin Attempts (3+) | 40 | Multiple unauthorized admin access attempts |
| Vulnerable Plugin Access | 60 | Access to known vulnerable plugin paths |
| Bad IP Reputation | 50+ | IPs from threat intelligence feeds |

### Cumulative Triggers

| Trigger | Cumulative Threshold | Description |
|---------|---------------------|-------------|
| Suspicious Activities | 5 activities | Repeated suspicious behavior |
| Rapid Automation | 20 req/sec | High-frequency automated requests |
| Admin Enumeration | 3 attempts | Scanning for admin endpoints |

### Session Binding

Once a session is routed to the honeypot:
- **All subsequent requests** from that session go to honeypot DB
- Session data is stored in Redis with `honeypot_bound: true`
- Binding persists for session lifetime (default: 1 hour)
- SQL routing follows HTTP routing decision automatically

## Database Configuration

### Network Topology

Both WordPress instances have access to both databases:

```yaml
# docker-compose.yml

production_eshop:
  networks:
    - production_network   # Access to production_database
    - honeypot_network     # Access to honeypot_database (NEW)
    - monitoring_network

honeypot_eshop:
  networks:
    - honeypot_network     # Access to honeypot_database
    - production_network   # Access to production_database (NEW)
    - monitoring_network
```

### Database Hosts

- **Production Database**: `production_database:3306` (172.20.0.0/24 network)
- **Honeypot Database**: `honeypot_database:3306` (172.21.0.0/24 network)

Both databases use the same credentials for seamless connection switching:
- User: `production_user`
- Password: `${MYSQL_PASSWORD}` (from .env)
- Database: `production_database`

## Implementation Details

### 1. Nginx Lua Modifications

**File**: `reverse_proxy_enhanced/lua/router.lua:448-465`

Added X-DB-Target header propagation:

```lua
function _M.apply_routing_decision(decision)
    ngx.var.route_decision = decision.target
    ngx.var.backend_upstream = decision.upstream

    -- Pass routing decision to WordPress for SQL proxy routing
    ngx.req.set_header("X-DB-Target", decision.target)
    ngx.log(ngx.INFO, "[ROUTING] Setting X-DB-Target header: ", decision.target)

    if decision.target == "honeypot" then
        ngx.var.suspicious_activity = "true"
        ngx.header["X-Honeypot-Route"] = "true"
        ngx.header["X-Route-Reason"] = decision.session_data.honeypot_reason or "unknown"
    end

    return decision
end
```

### 2. WordPress Database Drop-in

**File**: `production_eshop_files/wp-content/db.php`

Custom wpdb extension that:
- Intercepts `db_connect()` method
- Reads `X-DB-Target` header
- Dynamically sets database host
- Logs all routing decisions
- Tracks routing statistics

Key features:
- **Header Priority**: X-DB-Target → X-Honeypot-Route → Default (production)
- **Logging**: Writes to `wp-content/sql-routing.log` and WordPress debug.log
- **Statistics**: Tracks production vs honeypot connection counts
- **Fail-safe**: Defaults to production database if no header present

### 3. Docker Networking

**File**: `docker-compose.yml`

Modified both WordPress services to have cross-network access:

```yaml
production_eshop:
  environment:
    - WORDPRESS_DEBUG=1         # Enable debugging
    - WORDPRESS_DEBUG_LOG=1     # Enable debug.log
  networks:
    - production_network
    - honeypot_network  # NEW: Access to honeypot database
    - monitoring_network

honeypot_eshop:
  environment:
    - WORDPRESS_DEBUG=1         # Enable debugging
    - WORDPRESS_DEBUG_LOG=1     # Enable debug.log
  networks:
    - honeypot_network
    - production_network  # NEW: Access to production database
    - monitoring_network
```

## Testing

### Automated Test Suite

Run the comprehensive test script:

```bash
cd /home/user/dp/openstack-work
./test_sql_routing.sh
```

This tests:
1. ✅ db.php drop-in is loaded
2. ✅ SQL routing log file creation
3. ✅ Network connectivity to both databases
4. ✅ Database connections are active
5. ✅ Routing header propagation
6. ✅ Clean request → Production DB
7. ✅ Malicious user-agent → Honeypot DB
8. ✅ CVE pattern → Honeypot DB
9. ✅ SQL injection → Honeypot DB
10. ✅ Session persistence across requests

### Manual Testing

#### Test 1: Clean Request (Production DB)

```bash
# Make a normal request
curl -v http://localhost/

# Check SQL routing log
docker exec honeypot-ids-system-v1-production_eshop-1 \
  tail -f /var/www/html/wp-content/sql-routing.log

# Expected output:
# [SQL ROUTING] Target: PRODUCTION | IP: 172.x.x.x | URI: / | Reason: not_specified
```

#### Test 2: Malicious User-Agent (Honeypot DB)

```bash
# Make request with malicious user-agent
curl -H "User-Agent: sqlmap/1.0" http://localhost/

# Check SQL routing log
docker exec honeypot-ids-system-v1-production_eshop-1 \
  tail -f /var/www/html/wp-content/sql-routing.log

# Expected output:
# [SQL ROUTING] Target: HONEYPOT | IP: 172.x.x.x | URI: / | Reason: high_threat_score
```

#### Test 3: CVE Exploitation (Honeypot DB)

```bash
# Test CVE-2023-28121 pattern
curl -X POST -H "X-WCPAY-PLATFORM-CHECKOUT-USER: 1" \
  http://localhost/wp-json/wp/v2/users

# Check SQL routing log
docker exec honeypot-ids-system-v1-production_eshop-1 \
  tail -f /var/www/html/wp-content/sql-routing.log

# Expected output:
# [SQL ROUTING] Target: HONEYPOT | IP: 172.x.x.x | URI: /wp-json/wp/v2/users | Reason: cve_pattern_match
```

#### Test 4: Verify Database Connections

```bash
# Check production database connections
docker exec honeypot-ids-system-v1-production_database-1 \
  mysql -u production_user -p${MYSQL_PASSWORD} -e "SHOW PROCESSLIST;"

# Check honeypot database connections
docker exec honeypot-ids-system-v1-honeypot_database-1 \
  mysql -u production_user -p${MYSQL_PASSWORD} -e "SHOW PROCESSLIST;"

# You should see connections from both WordPress instances to both databases
```

## Monitoring and Logging

### SQL Routing Log

**Location**: `wp-content/sql-routing.log` (inside WordPress container)

**Format**:
```
[2025-11-05 14:23:45] [SQL ROUTING] Target: PRODUCTION | IP: 192.168.1.100 | URI: / | Reason: not_specified | Original Host: production_database:3306 | New Host: production_database:3306 | User-Agent: Mozilla/5.0...
[2025-11-05 14:24:12] [SQL ROUTING] Target: HONEYPOT | IP: 192.168.1.101 | URI: /wp-admin/ | Reason: multiple_admin_attempts | Original Host: production_database:3306 | New Host: honeypot_database:3306 | User-Agent: sqlmap/1.0
```

**View logs**:
```bash
# Production WordPress
docker exec honeypot-ids-system-v1-production_eshop-1 \
  tail -f /var/www/html/wp-content/sql-routing.log

# Honeypot WordPress
docker exec honeypot-ids-system-v1-honeypot_eshop-1 \
  tail -f /var/www/html/wp-content/sql-routing.log
```

### WordPress Debug Log

**Location**: `wp-content/debug.log` (inside WordPress container)

**View logs**:
```bash
docker exec honeypot-ids-system-v1-production_eshop-1 \
  tail -f /var/www/html/wp-content/debug.log
```

### Nginx Routing Logs

**Location**: `nginx_logs/access.log` and `nginx_logs/security.log`

**View logs**:
```bash
# Access log
tail -f /home/user/dp/openstack-work/nginx_logs/access.log

# Security log (threat analysis)
tail -f /home/user/dp/openstack-work/nginx_logs/security.log
```

### Redis Session Data

Check session routing decisions:

```bash
docker exec -it honeypot-ids-system-v1-session_store-1 \
  redis-cli -a "${REDIS_PASSWORD}"

# List all sessions
KEYS session:*

# View specific session
GET session:<session-id>

# Sample output:
# {"id":"abc123","honeypot_bound":true,"threat_score":85,"honeypot_reason":"malicious_user_agent"}
```

## Troubleshooting

### Issue: SQL queries not routing to honeypot database

**Diagnosis**:
```bash
# 1. Check if db.php exists
docker exec honeypot-ids-system-v1-production_eshop-1 \
  ls -la /var/www/html/wp-content/db.php

# 2. Check Nginx is setting X-DB-Target header
docker exec honeypot-ids-system-v1-reverse_proxy-1 \
  tail -n 50 /var/log/nginx/access.log | grep "X-DB-Target"

# 3. Check SQL routing log exists
docker exec honeypot-ids-system-v1-production_eshop-1 \
  cat /var/www/html/wp-content/sql-routing.log
```

**Solution**:
- Ensure `db.php` is present in `wp-content/` directory
- Restart Nginx: `docker compose restart reverse_proxy`
- Clear opcache: `docker compose restart production_eshop honeypot_eshop`

### Issue: Database connection failures

**Diagnosis**:
```bash
# Test network connectivity from WordPress to databases
docker exec honeypot-ids-system-v1-production_eshop-1 \
  nc -zv production_database 3306

docker exec honeypot-ids-system-v1-production_eshop-1 \
  nc -zv honeypot_database 3306
```

**Solution**:
- Verify both WordPress instances are on both networks in `docker-compose.yml`
- Restart Docker Compose: `docker compose down && docker compose up -d`
- Check database credentials in `.env` file

### Issue: All requests routing to production

**Diagnosis**:
```bash
# Check threat analyzer is working
docker logs honeypot-ids-system-v1-reverse_proxy-1 | grep "THREAT ANALYZER"

# Check Redis session data
docker exec -it honeypot-ids-system-v1-session_store-1 \
  redis-cli -a "${REDIS_PASSWORD}" KEYS session:*
```

**Solution**:
- Verify threat patterns in `reverse_proxy_enhanced/lua/threat_analyzer.lua`
- Check Nginx Lua configuration in `reverse_proxy_enhanced/nginx.conf`
- Increase threat threshold in config if too high

### Issue: SQL routing log not being written

**Diagnosis**:
```bash
# Check WordPress debug mode
docker exec honeypot-ids-system-v1-production_eshop-1 \
  cat /var/www/html/wp-config.php | grep WP_DEBUG

# Check file permissions
docker exec honeypot-ids-system-v1-production_eshop-1 \
  ls -la /var/www/html/wp-content/
```

**Solution**:
- Ensure `WORDPRESS_DEBUG=1` and `WORDPRESS_DEBUG_LOG=1` in docker-compose.yml
- Check file permissions: `chmod 755 /var/www/html/wp-content/`
- Verify db.php is not cached by opcache

## Performance Considerations

### Connection Overhead

- **Per-request overhead**: ~5-10ms for header reading and database host selection
- **No persistent connections**: Each request creates a new database connection based on routing decision
- **Redis lookup**: Already performed by Nginx Lua, no additional overhead in WordPress

### Optimization Recommendations

1. **Enable opcache** for PHP to cache the db.php drop-in (already enabled in WordPress Docker image)
2. **Use persistent Redis connections** in Nginx Lua (already implemented via connection pool)
3. **Database query caching** via MySQL query cache or object caching
4. **Connection pooling** via ProxySQL (optional future enhancement)

### Scalability

- **Horizontal scaling**: Each WordPress instance independently reads routing headers
- **Database load**: Distributed between production and honeypot databases based on threat distribution
- **Session store**: Redis can be clustered for high availability

## Security Considerations

### 1. Header Spoofing Prevention

The `X-DB-Target` header is set internally by Nginx and **cannot be spoofed** by external clients:

```nginx
# In nginx.conf
proxy_set_header X-DB-Target $route_decision;
# This overwrites any client-sent X-DB-Target header
```

### 2. Database Credential Security

- Same credentials used for both databases to enable seamless routing
- Credentials stored in `.env` file, not in code
- No credentials exposed in HTTP headers or logs

### 3. Network Isolation

- Databases are on separate Docker networks (172.20.x.x and 172.21.x.x)
- WordPress instances have limited cross-network access
- No direct external access to databases

### 4. Audit Logging

All SQL routing decisions are logged with:
- Source IP address
- Request URI
- User-Agent
- Routing reason
- Timestamp

## Future Enhancements

### 1. ProxySQL Integration

Replace custom db.php with ProxySQL for advanced features:
- Query rewriting
- Query caching
- Connection pooling
- Read/write splitting
- Query throttling

### 2. Query-Level Analysis

Extend routing to analyze actual SQL queries:
- Detect SQL injection in queries (beyond URI analysis)
- Route specific table queries (e.g., wp_users always to honeypot)
- Block destructive queries in production

### 3. Machine Learning Integration

Use ML models to:
- Predict routing based on behavioral patterns
- Adapt threat thresholds dynamically
- Identify zero-day attack patterns

### 4. Real-time Metrics Dashboard

Build Grafana dashboard showing:
- Production vs Honeypot query distribution
- Query latency by database
- Threat score distribution
- Database connection pool status

## References

- WordPress wpdb class: `wp-includes/class-wpdb.php`
- WordPress drop-ins: https://developer.wordpress.org/reference/functions/get_dropins/
- OpenResty Lua: https://github.com/openresty/lua-nginx-module
- Docker networking: https://docs.docker.com/network/

## Related Documentation

- [README.md](README.md) - Main system documentation
- [ELK_INTEGRATION.md](ELK_INTEGRATION.md) - SIEM integration
- [reverse_proxy_enhanced/HONEYPOT_ROUTING_TEST_CASES.md](reverse_proxy_enhanced/HONEYPOT_ROUTING_TEST_CASES.md) - HTTP routing tests

---

**Version**: 1.0.0
**Last Updated**: 2025-11-05
**Author**: Honeypot IDS Development Team
