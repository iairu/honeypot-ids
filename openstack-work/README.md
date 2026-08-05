# Honeypot IDS System with Suricata Integration

## Public demo

Local development/testing system:
- http://localhost for main website (intelligent routing between production/honeypot instances)
- https://localhost for HTTPS access (auto-generated self-signed certificates)
- http://localhost:3001 for session management API
- http://localhost:3001/health for system health check
- Suricata alerts: `tail -f suricata_logs/fast.log`
- Security logs: `tail -f nginx_logs/security.log`

## Architecture

todo: show that saved threat and suricata data from redis is used for immediate routing by reverse proxy so we do not wait for suricata but have realtime protection

┌─────────────────┐    ┌──────────────────┐
│   Internet      │───▶│  Reverse Proxy   │
│   Traffic       │    │  (Nginx + Lua)   │
└─────────────────┘    └──────────────────┘
                                │
                                │
                       ┌────────┴──────────┐
                       │                   │
                       ▼                   ▼
              ┌──────────────────┐    ┌──────────────────┐
              │ Session Manager  │    │  Threat Intel    │
              │    (Node.js)     │    │    (Python)      │
              └──────────────────┘    └──────────────────┘
                       │                       │
                       └────────┬──────────────┘
                                ▼
                       ┌──────────────────┐
                       │   Suricata IDS   │
                       │ (Traffic Monitor)│
                       └──────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │      Redis       │
                       │  (Session Store  │
                       │ + Threat Intel)  │
                       └──────────────────┘
                                │
                       ┌────────┴──────────┐
                       │                   │
                       ▼                   ▼
              ┌─────────────────┐  ┌──────────────────┐
              │   Production    │  │   Honeypot       │
              │   WordPress     │  │   WordPress      │
              └─────────────────┘  └──────────────────┘

## Features

- **Intelligent Traffic Routing**: Nginx Lua-based real-time routing between production and honeypot instances
- **SQL Proxy Routing**: Dynamic database routing based on threat analysis - single WordPress frontend with dual-database backend (NEW!)
- **IDS Integration**: Suricata IDS with 70+ custom WordPress vulnerability detection rules
- **Session Tracking**: Redis-backed session management with threat scoring
- **Attack Detection**: CVE pattern matching, SQL injection, XSS, directory traversal detection
- **SIEM Integration**: Ready for external ELK (Elasticsearch, Vector, Kibana) integration via Vector
- **Security Logging**: Comprehensive logging to local files and optional external SIEM

## Local development setup

**Recommendation**
- Use Linux, WSL2 or Virtual Machine(Linux).
- Run docker commands inside WSL2 or Virtual Machine(Linux) terminal
- Minimum 8GB RAM, 50GB disk space for logs and data

---

**First time setup**

1. Clone repo: `git clone <your-repository>`
2. `cd dp/openstack-work`
3. If on Windows: Force Windows Git to not be CRLF but LF for Docker Shell Scripts to work: `echo "core.autocrlf=false" >> .git/config ; git rm --cached -r . ; git reset --hard`
4. Optional: Go to a non-production branch where you will develop: `git checkout -b dev`
5. **IMPORTANT**: Set up environment variables:
   ```bash
   cp .env.example .env
   vi .env  # Edit and set secure passwords
   ```
   Or generate random passwords automatically:
   ```bash
   cp .env.example .env
   sed -i "s/change_this_root_password_in_production/$(openssl rand -base64 32)/" .env
   sed -i "s/change_this_user_password_in_production/$(openssl rand -base64 32)/" .env
   sed -i "s/change_this_redis_password_in_production/$(openssl rand -base64 32)/" .env
   sed -i "s/change_this_session_secret_in_production/$(openssl rand -base64 32)/" .env
   ```
6. Just in case: Stop and remove all remaining Docker containers and networks prefixed with "honeypot-ids-system-": `docker stop $(docker ps -a -q -f name=honeypot-ids-system-) ; docker rm -f $(docker ps -a -q -f name=honeypot-ids-system-) ; docker network rm $(docker network ls -q -f name=honeypot-ids-system_)`
7. Start the service chain: `./deploy.sh` in the root directory (automated deployment with health checks)
8. Wait for all services to be healthy (takes 3-5 minutes for full startup)
9. Test system functionality: `./test_system.sh`

---

Often used: **Restart** after minor config changes, inconsistencies or computer reboot:
- Turn off: `docker compose down`
- Stop and remove all remaining Docker containers and networks prefixed with "honeypot-ids-system-": `docker stop $(docker ps -a -q -f name=honeypot-ids-system-) ; docker rm -f $(docker ps -a -q -f name=honeypot-ids-system-) ; docker network rm $(docker network ls -q -f name=honeypot-ids-system_)`
- Turn on again: `docker compose up -d`

**Here it is in one line** (you may be copy-pasting this a lot, recommended to add to .bashrc as an alias):
```bash
docker compose down ; docker stop $(docker ps -a -q -f name=honeypot-ids-system-) ; docker rm -f $(docker ps -a -q -f name=honeypot-ids-system-) ; docker network rm $(docker network ls -q -f name=honeypot-ids-system_) ; docker compose up -d
```

---

Also often used: **Rebuild** after major changes:
- Turn off: `docker compose down`
- Stop and remove all remaining Docker containers and networks prefixed with "honeypot-ids-system-": `docker stop $(docker ps -a -q -f name=honeypot-ids-system-) ; docker rm -f $(docker ps -a -q -f name=honeypot-ids-system-) ; docker network rm $(docker network ls -q -f name=honeypot-ids-system_)`
- Important step - Rebuild without cache: `docker compose build --no-cache`
- Turn on: `docker compose up -d`

**Here it is in one line** (you may be copy-pasting this a lot, recommended to add to .bashrc as an alias):
```bash
docker compose down ; docker stop $(docker ps -a -q -f name=honeypot-ids-system-) ; docker rm -f $(docker ps -a -q -f name=honeypot-ids-system-) ; docker network rm $(docker network ls -q -f name=honeypot-ids-system_) ; docker compose build --no-cache ; docker compose up -d
```

Also useful if you're only changing **nginx** configuration locally may be this selective restart:
```bash
docker compose stop reverse_proxy && docker compose build reverse_proxy && docker compose up -d reverse_proxy
```

Also useful if you want to **force file synchronization** from production to honeypot:
```bash
docker compose restart file_sync
```

---

If **broken**: Purge all containers and images (**WARNING**: this will remove **!!!ALL!!!** containers on your machine):
- Stop and remove Docker containers then remove Docker images: `docker stop $(docker ps -a -q) ; docker rm -f $(docker ps -a -q) ; docker rmi $(docker images -q)`
- Afterwards remove all Docker volumes and Docker networks: `docker system prune -a --volumes --force`
- Start again from docker-compose.yml like fresh install: `docker compose up -d`

For debugging:
- `docker container ls -a` to get container names and ids
- `docker compose logs -f` to see logs or `docker logs container_id_goes_here`
- `docker exec -it <container-name> /bin/bash` to get bash in the container, if no such command then try `/bin/sh` instead
- Check system health: `curl http://localhost:3001/health`
- Monitor threats: `tail -f snort_logs/alert_fast`
- Test attack detection: `curl -H "User-Agent: sqlmap/1.0" http://localhost/`

## Service versions and usage

These are the versions Docker Compose uses:
- Production Database: `mysql:5.7` (clean WordPress database, accessed only by production instance)
- Honeypot Database: `mysql:5.7` (vulnerable WordPress database, accessed only by honeypot instance)
- Production WordPress: `wordpress:6.8.3-php8.1` (secure instance, receives clean traffic)
- Honeypot WordPress: `wordpress:6.8.3-php8.1` (vulnerable instance with CVE plugins, receives suspicious traffic)
- Session Manager: `node:18-alpine` + custom API (manages routing decisions, threat analysis) - **DISABLED**
- Reverse Proxy: `openresty/openresty:alpine` (Nginx + Lua for intelligent traffic routing)
- Suricata IDS: `jasonish/suricata:latest` (intrusion detection with 70+ custom WordPress rules) - **ENABLED**
- Session Store: `redis:7-alpine` (stores session data and threat intelligence)
- Threat Intel: `python:3.11-slim` (updates IP reputation and attack patterns) - **DISABLED**
- Vector: `timberio/vector:0.43.0-debian` (ships logs to ELK SIEM) - **ENABLED** (optional)

If Docker wasn't present this would need to be done manually:
- install these versions yourself - see `Dockerfile` in each service for instructions
- apply environment variables in `.env` file
- manually configure Suricata with custom rules from `suricata_rules/local.rules`
- manually configure OpenResty with Lua modules from `reverse_proxy_enhanced/lua/`
- start all services with proper network isolation and health checks
- manually sync files from production to honeypot directories
- generate SSL certificates and configure HTTPS

## What you should know

- System automatically copies production files to honeypot on every startup via `init_setup` service
- SSL certificates are auto-generated (self-signed) on each `docker compose up`
- Suricata IDS monitors all traffic and triggers routing decisions based on threat analysis
- Session management tracks user behavior and maintains routing decisions across requests
- Health checks ensure services start in proper dependency order (databases → redis → session manager → wordpress → snort → nginx)
- Lua scripts in Nginx analyze every request in real-time and route suspicious traffic to honeypot
- WordPress vulnerabilities are implemented via specific plugin versions in honeypot instance only
- Redis stores session data, threat intelligence, and IP reputation scores
- File synchronization runs continuously every 5 minutes to keep honeypot current with production
- All security events are logged to multiple files for analysis and forensics

The system works by:
1. **Monitoring all incoming traffic** with Suricata IDS using 70+ custom WordPress vulnerability rules
2. **Analyzing requests** via Lua scripts for suspicious patterns (SQL injection, XSS, CVE exploitation attempts)
3. **Calculating threat scores** based on IP reputation, user agent, request patterns, and behavior
4. **Making routing decisions** dynamically - clean traffic goes to production, suspicious traffic to honeypot
5. **Binding sessions** permanently to honeypot once compromised to maintain consistency
6. **Logging everything** for security analysis and threat intelligence

## Attack detection patterns

The system detects and routes these attacks to honeypot:
- **CVE-2023-28121**: WooCommerce Payments unauthorized admin access via `X-WCPAY-PLATFORM-CHECKOUT-USER` header
- **CVE-2023-2986**: Abandoned Cart Lite hardcoded encryption key exploitation via `wcal_action=checkout_link`
- **CVE-2025-4403**: Drag-and-drop file upload type bypass via `dnd_codedropz_upload` with `supported_type`
- **CVE-2025-2266**: Unauthenticated WordPress options update via `cwmpUpdateOptions`
- **CVE-2025-47577 & CVE-2024-8425**: Gift voucher file upload RCE via `mwb_wgm_preview_mail`
- **CVE-2024-2387**: Advanced Form Integration SQL injection via `integration_id` parameter
- **CVE-2025-10142 & CVE-2024-50508**: File path traversal and sensitive file access
- **Generic patterns**: SQL injection, XSS, directory traversal, command injection, malicious user agents
- **Behavioral patterns**: Rapid requests, admin enumeration, plugin scanning, brute force attempts

## Testing and verification

Use the automated test suite to verify functionality:
```bash
./test_system.sh                    # Run all tests
./test_system.sh --security         # Security-focused tests only  
./test_system.sh --api              # API functionality tests only
./test_system.sh --quick            # Essential tests only
```

Test manual attack scenarios:
```bash
# Test CVE-2023-28121 detection
curl -X POST -H "X-WCPAY-PLATFORM-CHECKOUT-USER: 1" http://localhost/wp-json/wp/v2/users

# Test SQL injection detection  
curl "http://localhost/?id=1' OR 1=1--"

# Test malicious user agent detection
curl -H "User-Agent: sqlmap/1.0" http://localhost/

# Test vulnerable plugin access
curl http://localhost/wp-content/plugins/woocommerce-payments/readme.txt

# Check routing decision
curl -I http://localhost/ | grep X-Route-Target
```

## Folder structure

- `reverse_proxy_enhanced/` contains OpenResty configuration with Lua modules for intelligent routing
- `reverse_proxy_configuration/` contains basic Nginx configs and proxy parameters
- `session_manager/` contains Node.js API service for session management and threat analysis
- `suricata_config/` contains Suricata IDS configuration files
- `suricata_rules/` contains custom Suricata rules for WordPress vulnerability detection (70+ rules)
- `suricata_logs/` contains Suricata alert logs and monitoring data (EVE JSON format for SIEM integration)
- `threat_intelligence/` contains Python service for updating IP reputation and threat feeds
- `ssl_certificates/` contains auto-generated SSL certificates (recreated on each deployment)
- `production_eshop_files/` contains WordPress files for production instance
- `honeypot_eshop_files/` contains WordPress files for honeypot instance (auto-synced from production)
- `production_database_data/` contains MySQL data for production WordPress
- `honeypot_database_data/` contains MySQL data for honeypot WordPress (auto-synced from production)
- `redis_data/` contains session data and threat intelligence ([see redis_data/README.md](redis_data/README.md) for details)
- `nginx_logs/` contains access logs and security event logs
- `vector/` contains Vector configuration for shipping logs to ELK SIEM
- Database volumes are managed by Docker; use `docker volume inspect` to find locations on host machine
- **ELK SIEM Integration**: See [ELK_INTEGRATION.md](ELK_INTEGRATION.md) for complete setup guide
- **SQL Proxy Routing**: See [SQL_PROXY_ROUTING.md](SQL_PROXY_ROUTING.md) for database routing architecture

## Security considerations

- **Change all default passwords** in `.env` before production deployment
- **Replace self-signed certificates** with proper CA certificates for external access
- **Review Suricata rules** and customize for your specific environment and threats
- **Monitor log files regularly** for security events and system health
- **Implement proper firewall rules** to restrict access to management interfaces
- **Regular updates** of threat intelligence feeds and vulnerability signatures
- **Backup configuration and logs** for forensic analysis and system recovery

## Service integration architecture

### How Node.js Session Manager connects to Nginx Lua Session Handler

The Node.js Session Manager and Nginx Lua Session Handler integrate through Redis and HTTP API calls:

**1. Redis as Shared Data Store:**
```bash
# Both services connect to the same Redis instance
REDIS_HOST=session_store
REDIS_PORT=6379
REDIS_PASSWORD=${REDIS_PASSWORD}  # From .env file
```

**2. Session Data Flow:**
- **Nginx Lua** (`lua/session_handler.lua`) creates/retrieves sessions from Redis using `session:${sessionId}` keys
- **Node.js API** manages the same Redis keys through the `/session/*` endpoints
- Both services use identical session data structure ensuring consistency
- **Redis data is cleared on every `docker compose up`** for clean testing (see [redis_data/README.md](redis_data/README.md))

**3. Routing Decision Process:**
```
Nginx Request → Lua script → Check Redis session → Make routing decision
                    ↓
Node.js API ← HTTP call ← Lua script (if complex analysis needed)
                    ↓
Redis session update ← Node.js API ← Lua script decision
```

**4. Real-time Communication:**
- **Nginx to Node.js**: HTTP calls to `http://session_manager:3001/routing/decide` for complex routing decisions
- **Node.js to Redis**: Direct Redis connection for session storage and retrieval
- **Lua to Redis**: Direct Redis connection via `_G.redis_pool.get_connection()` for fast session lookups

**5. Key Integration Points:**
```lua
-- In Nginx Lua (router.lua)
local routing_decision = router.decide_route(session_data, threat_result, ngx.var.remote_addr)

-- Makes HTTP call to Node.js when needed:
local httpc = http.new()
local res = httpc:request_uri("http://session_manager:3001/routing/decide", {
    method = "POST",
    body = cjson.encode(request_data)
})
```

```javascript
// In Node.js (server.js)
app.post('/routing/decide', this.makeRoutingDecision.bind(this));

async makeRoutingDecision(req, res) {
    // Analyzes request data and updates Redis session
    const routingDecision = await this.decideRouting(sessionData, threatAnalysis, uri);
    await this.redisClient.setEx(`session:${sessionId}`, 86400, JSON.stringify(sessionData));
}
```

### How Python Threat Intel connects to Nginx Lua Threat Analyzer

The Python Threat Intelligence service and Nginx Lua Threat Analyzer integrate through Redis data sharing:

**1. Shared Threat Data in Redis:**
- **Python service** updates Redis keys: `threat_ips`, `malicious_agents`, `attack_patterns`, `cve_signatures`
- **Lua scripts** read the same Redis keys for real-time threat analysis

**2. Data Update Cycle:**
```
Python Threat Intel Service (every 1 hour)
    ↓
Fetch threat feeds (ipsum, feodo, blocklist.de)
    ↓
Update Redis keys: threat_ips, malicious_agents, cve_signatures
    ↓
Nginx Lua scripts read updated data in real-time
```

**3. Threat Intelligence Flow:**
```python
# Python threat_intel.py updates Redis
def update_threat_ips(self):
    threat_ips = self.fetch_external_feeds()
    self.redis_client.set('threat_ips', json.dumps(threat_ips))
    self.redis_client.set('malicious_agents', json.dumps(malicious_agents))
    self.redis_client.set('cve_signatures', json.dumps(cve_data))
```

```lua
-- Lua threat_analyzer.lua reads Redis data
function _M.analyze_request(uri, headers, remote_ip)
    local threat_intel = ngx.shared.threat_intel
    local threat_ips_json = threat_intel:get("threat_ips")
    local threats = cjson.decode(threat_ips_json)
    
    if threats[remote_ip] then
        threat_result.ip_reputation = threats[remote_ip].score
    end
end
```

**4. Real-time Threat Analysis Integration:**
- **Python service** runs background tasks every hour updating threat intelligence
- **Lua scripts** cache threat data in `ngx.shared.threat_intel` for microsecond access times
- **Redis** acts as persistent storage bridging Python updates and Lua consumption
- **Suricata alerts** processed by both Node.js and Lua through Redis `suricata_alerts` list

**5. Data Synchronization Points:**
```python
# Python service populates Redis with threat data
self.redis_client.set('threat_ips', json.dumps({
    '192.168.1.100': {'score': 85, 'reason': 'malware_c2', 'updated': time.time()}
}))
```

```lua
-- Lua scripts consume threat data in real-time
local function check_ip_reputation(ip)
    local threat_intel = ngx.shared.threat_intel
    local threat_ips_json = threat_intel:get("threat_ips")
    if threat_ips_json then
        local threats = cjson.decode(threat_ips_json)
        return threats[ip] or {score = 0, reason = "clean"}
    end
end
```

**6. Integration Benefits:**
- **Sub-millisecond response times** for Lua-based routing decisions
- **Hourly threat intelligence updates** without service restart
- **Consistent threat data** across all system components
- **Scalable architecture** supporting high-traffic environments