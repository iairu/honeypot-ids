# Honeypot IDS System with Snort Integration

## Public demo

Local development/testing system:
- http://localhost for main website (intelligent routing between production/honeypot instances)
- https://localhost for HTTPS access (auto-generated self-signed certificates)
- http://localhost:3001 for session management API
- http://localhost:3001/health for system health check
- Snort alerts: `tail -f snort_logs/alert_fast`
- Security logs: `tail -f nginx_logs/security.log`

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Internet      │───▶│  Reverse Proxy   │───▶│   Production    │
│   Traffic       │    │  (Nginx + Lua)   │    │   WordPress     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                         │
                                ▼                         │
                       ┌──────────────────┐              │
                       │ Session Manager  │              │
                       │    (Node.js)     │              │
                       └──────────────────┘              │
                                │                         │
                                ▼                         │
                       ┌──────────────────┐              │
                       │     Snort IDS    │              │
                       │  (Threat Intel)  │              │
                       └──────────────────┘              │
                                │                         │
                                ▼                         │
                       ┌──────────────────┐              │
                       │     Redis        │              │
                       │ (Session Store)  │              │
                       └──────────────────┘              │
                                │                         │
                                ▼                         │
                       ┌──────────────────┐              │
                       │   Honeypot       │◀─────────────┘
                       │   WordPress      │
                       └──────────────────┘
```

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
5. Set environment variables for all Docker services: `cp .env.example .env` e.g. random values
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
- Session Manager: `node:18-alpine` + custom API (manages routing decisions, threat analysis)
- Reverse Proxy: `openresty/openresty:alpine` (Nginx + Lua for intelligent traffic routing)
- Snort IDS: `ciscosecurity/snort3:latest` (intrusion detection with 70+ custom WordPress rules)
- Session Store: `redis:7-alpine` (stores session data and threat intelligence)
- Threat Intel: `python:3.11-slim` (updates IP reputation and attack patterns)

If Docker wasn't present this would need to be done manually:
- install these versions yourself - see `Dockerfile` in each service for instructions
- apply environment variables in `.env` file
- manually configure Snort with custom rules from `snort_rules/local.rules`
- manually configure OpenResty with Lua modules from `reverse_proxy_enhanced/lua/`
- start all services with proper network isolation and health checks
- manually sync files from production to honeypot directories
- generate SSL certificates and configure HTTPS

## What you should know

- System automatically copies production files to honeypot on every startup via `init_setup` service
- SSL certificates are auto-generated (self-signed) on each `docker compose up`
- Snort IDS monitors all traffic and triggers routing decisions based on threat analysis
- Session management tracks user behavior and maintains routing decisions across requests
- Health checks ensure services start in proper dependency order (databases → redis → session manager → wordpress → snort → nginx)
- Lua scripts in Nginx analyze every request in real-time and route suspicious traffic to honeypot
- WordPress vulnerabilities are implemented via specific plugin versions in honeypot instance only
- Redis stores session data, threat intelligence, and IP reputation scores
- File synchronization runs continuously every 5 minutes to keep honeypot current with production
- All security events are logged to multiple files for analysis and forensics

The system works by:
1. **Monitoring all incoming traffic** with Snort IDS using 70+ custom WordPress vulnerability rules
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
- `snort_config/` contains Snort IDS configuration files
- `snort_rules/` contains custom Snort rules for WordPress vulnerability detection (70+ rules)
- `snort_logs/` contains Snort alert logs and monitoring data
- `threat_intelligence/` contains Python service for updating IP reputation and threat feeds
- `ssl_certificates/` contains auto-generated SSL certificates (recreated on each deployment)
- `production_eshop_files/` contains WordPress files for production instance
- `honeypot_eshop_files/` contains WordPress files for honeypot instance (auto-synced from production)
- `production_database_data/` contains MySQL data for production WordPress
- `honeypot_database_data/` contains MySQL data for honeypot WordPress (auto-synced from production)
- `redis_data/` contains session data and threat intelligence
- `nginx_logs/` contains access logs and security event logs
- Database volumes are managed by Docker; use `docker volume inspect` to find locations on host machine

## Security considerations

- **Change all default passwords** in `.env` before production deployment
- **Replace self-signed certificates** with proper CA certificates for external access
- **Review Snort rules** and customize for your specific environment and threats
- **Monitor log files regularly** for security events and system health
- **Implement proper firewall rules** to restrict access to management interfaces
- **Regular updates** of threat intelligence feeds and vulnerability signatures
- **Backup configuration and logs** for forensic analysis and system recovery

⚠️ **Remember**: This system is designed for security research and threat analysis. Ensure proper authorization and legal compliance before deployment!