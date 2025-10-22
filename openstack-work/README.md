# Honeypot IDS System with Snort Integration

A comprehensive honeypot system that integrates Snort IDS with intelligent session management to dynamically route suspicious traffic between production and honeypot instances.

## Overview

This system provides an advanced security architecture that:

- **Detects threats in real-time** using Snort IDS with custom rules for WordPress vulnerabilities
- **Routes traffic intelligently** between production and honeypot instances based on threat analysis
- **Manages sessions dynamically** to track and analyze user behavior patterns
- **Provides comprehensive logging** and analytics for security monitoring

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

## Features

### 🛡️ Advanced Threat Detection

- **Snort IDS Integration**: Real-time packet inspection with 70+ custom rules
- **CVE-Specific Detection**: Purpose-built rules for WordPress vulnerabilities including:
  - CVE-2023-28121: WooCommerce Payments unauthorized admin access
  - CVE-2023-2986: Abandoned Cart Lite hardcoded encryption key
  - CVE-2025-4403: User-controlled file upload type vulnerability
  - CVE-2025-2266: Unauthenticated WordPress options update
  - And many more...

### 🔀 Intelligent Traffic Routing

- **Dynamic Decision Making**: Lua-based routing logic in Nginx
- **Session-Based Tracking**: Persistent user behavior analysis
- **Threat Score Calculation**: Multi-factor scoring system
- **Gradual Escalation**: Progressive response to suspicious activities

### 📊 Session Management

- **Real-time Tracking**: Monitor user sessions across both instances
- **Behavioral Analysis**: Pattern recognition for automated tools
- **Geographic Intelligence**: IP reputation and location tracking
- **Persistent Storage**: Redis-backed session persistence

### 📈 Analytics & Monitoring

- **Comprehensive Logging**: Structured logging with Winston
- **Real-time Dashboards**: Session and threat analytics
- **Alert Management**: Snort alert processing and correlation
- **Performance Metrics**: System health and routing statistics

## Quick Start

### Prerequisites

- Docker & Docker Compose
- 8GB RAM minimum
- 50GB available disk space
- Linux host (Ubuntu 20.04+ recommended)

### Installation

1. **Clone and navigate to the project**:
   ```bash
   git clone <your-repository>
   cd dp/openstack-work
   ```

2. **Configure environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start the system**:
   ```bash
   docker-compose up -d
   ```

4. **Verify installation**:
   ```bash
   # Check all services are running
   docker-compose ps
   
   # Check session manager health
   curl http://localhost:3001/health
   
   # View logs
   docker-compose logs -f reverse_proxy
   ```

### Initial Setup

1. **Configure WordPress instances**:
   - Production: `http://localhost/`
   - Honeypot: Access managed automatically by routing logic

2. **Install vulnerable plugins in honeypot**:
   ```bash
   docker-compose exec honeypot_eshop wp plugin install woocommerce-payments --version=5.6.1 --activate
   # Install other vulnerable plugin versions as needed
   ```

3. **Verify Snort is detecting traffic**:
   ```bash
   docker-compose logs snort_ids
   tail -f snort_logs/alert_fast
   ```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `REDIS_PASSWORD` | Redis authentication password | `session_redis_password` |
| `SNORT_LOG_PATH` | Path to Snort log files | `/var/log/snort` |
| `SESSION_MANAGER_URL` | Session manager API endpoint | `http://session_manager:3001` |
| `LOG_LEVEL` | Logging verbosity | `info` |

### Nginx Configuration

The reverse proxy uses OpenResty with custom Lua modules for:

- **Session Handling**: `lua/session_handler.lua`
- **Threat Analysis**: `lua/threat_analyzer.lua` 
- **Routing Logic**: `lua/router.lua`
- **Vulnerability Detection**: `lua/vulnerability_handler.lua`

### Snort Rules

Custom rules are defined in `snort_rules/local.rules`:

- **70+ detection rules** for WordPress-specific attacks
- **CVE-based patterns** for known vulnerabilities
- **Behavioral detection** for scanning and automation tools
- **Rate limiting** and DoS protection

### Session Manager API

RESTful API for session and threat management:

```bash
# Create session
POST /session/create
{
  "ip": "192.168.1.100",
  "userAgent": "Mozilla/5.0...",
  "initialRoute": "production"
}

# Get routing decision
POST /routing/decide
{
  "sessionId": "abc123",
  "ip": "192.168.1.100",
  "uri": "/wp-admin/admin-ajax.php",
  "headers": {...}
}

# Get analytics
GET /analytics/sessions
GET /analytics/threats
GET /analytics/routing
```

## Usage Examples

### Monitoring Threats

```bash
# View real-time Snort alerts
docker-compose exec session_manager curl localhost:3001/snort/alerts

# Check IP reputation
curl "http://localhost:3001/threat/ip/192.168.1.100"

# Report manual threat
curl -X POST http://localhost:3001/threat/report \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.100","threatType":"manual_analysis","details":{"reason":"suspicious_behavior"}}'
```

### Session Analysis

```bash
# Get session analytics
curl http://localhost:3001/analytics/sessions

# View specific session
curl http://localhost:3001/session/abc123def456

# Monitor routing decisions
tail -f /var/log/nginx/security.log | grep "route_decision"
```

### Testing Vulnerability Detection

```bash
# Test CVE-2023-28121 (WooCommerce Payments)
curl -X POST "http://localhost/" \
  -H "X-WCPAY-PLATFORM-CHECKOUT-USER: 1" \
  -d "rest_route=/wp/v2/users&username=attacker&email=test@test.com"

# Test directory traversal
curl "http://localhost/wp-content/themes/../../wp-config.php"

# Test SQL injection
curl "http://localhost/?page=advanced-form-integration-log&integration_id=1' UNION SELECT 1,2,3--"
```

## Maintenance

### Log Management

```bash
# Rotate logs
docker-compose exec session_manager npm run rotate-logs

# Archive Snort logs
tar -czf snort_logs_$(date +%Y%m%d).tar.gz snort_logs/

# Clean old sessions
docker-compose exec session_manager curl -X POST localhost:3001/maintenance/cleanup
```

### Updates

```bash
# Update threat intelligence
docker-compose restart threat_intel

# Reload Snort rules
docker-compose exec snort_ids snort --reload-rules

# Update Nginx configuration
docker-compose exec reverse_proxy nginx -s reload
```

### Backup

```bash
# Backup Redis data
docker-compose exec session_store redis-cli --rdb /data/backup.rdb

# Backup WordPress data
docker-compose exec production_database mysqldump -u root -p production_database > backup_production.sql
docker-compose exec honeypot_database mysqldump -u root -p honeypot_database > backup_honeypot.sql
```

## Monitoring & Alerts

### Key Metrics

- **Session Distribution**: Production vs Honeypot routing ratio
- **Threat Detection Rate**: Snort alerts per hour
- **False Positive Rate**: Legitimate traffic routed to honeypot
- **Response Time**: Routing decision latency

### Log Locations

- **Nginx Access**: `/var/log/nginx/access.log`
- **Security Events**: `/var/log/nginx/security.log`
- **Snort Alerts**: `/var/log/snort/alert_fast`
- **Session Manager**: `/var/log/session_manager/session-manager.log`

### Alerting

Configure external monitoring for:

- High threat score sessions (>70)
- Snort alert volume spikes
- Service availability issues
- Disk space usage (logs can grow quickly)

## Troubleshooting

### Common Issues

**1. Snort not detecting traffic**
```bash
# Check network configuration
docker-compose exec snort_ids ip addr show
docker-compose exec snort_ids tcpdump -i eth0 -c 10

# Verify rules syntax
docker-compose exec snort_ids snort -T -c /usr/local/etc/snort/snort.conf
```

**2. Session Manager connection issues**
```bash
# Check Redis connectivity
docker-compose exec session_manager redis-cli ping

# Verify API health
curl http://localhost:3001/health
```

**3. Routing not working correctly**
```bash
# Check Nginx Lua errors
docker-compose logs reverse_proxy | grep lua

# Test routing decision API
curl -X POST http://localhost:3001/routing/decide \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.100","uri":"/test","userAgent":"test"}'
```

**4. High memory usage**
```bash
# Check Redis memory
docker-compose exec session_store redis-cli info memory

# Clear old sessions
docker-compose exec session_store redis-cli FLUSHDB
```

### Debug Mode

Enable debug logging:

```bash
# Set debug level in environment
echo "LOG_LEVEL=debug" >> .env

# Restart with verbose logging
docker-compose down && docker-compose up -d

# Follow debug logs
docker-compose logs -f session_manager
```

## Security Considerations

### Production Deployment

- **Change default passwords** in Redis and databases
- **Use SSL/TLS certificates** for external access
- **Implement firewall rules** to restrict access
- **Regular security updates** for all components
- **Monitor log files** for unauthorized access attempts

### Data Privacy

- **Session data encryption** at rest and in transit
- **IP address anonymization** for analytics
- **GDPR compliance** for user data handling
- **Secure log rotation** and retention policies

## Performance Tuning

### High Traffic Optimization

```yaml
# docker-compose.override.yml
services:
  reverse_proxy:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
  
  session_manager:
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '1'
          memory: 2G
```

### Redis Optimization

```bash
# Increase Redis memory limit
echo "maxmemory 2gb" >> redis_config/redis.conf
echo "maxmemory-policy allkeys-lru" >> redis_config/redis.conf
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request with detailed description

### Development Setup

```bash
# Install development dependencies
cd session_manager && npm install

# Run tests
npm test

# Lint code
npm run lint

# Format code
npm run format
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:

- **GitHub Issues**: Report bugs and request features
- **Documentation**: Check the wiki for detailed guides
- **Security Issues**: Report privately to security@domain.com

## Changelog

### v1.0.0 (2024-01-XX)
- Initial release with Snort integration
- Session-based routing system
- 70+ custom detection rules
- Real-time analytics dashboard
- Docker Compose deployment

---

**⚠️ Warning**: This is a security research tool. Deploy responsibly and ensure proper authorization before monitoring network traffic.