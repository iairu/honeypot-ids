# ELK SIEM Integration Guide

This document describes how to integrate the Honeypot IDS System with an external ELK (Elasticsearch, Logstash, Kibana) SIEM for centralized security monitoring and analysis.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Honeypot IDS System                       │
│                                                              │
│  ┌──────────────┐         ┌─────────────┐                  │
│  │  Suricata    │────────▶│  Filebeat   │────┐             │
│  │  (EVE JSON)  │         │             │    │             │
│  └──────────────┘         └─────────────┘    │             │
│                                               │             │
│  ┌──────────────┐                            │             │
│  │    Nginx     │────────▶                   │             │
│  │ (Access Logs)│                            │             │
│  └──────────────┘                            │             │
│                                               │             │
│  ┌──────────────┐                            ▼             │
│  │  Nginx Lua   │────────────────────▶  Elasticsearch     │
│  │ (Security    │         HTTP             Index           │
│  │  Events)     │         API                │             │
│  └──────────────┘                            │             │
└──────────────────────────────────────────────┼─────────────┘
                                               │
                                               ▼
                    ┌──────────────────────────────────────┐
                    │      External ELK SIEM Server        │
                    │                                       │
                    │  ┌──────────────┐                    │
                    │  │Elasticsearch │◀────Ingest         │
                    │  │   Indices:   │                    │
                    │  │ honeypot-ids-* │                  │
                    │  │ honeypot-nginx-* │                │
                    │  └──────────────┘                    │
                    │         ▲                             │
                    │         │                             │
                    │  ┌──────┴──────┐                     │
                    │  │   Kibana    │◀────Visualize       │
                    │  │  Dashboards │                     │
                    │  └─────────────┘                     │
                    └──────────────────────────────────────┘
```

## Data Sources

### 1. Suricata IDS Logs
- **Format**: EVE JSON (Suricata native format)
- **Location**: `/var/log/suricata/eve.json`
- **Shipped by**: Filebeat
- **Index**: `honeypot-ids-YYYY.MM.DD`
- **Contents**:
  - IDS Alerts
  - HTTP transactions
  - DNS queries
  - TLS handshakes
  - Network flows
  - Anomalies
  - Statistics

### 2. Nginx Access Logs
- **Format**: Extended log format
- **Location**: `/var/log/nginx/access.log`
- **Shipped by**: Filebeat
- **Index**: `honeypot-nginx-YYYY.MM.DD`
- **Contents**:
  - Request details
  - Response codes
  - Timing information
  - User agents

### 3. Nginx Security Logs
- **Format**: Custom security format
- **Location**: `/var/log/nginx/security.log`
- **Shipped by**: Filebeat
- **Index**: `honeypot-nginx-YYYY.MM.DD`
- **Contents**:
  - Session IDs
  - Routing decisions
  - Threat scores
  - Suspicious activity flags

### 4. Nginx Lua Security Events
- **Format**: JSON
- **Source**: Lua elk_logger module
- **Shipped by**: HTTP API (direct to Elasticsearch)
- **Index**: `honeypot-nginx-YYYY.MM.DD`
- **Contents**:
  - Real-time security events
  - Attack attempts with CVE matching
  - Routing decisions
  - Session activity
  - Threat analysis

## Setup Instructions

### Prerequisites

1. External ELK Stack (v8.x) running with:
   - Elasticsearch
   - Kibana
   - (Optional) Logstash

2. Network connectivity from honeypot to ELK server

3. Elasticsearch API credentials

### Step 1: Configure ELK Credentials

Edit `.env` file:

```bash
cp .env.example .env
vi .env
```

Set the following variables:

```bash
# Enable ELK integration
ELK_ENABLED=true

# Elasticsearch connection
ELASTICSEARCH_HOST=your-elk-server.example.com
ELASTICSEARCH_PORT=9200
ELASTICSEARCH_PROTOCOL=https
ELASTICSEARCH_USER=elastic
ELASTICSEARCH_PASSWORD=your-secure-password
ELASTICSEARCH_SSL_ENABLED=true
ELASTICSEARCH_SSL_VERIFY=certificate

# Kibana connection (optional)
KIBANA_HOST=your-elk-server.example.com
KIBANA_PORT=5601
KIBANA_PROTOCOL=https

# Environment tag
ENVIRONMENT=production
```

### Step 2: Install SSL Certificate

Copy your Elasticsearch CA certificate to the honeypot system:

```bash
# On ELK server
cat /etc/elasticsearch/certs/http_ca.crt

# On honeypot system
cat > filebeat/certs/ca.crt <<'EOF'
[Paste certificate content here]
EOF

chmod 644 filebeat/certs/ca.crt
```

### Step 3: Restart Services

```bash
docker compose down
docker compose up -d
```

### Step 4: Verify Integration

Check Filebeat logs:

```bash
docker compose logs filebeat | tail -50
```

Look for successful connection messages:

```
Connection to https://your-elk-server:9200 established
Successfully indexed 10 events
```

Check Nginx Lua ELK logger:

```bash
docker compose logs reverse_proxy | grep ELK
```

Expected output:

```
[ELK] Logger initialized. Enabled: true
[ELK] Successfully sent event to Elasticsearch
```

### Step 5: Create Kibana Index Patterns

In Kibana, create index patterns for:

1. `honeypot-ids-*` - Suricata/IDS data
2. `honeypot-nginx-*` - Nginx and Lua security events

Navigate to: **Stack Management** → **Index Patterns** → **Create index pattern**

## Elasticsearch Indices

### Index: `honeypot-ids-*`

**Daily indices**: `honeypot-ids-8.11.0-2025.11.04`

**Document types**:
- Suricata alerts
- HTTP transactions
- DNS queries
- TLS sessions
- Network flows

**Key fields**:
- `@timestamp`: Event timestamp
- `event_type`: Suricata event type (alert, http, dns, etc.)
- `src_ip`, `dest_ip`: Source and destination IPs
- `alert.signature`: Alert signature name
- `alert.severity`: Alert severity level
- `http.hostname`, `http.url`: HTTP request details
- `tags`: ["suricata", "ids", "honeypot"]

### Index: `honeypot-nginx-*`

**Daily indices**: `honeypot-nginx-2025.11.04`

**Document types**:
- Security events
- Attack attempts
- Routing decisions
- Session activity

**Key fields**:
- `@timestamp`: Event timestamp
- `event_type`: Event type (security_event, attack_attempt, routing_decision, session_activity)
- `client_ip`: Client IP address
- `threat_score`: Calculated threat score
- `route_decision`: Routing decision (production/honeypot)
- `attack_type`: Type of attack detected
- `cve_matched`: Matched CVE identifiers
- `tags`: ["nginx", "security", "honeypot"]

## Kibana Dashboards

### Recommended Dashboards

**1. Real-Time Threat Overview**
- Threat score timeline
- Attack attempts by type
- Top attacking IPs
- Routing decisions distribution
- CVE detections

**2. IDS Alerts Dashboard**
- Suricata alerts over time
- Alert severity breakdown
- Top alert signatures
- Source/destination IP maps
- Protocol distribution

**3. Session Analysis**
- Session creation rate
- Honeypot binding events
- Session threat score distribution
- User agent analysis

**4. Attack Patterns**
- CVE exploitation attempts
- SQL injection attempts
- XSS attempts
- Directory traversal attempts
- Vulnerable plugin access

### Example Kibana Queries

**High-severity attacks**:
```
event_type:"attack_attempt" AND severity:"high"
```

**Honeypot-bound sessions**:
```
event_type:"routing_decision" AND route_target:"honeypot"
```

**CVE-2023-28121 exploitation**:
```
cve:"CVE-2023-28121"
```

**Failed routing to production**:
```
route_decision:"honeypot" AND threat_score:>80
```

## Alerting Rules

### Elasticsearch Watcher Examples

**Alert on Critical Attacks**:

```json
{
  "trigger": {
    "schedule": {
      "interval": "1m"
    }
  },
  "input": {
    "search": {
      "request": {
        "indices": ["honeypot-nginx-*"],
        "body": {
          "query": {
            "bool": {
              "must": [
                {"match": {"event_type": "attack_attempt"}},
                {"match": {"severity": "critical"}},
                {"range": {"@timestamp": {"gte": "now-1m"}}}
              ]
            }
          }
        }
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total": {
        "gt": 0
      }
    }
  },
  "actions": {
    "log": {
      "logging": {
        "text": "Critical attack detected on honeypot system"
      }
    }
  }
}
```

## Performance Considerations

### Filebeat Settings

- **Batch size**: 50 events
- **Workers**: 1
- **Timeout**: 90 seconds
- **Buffering**: Local queue before shipping

### Nginx Lua ELK Logger

- **Batch size**: 10 events
- **Flush interval**: 5 seconds
- **Timeout**: 1 second (non-blocking)
- **Async**: Events queued and sent in background

### Expected Data Volume

- **Suricata EVE logs**: ~100-500 MB/day (depending on traffic)
- **Nginx logs**: ~50-200 MB/day
- **Lua security events**: ~10-50 MB/day
- **Total**: ~200-750 MB/day

### Index Lifecycle Management

Recommended ILM policy:

```json
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_age": "1d",
            "max_size": "50gb"
          }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "shrink": {
            "number_of_shards": 1
          }
        }
      },
      "delete": {
        "min_age": "90d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
```

## Troubleshooting

### Filebeat Not Connecting

**Check logs**:
```bash
docker compose logs filebeat
```

**Common issues**:
1. Wrong Elasticsearch URL
2. Invalid credentials
3. SSL certificate mismatch
4. Firewall blocking port 9200

**Solution**:
```bash
# Test connection manually
docker exec filebeat curl -k -u elastic:password https://your-elk-server:9200
```

### Nginx Lua Not Sending Events

**Check logs**:
```bash
docker compose logs reverse_proxy | grep ELK
```

**Common issues**:
1. `ELK_ENABLED=false` in environment
2. Network connectivity issues
3. HTTP module not loaded

**Solution**:
```bash
# Verify environment
docker exec reverse_proxy env | grep ELK

# Test Elasticsearch endpoint
docker exec reverse_proxy curl -k https://your-elk-server:9200
```

### Missing Data in Kibana

**Check index patterns**:
1. Go to Kibana → Stack Management → Index Patterns
2. Verify `honeypot-*` patterns exist
3. Refresh field list

**Check indices**:
```bash
# List indices
curl -u elastic:password https://your-elk-server:9200/_cat/indices?v | grep honeypot

# Check document count
curl -u elastic:password https://your-elk-server:9200/honeypot-nginx-*/_count
```

## Security Considerations

1. **Use strong passwords** for Elasticsearch authentication
2. **Enable SSL/TLS** for all connections
3. **Restrict network access** to ELK ports (9200, 5601)
4. **Rotate credentials** regularly
5. **Monitor ELK logs** for unauthorized access
6. **Use index lifecycle management** to control data retention
7. **Implement RBAC** in Elasticsearch for least privilege access

## Disable ELK Integration

To disable ELK integration:

```bash
# In .env file
ELK_ENABLED=false

# Restart services
docker compose restart
```

Logs will continue to be written locally but won't be shipped to ELK.

## Support and Documentation

- Filebeat Documentation: https://www.elastic.co/guide/en/beats/filebeat/current/index.html
- Elasticsearch API: https://www.elastic.co/guide/en/elasticsearch/reference/current/docs.html
- Kibana User Guide: https://www.elastic.co/guide/en/kibana/current/index.html
