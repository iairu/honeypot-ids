# ELK SIEM Stack for Honeypot Monitoring

This directory contains a secure ELK (Elasticsearch, Logstash, Kibana) stack designed to run on a **separate VM** from your main honeypot system for centralized log collection, analysis, and visualization.

## Architecture

The SIEM runs independently on its own VM and receives logs from the main honeypot VM via Filebeat → Logstash over secure SSL/TLS connections.

```
Main Honeypot VM                    SIEM VM (this stack)
┌─────────────────┐                ┌─────────────────┐
│   Filebeat      │───SSL/TLS───→  │   Logstash      │
│   (collector)   │    port 5044   │   (processor)   │
│                 │                │        ↓        │
│ - Docker logs   │                │  Elasticsearch  │
│ - Nginx logs    │                │   (storage)     │
│ - Redis logs    │                │        ↓        │
│ - Suricata logs │                │     Kibana      │
└─────────────────┘                │ (visualization) │
                                   └─────────────────┘
```

## Quick Start

### For SIEM VM Setup:

1. **Generate SSL certificates:**
   ```bash
   cd certs/root-ca/
   ./gen_elk_certs.sh
   ```

2. **Create environment file:**
   ```bash
   cd docker/
   cp .env.example .env
   # Edit .env and set secure passwords
   ```

3. **Start the ELK stack:**
   ```bash
   docker compose up -d
   ```

4. **Access Kibana:**
   ```
   https://<SIEM_VM_IP>:5601
   ```

### For Main Honeypot VM Setup:

See the detailed setup guide: **[SETUP_GUIDE.md](./SETUP_GUIDE.md)**

## Documentation

- **[SETUP_GUIDE.md](./SETUP_GUIDE.md)** - Complete two-VM setup instructions
- **[filebeat/certs/README.md](../filebeat/certs/README.md)** - Certificate setup for main VM
- **[docker/.env.example](./docker/.env.example)** - SIEM VM environment variables
- **[../.env.example](../.env.example)** - Main VM environment variables

## Components

- **Elasticsearch** (port 9200) - Search and analytics engine for log storage
- **Logstash** (port 5044) - Log processing pipeline that receives data from Filebeat
- **Kibana** (port 5601) - Visualization and exploration interface

## Log Indices

Logs are organized into daily indices:

- `honeypot-docker-logs-YYYY.MM.DD` - Docker container logs from all services
- `honeypot-nginx-logs-YYYY.MM.DD` - Nginx access, error, and security logs
- `honeypot-redis-logs-YYYY.MM.DD` - Redis session store logs
- `honeypot-generic-logs-YYYY.MM.DD` - Suricata IDS alerts and events

## Features

✅ **Secure by default** - SSL/TLS encryption, client certificate authentication
✅ **Two-VM architecture** - SIEM isolated from honeypot for security
✅ **Automatic log parsing** - Nginx, Docker, Redis logs pre-parsed
✅ **GeoIP enrichment** - IP addresses enriched with location data
✅ **DNS resolution** - Reverse DNS lookups for IP addresses
✅ **Filtered collection** - Only collects logs from specified docker-compose project

## Maintenance

### View logs:
```bash
docker compose logs -f logstash  # Watch Logstash processing
docker compose logs -f kibana    # Watch Kibana
docker compose logs -f es01      # Watch Elasticsearch
```

### Check health:
```bash
docker compose ps                              # Service status
curl -k -u elastic:pass https://localhost:9200/_cluster/health?pretty
```

### Restart services:
```bash
docker compose restart logstash  # Restart single service
docker compose restart           # Restart all services
```

## Troubleshooting

If you encounter issues, see the **Troubleshooting** section in [SETUP_GUIDE.md](./SETUP_GUIDE.md).

Common issues:
- **Connection refused** → Check firewall allows port 5044
- **SSL errors** → Verify certificates copied correctly
- **No logs** → Check Filebeat configuration and Docker permissions

## Security Considerations

🔒 **Change default passwords** in `.env` before deployment
🔒 **Use firewall rules** to restrict access to ports 5601, 9200
🔒 **Never commit certificates** or `.env` files to version control
🔒 **Rotate certificates** annually (validity: 365 days)
🔒 **Monitor disk usage** - Elasticsearch indices can grow large

## Support

For detailed instructions and troubleshooting, see [SETUP_GUIDE.md](./SETUP_GUIDE.md) 
