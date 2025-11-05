# ELK SIEM Setup Guide for Two-VM Architecture

This guide explains how to set up the ELK SIEM stack on a separate VM to monitor and collect logs from the main honeypot VM.

## Architecture Overview

```
┌─────────────────────────────────┐         ┌─────────────────────────────────┐
│      Main Honeypot VM           │         │       SIEM VM (ELK Stack)       │
│                                 │         │                                 │
│  ┌──────────────────────────┐  │         │  ┌──────────────────────────┐  │
│  │  Docker Containers       │  │         │  │  Elasticsearch           │  │
│  │  - WordPress Production  │  │         │  │  (Data Storage & Search) │  │
│  │  - WordPress Honeypot    │  │         │  └──────────────────────────┘  │
│  │  - Nginx Reverse Proxy   │  │         │                                 │
│  │  - Redis Session Store   │  │         │  ┌──────────────────────────┐  │
│  │  - Suricata IDS          │  │         │  │  Logstash                │  │
│  └──────────────────────────┘  │         │  │  (Log Processing)        │  │
│              │                  │         │  │  Port 5044 (SSL/TLS)     │  │
│              │                  │         │  └──────────────────────────┘  │
│  ┌──────────▼──────────────┐  │         │            ▲                    │
│  │  Filebeat               │  │         │            │                    │
│  │  - Docker logs          │──┼─────────┼────────────┘                    │
│  │  - Nginx logs           │  │  SSL/   │                                 │
│  │  - Redis logs           │  │  TLS    │  ┌──────────────────────────┐  │
│  │  - Suricata logs        │  │         │  │  Kibana                  │  │
│  └─────────────────────────┘  │         │  │  (Visualization)         │  │
│                                 │         │  │  Port 5601 (HTTPS)       │  │
└─────────────────────────────────┘         └──────────────────────────────┘
```

## Prerequisites

### SIEM VM Requirements
- Ubuntu/Debian Linux
- Minimum 4GB RAM (8GB recommended)
- 20GB+ disk space
- Docker and Docker Compose installed
- Static IP address or hostname

### Main Honeypot VM Requirements
- Docker and Docker Compose installed
- Network connectivity to SIEM VM on port 5044

## Setup Instructions

### Part 1: SIEM VM Setup

#### 1.1. Clone/Copy the SIEM Configuration

```bash
# On SIEM VM
cd ~/
git clone <your-repo> dp
cd dp/openstack-work/siem
```

#### 1.2. Create Environment File

Create a `.env` file in the `docker/` directory:

```bash
cd docker/
cat > .env <<'EOF'
# Stack version
STACK_VERSION=8.11.0

# Elasticsearch
ES_PORT=9200
ELASTIC_USERNAME=elastic
ELASTIC_PASSWORD=ChangeMe_SecurePassword123!

# Kibana
KIBANA_PORT=5601
KIBANA_PASSWORD=ChangeMe_KibanaPassword123!

# Logstash
LOGSTASH_PORT=9600
EOF
```

**Important:** Change the passwords to secure, random values!

#### 1.3. Generate SSL/TLS Certificates

```bash
cd ../certs/root-ca/
chmod +x gen_elk_certs.sh
./gen_elk_certs.sh
```

This will generate:
- CA certificate (rootCA.crt)
- Elasticsearch certificate (es01.crt/key)
- Kibana certificate (kibana.crt/key)
- Logstash certificate (logstash.crt/key)
- **Filebeat client certificate (filebeat.crt/key)** - needed for main VM

The script automatically copies certificates to the correct locations.

#### 1.4. Start ELK Stack

```bash
cd ../../docker/
docker compose up -d
```

Wait for all services to become healthy:

```bash
docker compose ps
```

All services should show "healthy" status.

#### 1.5. Verify ELK Stack

Test Elasticsearch:
```bash
curl -k -u elastic:YourElasticPassword https://localhost:9200
```

Test Kibana (open in browser):
```
https://<SIEM_VM_IP>:5601
```

Login with:
- Username: `elastic`
- Password: Your `ELASTIC_PASSWORD` from `.env`

#### 1.6. Configure Firewall

Allow Logstash port for Filebeat connections:

```bash
# Using ufw
sudo ufw allow 5044/tcp comment 'Logstash Beats input'

# Or using firewalld
sudo firewall-cmd --permanent --add-port=5044/tcp
sudo firewall-cmd --reload

# Or using iptables
sudo iptables -A INPUT -p tcp --dport 5044 -j ACCEPT
sudo iptables-save > /etc/iptables/rules.v4
```

### Part 2: Main Honeypot VM Setup

#### 2.1. Copy Filebeat Certificates from SIEM VM

On the **main honeypot VM**, copy the certificates generated on the SIEM VM:

```bash
# Replace SIEM_VM_IP with your SIEM VM IP address
cd ~/dp/openstack-work/filebeat/certs/

# Copy CA certificate
scp user@SIEM_VM_IP:~/dp/openstack-work/siem/logstash/certs/filebeat/ca.crt ./ca.crt

# Copy Filebeat client certificate
scp user@SIEM_VM_IP:~/dp/openstack-work/siem/logstash/certs/filebeat/filebeat.crt ./filebeat.crt

# Copy Filebeat client private key
scp user@SIEM_VM_IP:~/dp/openstack-work/siem/logstash/certs/filebeat/filebeat.key ./filebeat.key
```

Set correct permissions:

```bash
chmod 644 ca.crt filebeat.crt
chmod 600 filebeat.key
```

#### 2.2. Update Environment Variables

Edit your `openstack-work/.env` file and add/update:

```bash
# Enable ELK SIEM integration
ELK_ENABLED=true

# Logstash connection (on SIEM VM)
LOGSTASH_HOST=<SIEM_VM_IP>
LOGSTASH_PORT=5044

# Docker Compose project name (for log filtering)
COMPOSE_PROJECT_NAME=honeypot-ids-system-v1

# Environment identifier
ENVIRONMENT=production
```

#### 2.3. Restart Filebeat

```bash
cd ~/dp/openstack-work/
docker compose restart filebeat
```

#### 2.4. Verify Filebeat Connection

Check Filebeat logs:

```bash
docker compose logs filebeat | tail -50
```

You should see successful connection messages to Logstash.

### Part 3: Verification and Testing

#### 3.1. Check Log Flow from Main VM

On the **main honeypot VM**:

```bash
# Generate some test traffic
curl http://localhost/

# Check Filebeat is shipping logs
docker compose logs filebeat | grep -i "events"
```

#### 3.2. Check Log Receipt on SIEM VM

On the **SIEM VM**:

```bash
cd ~/dp/openstack-work/siem/docker/

# Check Logstash is receiving data
docker compose logs logstash | grep -i "beats"

# Wait a few minutes, then check Elasticsearch indices
curl -k -u elastic:YourPassword https://localhost:9200/_cat/indices?v
```

You should see indices like:
- `honeypot-docker-logs-YYYY.MM.DD`
- `honeypot-nginx-logs-YYYY.MM.DD`
- `honeypot-redis-logs-YYYY.MM.DD`

#### 3.3. View Logs in Kibana

1. Open Kibana: `https://<SIEM_VM_IP>:5601`
2. Login with elastic user
3. Go to **Analytics → Discover**
4. Create index patterns:
   - `honeypot-docker-logs-*`
   - `honeypot-nginx-logs-*`
   - `honeypot-redis-logs-*`
5. Start exploring your logs!

## Log Types Collected

### Docker Container Logs
- **Source:** `/var/lib/docker/containers/**/*.log`
- **Filtered by:** Docker Compose project name (`honeypot-ids-system-v1`)
- **Includes:** All container stdout/stderr logs
- **Index:** `honeypot-docker-logs-YYYY.MM.DD`

### Nginx Logs
- **Access logs:** `/var/log/nginx/access.log`
- **Error logs:** `/var/log/nginx/error.log`
- **Security logs:** `/var/log/nginx/security.log`
- **Index:** `honeypot-nginx-logs-YYYY.MM.DD`
- **Parsed fields:** Client IP, request, status code, user agent, etc.

### Redis Logs
- **Source:** Redis container logs via Docker
- **Index:** `honeypot-redis-logs-YYYY.MM.DD`

### Suricata IDS Logs
- **EVE JSON:** `/var/log/suricata/eve.json`
- **Fast log:** `/var/log/suricata/fast.log`
- **Index:** `honeypot-generic-logs-YYYY.MM.DD`

## Troubleshooting

### Filebeat Can't Connect to Logstash

**Symptoms:** Connection refused or timeout errors

**Solutions:**
1. Verify SIEM VM IP is correct in `.env`
2. Check firewall allows port 5044
3. Verify Logstash is running: `docker compose ps logstash`
4. Check Logstash logs: `docker compose logs logstash`

### SSL/TLS Certificate Errors

**Symptoms:** SSL handshake failures

**Solutions:**
1. Verify all three certificate files exist in `filebeat/certs/`
2. Check file permissions (644 for .crt, 600 for .key)
3. Ensure certificates were copied correctly from SIEM VM
4. Regenerate certificates if needed

### No Logs Appearing in Elasticsearch

**Symptoms:** Indices not created or empty

**Solutions:**
1. Check Filebeat is running: `docker compose ps filebeat`
2. Generate test traffic on main VM
3. Check Filebeat logs for errors
4. Verify Docker containers are running and generating logs
5. Check Logstash pipeline for errors: `docker compose logs logstash | grep ERROR`

### Docker Container Logs Not Collected

**Symptoms:** Only Nginx/Suricata logs appear

**Solutions:**
1. Verify Filebeat has Docker socket access: `ls -la /var/run/docker.sock`
2. Check Filebeat is running as root: `docker compose exec filebeat whoami`
3. Verify container logs exist: `ls -la /var/lib/docker/containers/`
4. Check compose project name matches: `docker inspect <container> | grep com.docker.compose.project`

## Maintenance

### Certificate Rotation

Certificates are valid for 1 year. To rotate:

1. On SIEM VM, regenerate certificates:
   ```bash
   cd ~/dp/openstack-work/siem/certs/root-ca/
   ./gen_elk_certs.sh
   ```

2. Restart ELK stack:
   ```bash
   cd ~/dp/openstack-work/siem/docker/
   docker compose restart
   ```

3. Copy new Filebeat certificates to main VM (repeat Part 2.1)

4. Restart Filebeat on main VM:
   ```bash
   docker compose restart filebeat
   ```

### Index Management

Elasticsearch indices grow over time. Configure Index Lifecycle Management (ILM) in Kibana:

1. Go to **Management → Stack Management → Index Lifecycle Policies**
2. Create policy to delete old indices after 30/60/90 days
3. Apply policy to honeypot indices

### Monitoring

Check system health regularly:

```bash
# On SIEM VM
cd ~/dp/openstack-work/siem/docker/

# Check service status
docker compose ps

# Check Elasticsearch cluster health
curl -k -u elastic:Password https://localhost:9200/_cluster/health?pretty

# Check disk usage
docker compose exec es01 df -h
```

## Security Considerations

1. **Change default passwords** in `.env` files
2. **Use firewall rules** to restrict access to ELK ports
3. **Keep certificates private** - never commit to version control
4. **Regular updates** - update ELK stack images regularly
5. **Network segmentation** - isolate SIEM VM on management network
6. **Access control** - limit who can access Kibana

## Performance Tuning

### For High Log Volume

If you're processing large amounts of logs:

1. **Increase Logstash workers** in `logstash/logstash.yml`:
   ```yaml
   pipeline.workers: 4
   pipeline.batch.size: 250
   ```

2. **Tune Elasticsearch heap** in SIEM `docker/.env`:
   ```bash
   ES_MEM_LIMIT=4g
   ```

3. **Optimize Filebeat** in main VM `filebeat/filebeat.yml`:
   ```yaml
   output.logstash:
     worker: 4
     bulk_max_size: 4096
   ```

4. **Use SSD storage** for Elasticsearch data

## Additional Resources

- [Elastic Stack Documentation](https://www.elastic.co/guide/index.html)
- [Filebeat Reference](https://www.elastic.co/guide/en/beats/filebeat/current/index.html)
- [Logstash Reference](https://www.elastic.co/guide/en/logstash/current/index.html)
- [Kibana Guide](https://www.elastic.co/guide/en/kibana/current/index.html)
