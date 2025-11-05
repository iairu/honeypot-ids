# ELK SIEM SSL Certificates

This directory contains SSL/TLS certificates required for secure communication between Filebeat and the ELK SIEM (Logstash) running on a separate VM.

## Required Certificates

You need the following certificates from your SIEM VM:

1. **ca.crt** - CA certificate (for verifying server identity)
2. **filebeat.crt** - Filebeat client certificate (for client authentication)
3. **filebeat.key** - Filebeat client private key (for client authentication)

## Setup Instructions

### 1. Generate Certificates on SIEM VM

On your SIEM VM, run the certificate generation script:

```bash
# On SIEM VM in openstack-work/siem directory
cd certs/root-ca/
./gen_elk_certs.sh
```

This script generates all required certificates including ones for Filebeat.

### 2. Copy Certificates from SIEM VM to Main VM

Copy the required certificates from the SIEM VM to this directory:

```bash
# From the main honeypot VM, copy certificates from SIEM VM
# Replace <SIEM_VM_IP> with your SIEM VM IP address

# Copy CA certificate
scp user@<SIEM_VM_IP>:/path/to/siem/elasticsearch/certs/ca/ca.crt ./ca.crt

# Copy Filebeat client certificate and key
scp user@<SIEM_VM_IP>:/path/to/siem/logstash/certs/filebeat/filebeat.crt ./filebeat.crt
scp user@<SIEM_VM_IP>:/path/to/siem/logstash/certs/filebeat/filebeat.key ./filebeat.key
```

**Note:** The exact paths depend on how the gen_elk_certs.sh script organizes certificates. Check the SIEM directory structure after running the script.

### 3. Set Correct Permissions

```bash
chmod 644 ca.crt filebeat.crt
chmod 600 filebeat.key
```

### 4. Configure Environment Variables

In your main `openstack-work/.env` file, set these variables:

```bash
# Enable ELK SIEM integration
ELK_ENABLED=true

# Logstash connection (on SIEM VM)
LOGSTASH_HOST=<SIEM_VM_IP>
LOGSTASH_PORT=5044

# Docker Compose project name for log filtering
COMPOSE_PROJECT_NAME=honeypot-ids-system-v1

# Environment identifier
ENVIRONMENT=production
```

### 5. Restart Filebeat

```bash
docker compose restart filebeat
```

## Testing Connection

Test Filebeat connection to Logstash:

```bash
docker compose logs filebeat | grep -i "logstash"
```

Successful output should show:
```
Connection to Logstash (<SIEM_VM_IP>:5044) established
```

Check if logs are being shipped:

```bash
docker compose logs filebeat | tail -50
```

## Verifying Logs in SIEM

On your SIEM VM, check if logs are being received:

```bash
# Check Logstash logs
docker compose logs logstash | grep -i "beats"

# Check Elasticsearch indices
curl -k -u elastic:${ELASTIC_PASSWORD} https://localhost:9200/_cat/indices?v | grep honeypot
```

You should see indices like:
- `honeypot-docker-logs-YYYY.MM.DD`
- `honeypot-nginx-logs-YYYY.MM.DD`
- `honeypot-redis-logs-YYYY.MM.DD`

## Troubleshooting

### SSL Handshake Errors

If you see SSL handshake errors:
1. Verify all three certificate files exist in this directory
2. Check file permissions (644 for .crt files, 600 for .key file)
3. Verify the certificates were generated correctly on the SIEM VM
4. Ensure the CA certificate matches the one used to sign Logstash's certificate

### Connection Refused

If connection is refused:
1. Verify LOGSTASH_HOST IP is correct
2. Check firewall rules allow port 5044 between VMs
3. Verify Logstash is running on SIEM VM: `docker compose ps logstash`
4. Check Logstash port binding: `docker compose logs logstash | grep 5044`

### No Logs Appearing

If Filebeat connects but no logs appear:
1. Check Docker container logs are being created: `ls -la /var/lib/docker/containers/`
2. Verify Filebeat has permission to read Docker socket and container logs
3. Check Filebeat is running as root: `docker compose ps filebeat`
4. Review Filebeat internal logs: `cat filebeat/logs/filebeat.log`

## Security Notes

- **Never commit certificates to version control**
- Keep `.key` files private with restricted permissions (600)
- Use strong passphrases if generating password-protected keys
- Rotate certificates periodically (every 90-365 days)
- In production, use certificates from a trusted CA
