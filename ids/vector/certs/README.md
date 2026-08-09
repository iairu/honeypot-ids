# ELK SIEM SSL Certificates

This directory contains SSL/TLS certificates required for secure communication between the Vector agent and the ELK SIEM's Vector aggregator running on a separate VM.

## Required Certificates

You need the following certificates from your SIEM VM:

1. **ca.crt** - CA certificate (for verifying server identity)
2. **vector-agent.crt** - Vector agent client certificate (for client authentication)
3. **vector-agent.key** - Vector agent client private key (for client authentication)

## Setup Instructions

### 1. Generate Certificates on SIEM VM

On your SIEM VM, run the certificate generation script:

```bash
# On SIEM VM, in the siem/ project directory
cd certs/root-ca/
./gen_elk_certs.sh
```

This script generates all required certificates including ones for the Vector agent.

### 2. Copy Certificates from SIEM VM to Main VM

Copy the required certificates from the SIEM VM to this directory:

```bash
# From the main honeypot VM, copy certificates from SIEM VM
# Replace <SIEM_VM_IP> with your SIEM VM IP address

# Copy CA certificate
scp user@<SIEM_VM_IP>:/path/to/siem/elasticsearch/certs/ca/ca.crt ./ca.crt

# Copy Vector agent client certificate and key
scp user@<SIEM_VM_IP>:/path/to/siem/vector/certs/vector-agent/vector-agent.crt ./vector-agent.crt
scp user@<SIEM_VM_IP>:/path/to/siem/vector/certs/vector-agent/vector-agent.key ./vector-agent.key
```

**Note:** The exact paths depend on how the gen_elk_certs.sh script organizes certificates. Check the SIEM directory structure after running the script.

### 3. Set Correct Permissions

```bash
chmod 644 ca.crt vector-agent.crt
chmod 600 vector-agent.key
```

### 4. Configure Environment Variables

In your main `ids/.env` file, set these variables:

```bash
# Enable ELK SIEM integration
ELK_ENABLED=true

# Vector aggregator connection (on SIEM VM)
VECTOR_HOST=<SIEM_VM_IP>
VECTOR_PORT=6000

# Docker Compose project name for log filtering
COMPOSE_PROJECT_NAME=honeypot-ids-system-v1

# Environment identifier
ENVIRONMENT=production
```

### 5. Restart Vector

```bash
docker compose restart vector
```

## Testing Connection

Test the Vector agent's connection to the aggregator:

```bash
docker compose logs vector | grep -i "vector"
```

Successful output should show a healthy sink with no connection errors.

Check if logs are being shipped:

```bash
docker compose logs vector | tail -50
```

## Verifying Logs in SIEM

On your SIEM VM, check if logs are being received:

```bash
# Check Vector aggregator logs
docker compose logs vector | grep -i "source"

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
4. Ensure the CA certificate matches the one used to sign the aggregator's certificate

### Connection Refused

If connection is refused:
1. Verify VECTOR_HOST IP is correct
2. Check firewall rules allow port 6000 between VMs
3. Verify Vector is running on SIEM VM: `docker compose ps vector`
4. Check Vector port binding: `docker compose logs vector | grep 6000`

### No Logs Appearing

If the Vector agent connects but no logs appear:
1. Check Docker container logs are being created: `docker compose logs vector | grep docker_in`
2. Verify Vector has permission to read the Docker socket
3. Check Vector is running as root: `docker compose ps vector`
4. Review Vector's internal logs: `cat vector/logs/vector.log`

## Security Notes

- **Never commit certificates to version control**
- Keep `.key` files private with restricted permissions (600)
- Use strong passphrases if generating password-protected keys
- Rotate certificates periodically (every 90-365 days)
- In production, use certificates from a trusted CA
