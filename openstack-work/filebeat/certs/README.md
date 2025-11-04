# ELK SSL Certificates

Place your ELK/Elasticsearch CA certificate here to enable SSL/TLS verification.

## Setup Instructions

### 1. Obtain Your ELK CA Certificate

From your Elasticsearch server, copy the CA certificate:

```bash
# On your Elasticsearch server
cat /etc/elasticsearch/certs/http_ca.crt
```

### 2. Copy to This Directory

Save the certificate as `ca.crt` in this directory:

```bash
# On your honeypot system
cat > /home/debian/dp/openstack-work/filebeat/certs/ca.crt <<'EOF'
-----BEGIN CERTIFICATE-----
[Your certificate content here]
-----END CERTIFICATE-----
EOF
```

### 3. Set Permissions

```bash
chmod 644 /home/debian/dp/openstack-work/filebeat/certs/ca.crt
```

### 4. Enable ELK in .env

```bash
ELK_ENABLED=true
ELASTICSEARCH_HOST=your-elk-server.example.com
ELASTICSEARCH_USER=elastic
ELASTICSEARCH_PASSWORD=your-secure-password
```

### 5. Restart Services

```bash
docker compose restart filebeat reverse_proxy
```

## Testing Connection

Test Filebeat connection to Elasticsearch:

```bash
docker compose logs filebeat | grep -i "connection"
```

Successful output should show:
```
Connection to https://your-elk-server:9200 established
```

## Troubleshooting

If you see SSL verification errors, you can temporarily disable verification:

```bash
# In .env file
ELASTICSEARCH_SSL_VERIFY=none
```

**WARNING:** Only use `SSL_VERIFY=none` for testing. Always use proper certificates in production!
