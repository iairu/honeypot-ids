#!/bin/bash

# Set variables
CERTS_DIR="certs"
ROOT_CA_NAME="rootCA"
DAYS_VALID=365   # 1 year validity
ELASTIC_HOSTS=("es01" "vector" "kibana" "vector-agent")  # ELK components (vector-agent is the client cert for the remote shipper)

# Create directory to store certificates
mkdir -p $CERTS_DIR
cd $CERTS_DIR

echo "🚀 Generating Root CA..."
# Generate Root CA key (silent mode)
openssl genpkey -algorithm RSA -out ${ROOT_CA_NAME}.key 2>/dev/null
# Create Root CA certificate (silent mode)
openssl req -x509 -new -nodes -key ${ROOT_CA_NAME}.key -sha256 -days $DAYS_VALID -out ${ROOT_CA_NAME}.crt -subj "/C=US/ST=Example/L=City/O=MyOrg/CN=RootCA" 2>/dev/null

echo "✅ Root CA created: ${ROOT_CA_NAME}.crt"

# "vector" is the aggregator's SERVER cert -- issued to the SIEM stack's
# `vector_inbound` container -- for the edge shipper's (`vector_outbound`)
# mTLS connection -- the edge shipper's TLS client validates the hostname
# it connected with against this cert's identity. A bare CN-only cert
# (what every other service here uses) only matches a client connecting
# via the exact string "vector_inbound", which breaks in two real cases:
# (1) single-host dev/testing, where the edge shipper reaches this
# container through host.docker.internal (its own compose project has no
# shared network with this one -- see ids/docker-compose.yml's
# vector_outbound service comment) instead of the container name
# "vector_inbound", and (2) genuine two-host production, where the edge
# shipper's default VECTOR_HOST is the SIEM VM's raw IP (see
# ids/vector/vector.yaml), which a CN-only cert never matches either --
# confirmed live: this was failing with "hostname mismatch" even before
# single-host testing was a consideration. Listing every hostname/IP this
# cert should be valid for as Subject Alternative Names fixes both,
# without weakening verification (verify_certificate + verify_hostname
# both stay enabled end to end) -- unlike a public CA, this is a private
# CA minted specifically for this one shipper<->aggregator pairing, so
# the CA-chain trust already IS the real security boundary; SANs here are
# about covering every legitimate way to reach it, not about narrowing
# what's trusted.
#
# NOTE: if the real SIEM host ends up at a different IP/hostname than the
# 147.175.151.193 placeholder below, add it here and re-run this script.
VECTOR_SAN="DNS:vector_inbound,DNS:localhost,DNS:host.docker.internal,IP:127.0.0.1,IP:147.175.151.193"

# Generate certificates for each ELK component
for SERVICE in "${ELASTIC_HOSTS[@]}"; do
    echo "🚀 Generating certificate for $SERVICE..."

    # Generate private key (silent mode)
    openssl genpkey -algorithm RSA -out ${SERVICE}.key 2>/dev/null

    # Create a certificate signing request (CSR) (silent mode)
    openssl req -new -key ${SERVICE}.key -out ${SERVICE}.csr -subj "/C=US/ST=Example/L=City/O=MyOrg/CN=${SERVICE}" 2>/dev/null

    if [ "$SERVICE" = "vector" ]; then
        # Sign with a SAN extension (see VECTOR_SAN comment above).
        openssl x509 -req -in ${SERVICE}.csr -CA ${ROOT_CA_NAME}.crt -CAkey ${ROOT_CA_NAME}.key -CAcreateserial \
            -out ${SERVICE}.crt -days $DAYS_VALID -sha256 \
            -extfile <(printf "subjectAltName=%s" "$VECTOR_SAN") 2>/dev/null
    else
        # Create and sign certificate using Root CA (silent mode)
        openssl x509 -req -in ${SERVICE}.csr -CA ${ROOT_CA_NAME}.crt -CAkey ${ROOT_CA_NAME}.key -CAcreateserial -out ${SERVICE}.crt -days $DAYS_VALID -sha256 2>/dev/null
    fi

    echo "✅ Certificate generated for $SERVICE: ${SERVICE}.crt"

    # Clean up CSR
    rm -f ${SERVICE}.csr
done

# Display created certificates
ls -l *.crt *.key | awk '{print $9, $5}'

echo "🎉 All certificates are ready in the '$CERTS_DIR' folder!"

# ----------------------------------------
# Copying certificates to correct locations
# ----------------------------------------

echo "🚀 Copying certificates to ELK locations..."

# Elasticsearch certificates
mkdir -p ../../../elasticsearch/certs/ca
mkdir -p ../../../elasticsearch/certs/es01
mkdir -p ../../../elasticsearch/certs/kibana

cp rootCA.crt ../../../elasticsearch/certs/ca/ca.crt
cp es01.key ../../../elasticsearch/certs/es01/es01.key
cp es01.crt ../../../elasticsearch/certs/es01/es01.crt
cp kibana.crt ../../../elasticsearch/certs/kibana/kibana.crt

# Kibana certificates
mkdir -p ../../../kibana/certs/ca
mkdir -p ../../../kibana/certs/kibana
mkdir -p ../../../kibana/certs/es01

cp rootCA.crt ../../../kibana/certs/ca/ca.crt
cp kibana.key ../../../kibana/certs/kibana/kibana.key
cp kibana.crt ../../../kibana/certs/kibana/kibana.crt
cp es01.crt ../../../kibana/certs/es01/es01.crt

# Vector (aggregator) certificates
mkdir -p ../../../vector/certs/ca
mkdir -p ../../../vector/certs/vector
mkdir -p ../../../vector/certs/vector-agent

cp rootCA.crt ../../../vector/certs/ca/ca.crt
cp vector.key ../../../vector/certs/vector/vector.key
cp vector.crt ../../../vector/certs/vector/vector.crt

# Vector-agent client certificate (copy vector-agent.crt/key + ca.crt to the
# honeypot VM's vector/certs/ directory for mTLS to the aggregator above)
cp rootCA.crt ../../../vector/certs/vector-agent/ca.crt
cp vector-agent.key ../../../vector/certs/vector-agent/vector-agent.key
cp vector-agent.crt ../../../vector/certs/vector-agent/vector-agent.crt


# TODO oneday change to dedicated user in Dockerfile maybe
chown 1000:1000 ../../../kibana/certs/kibana/kibana.key
chown 1000:1000 ../../../vector/certs/vector/vector.key
chown 1000:1000 ../../../elasticsearch/certs/es01/es01.key

echo "✅ Certificates copied successfully!"

