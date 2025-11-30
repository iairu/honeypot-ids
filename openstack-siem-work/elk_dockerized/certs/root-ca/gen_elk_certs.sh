#!/bin/bash

# Set variables
CERTS_DIR="certs"
ROOT_CA_NAME="rootCA"
DAYS_VALID=365   # 1 year validity
ELASTIC_HOSTS=("es01" "logstash" "kibana")  # ELK components

# Create directory to store certificates
mkdir -p $CERTS_DIR
cd $CERTS_DIR

echo "🚀 Generating Root CA..."
# Generate Root CA key (silent mode)
openssl genpkey -algorithm RSA -out ${ROOT_CA_NAME}.key 2>/dev/null
# Create Root CA certificate (silent mode)
openssl req -x509 -new -nodes -key ${ROOT_CA_NAME}.key -sha256 -days $DAYS_VALID -out ${ROOT_CA_NAME}.crt -subj "/C=US/ST=Example/L=City/O=MyOrg/CN=RootCA" 2>/dev/null

echo "✅ Root CA created: ${ROOT_CA_NAME}.crt"

# Generate certificates for each ELK component
for SERVICE in "${ELASTIC_HOSTS[@]}"; do
    echo "🚀 Generating certificate for $SERVICE..."

    # Generate private key (silent mode)
    openssl genpkey -algorithm RSA -out ${SERVICE}.key 2>/dev/null

    # Create a certificate signing request (CSR) (silent mode)
    openssl req -new -key ${SERVICE}.key -out ${SERVICE}.csr -subj "/C=US/ST=Example/L=City/O=MyOrg/CN=${SERVICE}" 2>/dev/null

    # Create and sign certificate using Root CA (silent mode)
    openssl x509 -req -in ${SERVICE}.csr -CA ${ROOT_CA_NAME}.crt -CAkey ${ROOT_CA_NAME}.key -CAcreateserial -out ${SERVICE}.crt -days $DAYS_VALID -sha256 2>/dev/null

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

# Logstash certificates
mkdir -p ../../../logstash/certs/ca
mkdir -p ../../../logstash/certs/logstash

cp rootCA.crt ../../../logstash/certs/ca/ca.crt
cp logstash.key ../../../logstash/certs/logstash/logstash.key
cp logstash.crt ../../../logstash/certs/logstash/logstash.crt


# TODO oneday change to dedicated user in Dockerfile maybe
chown 1000:1000 ../../../kibana/certs/kibana/kibana.key
chown 1000:1000 ../../../logstash/certs/logstash/logstash.key
chown 1000:1000 ../../../elasticsearch/certs/es01/es01.key

echo "✅ Certificates copied successfully!"

