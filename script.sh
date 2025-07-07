#!/bin/bash

# Set filenames
CERT_FILE="cert.pem"
KEY_FILE="key.pem"

# Check if certificate and key already exist
if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
  echo "✔️ TLS certificate and key already exist."
else
  echo "🔐 Generating new self-signed TLS certificate..."
  openssl req -x509 -nodes -days 365 \
    -newkey rsa:2048 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -subj "/C=BR/ST=State/L=City/O=MyCompany/OU=Dev/CN=localhost"
  echo "✅ Certificate generated: $CERT_FILE and $KEY_FILE"
fi
