#!/bin/bash
# Create virtual environment if it doesn't exist
if [ ! -d "env" ]; then
  python3 -m venv env
fi

# Activate virtual environment
source env/bin/activate

# Install requirements
pip install -r requirements.txt


# Set filenames
CERT_FILE="cert.pem"
KEY_FILE="key.pem"

# Check if certificate and key already exist
if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
  echo "TLS certificate and key already exist."
else
  echo "Generating new self-signed TLS certificate..."
  openssl req -x509 -nodes -days 15 \
    -newkey rsa:2048 \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -subj "/CN=localhost" 2>/dev/null
  echo "Certificate generated: $CERT_FILE and $KEY_FILE"
fi

# Generate HMAC secret if it doesn't exist
if [ ! -f "hmac_key.pem" ]; then
    openssl rand -out hmac_key.pem 32 2>/dev/null

    # Protect the HMAC key file
    chmod 600 hmac_key.pem
fi

echo ""
echo "To activate the virtual environment in your terminal, run:"
echo "source env/bin/activate"