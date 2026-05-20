#!/bin/bash
set -e

P12_FILE=$1
PASSWORD=$2
EXPECTED_CN=$3

if [ ! -f "$P12_FILE" ]; then
    echo "Error: $P12_FILE not found"
    exit 1
fi

echo "Inspecting $P12_FILE..."

# Check if we can open it with the password and list contents
openssl pkcs12 -in "$P12_FILE" -passin "pass:$PASSWORD" -nokeys -info

# Extract the certificate and check the CN
CN=$(openssl pkcs12 -in "$P12_FILE" -passin "pass:$PASSWORD" -clcerts -nokeys | openssl x509 -noout -subject | grep -o "CN = [^,]*" | cut -d' ' -f3)

echo "Extracted CN: $CN"

if [ "$CN" != "$EXPECTED_CN" ]; then
    echo "Error: Expected CN '$EXPECTED_CN', but got '$CN'"
    exit 1
fi

# Check if private key is present and matches the cert
openssl pkcs12 -in "$P12_FILE" -passin "pass:$PASSWORD" -nocerts -nodes -out temp.key
openssl pkcs12 -in "$P12_FILE" -passin "pass:$PASSWORD" -clcerts -nokeys -out temp.crt

PUBKEY_FROM_CERT=$(openssl x509 -in temp.crt -noout -pubkey)
PUBKEY_FROM_KEY=$(openssl pkey -in temp.key -pubout)

if [ "$PUBKEY_FROM_CERT" != "$PUBKEY_FROM_KEY" ]; then
    echo "Error: Private key does not match certificate"
    rm temp.key temp.crt
    exit 1
fi

echo "Success: P12 file is valid and contains matching key/cert for $EXPECTED_CN"
rm temp.key temp.crt
