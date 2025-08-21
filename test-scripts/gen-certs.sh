#!/bin/bash

# Generate test certificates for gosniproxy testing

echo "Generating CA certificate..."
openssl req -x509 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 365 -nodes -subj "/CN=TestCA"

# Generate server certificate
openssl req -newkey rsa:2048 -keyout server.key -out server.csr -nodes -subj "/CN=localhost"

# Sign server certificate with CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365

# Generate client certificate
openssl req -newkey rsa:2048 -keyout client.key -out client.csr -nodes -subj "/CN=test-client"

# Sign client certificate with CA
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365

echo "Certificate generation complete."
echo "Files created:"
echo "- ca.crt (CA certificate)"
echo "- ca.key (CA private key)"
echo "- server.crt (Server certificate)"
echo "- server.key (Server private key)"
echo "- client.crt (Client certificate)"
echo "- client.key (Client private key)"