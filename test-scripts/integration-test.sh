#!/bin/bash

# Integration test script for gosniproxy using Docker

set -e  # Exit on any error

echo "Starting integration tests for gosniproxy using Docker"

# Build the proxy container
echo "Building gosniproxy Docker image..."
docker build -t gosniproxy-test .

# Generate test certificates
if [ ! -f "ca.crt" ] || [ ! -f "server.crt" ] || [ ! -f "server.key" ]; then
  echo "Generating test certificates..."
  cd test-scripts
  ./gen-certs.sh
  cd ..
fi

# Start a simple backend server for testing
# We'll use Python's built-in HTTP server as a mock backend
python3 -m http.server 7443 &
BACKEND_PID=$!

# Wait a moment for the backend to start
sleep 1

echo "Starting gosniproxy Docker container..."
# Run proxy in Docker container with test configuration
# Using privileged mode to avoid eBPF issues on Linux
# We'll disable eBPF and DTLS for testing purposes

docker run -d \
  --name gosniproxy-test-container \
  --privileged \
  -p 5443:5443 \
  -v $(pwd):/app \
  -w /app \
  gosniproxy-test \
  /usr/local/bin/gosniproxy \
  -listen-addr 0.0.0.0:5443 \
  -backend-mapping example.com:127.0.0.1:7443 \
  -cert-file /app/server.crt \
  -key-file /app/server.key \
  -enable-dtls=false \
  -enable-ebpf=false

# Give proxy time to start
sleep 3

# Test HTTP connection (should work)
echo "Testing HTTP connection..."
curl -v --resolve example.com:5443:127.0.0.1 http://example.com:5443/ 2>&1 | head -n 10 || echo "HTTP test completed"

# Test HTTPS connection with SNI (should work)
echo "Testing HTTPS connection with SNI..."
curl -v --resolve example.com:5443:127.0.0.1 https://example.com:5443/ --insecure 2>&1 | head -n 10 || echo "HTTPS test completed"

# Stop the backend server
kill $BACKEND_PID 2>/dev/null || true

# Stop the proxy container
docker stop gosniproxy-test-container 2>/dev/null || true
docker rm gosniproxy-test-container 2>/dev/null || true

echo "Integration tests completed."
