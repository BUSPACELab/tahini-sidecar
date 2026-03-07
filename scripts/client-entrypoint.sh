#!/usr/bin/env bash
# Client entrypoint: wait for server credentials, then connect with delegated TLS
set -e

SHARED_DIR="/shared"
WORKSPACE="/workspace"
SERVER_ADDR="server:8443"

echo "[client-entrypoint] waiting for delegated credential from server..."

# Wait for the server to publish credentials
TIMEOUT=120
ELAPSED=0
while [ ! -f "$SHARED_DIR/.dc-ready" ]; do
    sleep 1
    ELAPSED=$((ELAPSED + 1))
    if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
        echo "[client-entrypoint] ERROR: timed out waiting for credentials"
        exit 1
    fi
done

echo "[client-entrypoint] credentials found, waiting for server to start listening..."

# Give the server a moment to start accepting connections
# (the sidecar needs to do attestation + execveat + server bind)
sleep 5

echo "[client-entrypoint] connecting to $SERVER_ADDR with delegated TLS..."

exec /usr/local/bin/rpc-client \
    --dc-sig "$SHARED_DIR/fizz_client.json" \
    --dc-cert "$SHARED_DIR/fizz.crt" \
    --server "$SERVER_ADDR"
