#!/bin/bash
set -e

# Setup environment
mkdir -p tests/mock-ca
if [ ! -f tests/mock-ca/root.key ]; then
    echo "Generating mock root CA..."
    openssl ecparam -name prime256v1 -genkey -noout -out tests/mock-ca/root.key
    openssl req -new -x509 -sha256 -key tests/mock-ca/root.key -out tests/mock-ca/root.crt -subj "/CN=Mock Root CA" -days 365
fi

export PATH="$(pwd)/tests/bin:$PATH"
export ROOT_CA_PATH="$(pwd)/tests/mock-ca/root.crt"
export MOCK_STEP_CLI=false # We want to use our shim, not the internal backend mock
export TRUSTED_PROXIES='["127.0.0.1"]'

# Cleanup
cleanup() {
    echo "Cleaning up..."
    kill $(lsof -t -i :8000) 2>/dev/null || true
    kill $(lsof -t -i :5173) 2>/dev/null || true
}
trap cleanup EXIT

# Start Backend
echo "Starting backend..."
uv run uvicorn main:app --port 8000 > backend.log 2>&1 &
BACKEND_PID=$!

# Start Frontend
echo "Starting frontend..."
cd frontend
npm run dev -- --port 5173 > ../frontend.log 2>&1 &
FRONTEND_PID=$!
cd ..

# Wait for services to be ready
echo "Waiting for services..."
timeout 30s bash -c 'until curl -s http://localhost:5173 > /dev/null; do sleep 1; done'
timeout 30s bash -c 'until curl -s http://localhost:8000/api/me > /dev/null; do sleep 1; done'

# Run Playwright tests
echo "Running Playwright tests..."
cd frontend
npx playwright test
cd ..

# Run P12 verification
echo "Verifying downloaded P12..."
./tests/verify_p12.sh test-vending.p12 test-password-123 test-e2e-user
