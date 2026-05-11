# mTLS Vending Machine

A self-service web portal for generating mTLS client certificates securely. The private key never leaves the user's browser.

## Features

- **Secure Key Generation**: RSA keys and CSRs are generated in the browser using Forge.js.
- **Automated Signing**: Backend interfaces with Smallstep CA to sign CSRs.
- **No Private Key Exposure**: The server never sees the user's private key.
- **Identity Integration**: Trusts `X-Authentik-Username` (or configurable header) from a trusted proxy.

## Architecture & Deployment

The mTLS Vending Machine is designed to operate as a self-service component within a secure infrastructure.

### The Stack

1.  **Traefik**: Acts as the entry point, handling TLS termination and routing.
2.  **Authentik**: Operates in **Proxy Mode** using **Forward Auth**. It authenticates the user and injects the `X-Authentik-Username` header into the request.
3.  **Smallstep CA**: The backend certificate authority that signs the CSRs.

### Workflow

*   User navigates to `mtls.example.com`.
*   Traefik delegates authentication to Authentik.
*   Upon successful login, the request is forwarded to the Vending Machine with the user's identity in the headers.
*   The user generates their keypair and CSR in the browser, which are then signed by the backend via Smallstep.

### Docker Compose Example

```yaml
services:
  vending-machine:
    image: ghcr.io/mvschaik/mtls-vending-machine:main
    container_name: mtls-vending-machine
    restart: unless-stopped
    environment:
      - STEP_CA_URL=https://ca.internal
      - STEP_PROVISIONER=vending-machine
      - STEP_PROVISIONER_PASSWORD_FILE=/run/secrets/step_password
      - ROOT_CA_PATH=/run/secrets/root_ca.crt
      - TRUSTED_PROXIES=["172.16.0.0/12"] # Adjust to your Docker network
    secrets:
      - step_password
      - root_ca.crt
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.mtls.rule=Host(`mtls.example.com`)"
      - "traefik.http.routers.mtls.entrypoints=websecure"
      - "traefik.http.routers.mtls.tls=true"
      - "traefik.http.routers.mtls.middlewares=authentik@docker"

secrets:
  step_password:
    file: ./secrets/password.txt
  root_ca.crt:
    file: ./secrets/root_ca.crt
```

## Local Development

This project uses **uv** for Python dependency management and **Node.js** for the TypeScript frontend.

### Prerequisites

- [uv](https://github.com/astral-sh/uv) installed on your machine.
- [Node.js](https://nodejs.org/) (v20+) and **npm**.
- [step CLI](https://smallstep.com/docs/step-cli/installation) (if you want to test signing locally without mocks).

### Setup

1. Clone the repository and navigate to the project directory.
2. Initialize the Python environment and install dependencies:
   ```bash
   uv sync
   ```
3. Initialize the frontend and install dependencies:
   ```bash
   cd frontend && npm install && cd ..
   ```
4. Create a `.env` file with your configuration (optional, defaults are in `config.py`).

### Running the Application

For the best development experience, run the backend and frontend separately:

**1. Start the Backend:**
```bash
uv run uvicorn main:app --reload
```
The backend runs on `http://localhost:8000`.

**2. Start the Frontend (with HMR and Proxy):**
```bash
cd frontend && npm run dev
```
The frontend runs on `http://localhost:5173` and proxies API requests to the backend. You can now step through TypeScript code in the browser.

### Running Tests

**Backend Tests:**
```bash
uv run pytest
```

**Frontend Tests:**
```bash
cd frontend && npm test
```

## Docker Deployment

### Build

The Docker build is **multi-stage**. It automatically builds the TypeScript frontend and packages it with the Python backend.

```bash
docker build -t mtls-vending-machine .
```

### Run

To run the container, you need to provide the necessary environment variables and mount the Root CA and provisioner password file.

```bash
docker run -d \
  --name mtls-vending-machine \
  -p 8000:8000 \
  -e STEP_CA_URL="https://ca.example.com" \
  -e STEP_PROVISIONER="vending-machine" \
  -e STEP_PROVISIONER_PASSWORD_FILE="/secrets/password.txt" \
  -e ROOT_CA_PATH="/secrets/root_ca.crt" \
  -v $(pwd)/secrets:/secrets \
  mtls-vending-machine
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `STEP_CA_URL` | The URL of your Smallstep CA instance. | `https://ca.internal` |
| `STEP_PROVISIONER` | The name of the JWK provisioner to use. | `vending-machine` |
| `STEP_PROVISIONER_PASSWORD_FILE` | Path to the file containing the provisioner password. | `None` |
| `ROOT_CA_PATH` | Path to the Root CA certificate PEM file. | `/etc/step-ca/certs/root_ca.crt` |
| `CERT_DURATION` | TTL for the issued certificates (e.g., `8760h`, `24h`). | `8760h` |
| `AUTHENTIK_USERNAME_HEADER` | The header used to identify the user. | `X-Authentik-Username` |
| `TRUSTED_PROXIES` | JSON list of trusted proxy IPs/CIDRs (e.g., `["10.0.0.0/8"]`). Use `["*"]` to trust all (unsafe). | `["127.0.0.1"]` |

## Smallstep CA Configuration

The Vending Machine requires a **JWK Provisioner** in your Smallstep CA.

### Create a JWK Provisioner

Run the following command on your Smallstep CA server (or via an admin-privileged CLI):

```bash
step ca provisioner add vending-machine --type=JWK --create
```

This will generate a new JWK key pair. You will be prompted for a password to protect the private key. **This is the password you must store in a file and provide via the `STEP_PROVISIONER_PASSWORD_FILE` environment variable.**

## Security Hardening

- **Non-Root User**: The application runs as `appuser` (UID 1000).
- **Minimal Base Image**: Uses `python:3.14-slim`.
- **Read-Only Context**: Ensure mounted secrets have appropriate permissions for the `appuser`.
