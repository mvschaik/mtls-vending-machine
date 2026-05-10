# mTLS Vending Machine

A self-service web portal for generating mTLS client certificates securely. The private key never leaves the user's browser.

## Features

- **Secure Key Generation**: RSA keys and CSRs are generated in the browser using Forge.js.
- **Automated Signing**: Backend interfaces with Smallstep CA to sign CSRs.
- **No Private Key Exposure**: The server never sees the user's private key.
- **Identity Integration**: Trusts `X-Authentik-Username` (or configurable header) from a trusted proxy.

## Local Development

This project uses **uv** for Python dependency management.

### Prerequisites

- [uv](https://github.com/astral-sh/uv) installed on your machine.
- [step CLI](https://smallstep.com/docs/step-cli/installation) (if you want to test signing locally without mocks).

### Setup

1. Clone the repository and navigate to the project directory.
2. Initialize the environment and install dependencies:
   ```bash
   uv sync
   ```
3. Create a `.env` file with your configuration (optional, defaults are in `config.py`).
4. Run the application:
   ```bash
   uv run uvicorn main:app --reload
   ```

### Running Tests

```bash
uv run pytest
```

## Docker Deployment

### Build

To build the Docker image:

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
