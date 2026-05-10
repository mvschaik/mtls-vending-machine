# Technical Specification: Secure mTLS Vending Machine

## Overview

Build a self-service web portal that allows authenticated users to generate mTLS client certificates without the private key ever touching the server.

## Architecture

1. **Identity**: The app sits behind Traefik + Authentik (Forward Auth). It must trust `X-Authentik-Username` for the Certificate Common Name (CN).
1. **Frontend** (The "Secure" Zone): Uses the Browser **Web Crypto API** and **Forge.js** (via CDN) to generate keys and package the final bundle.
1. **Backend** (The "Signer"): A FastAPI app that interface with a `step-ca` instance to sign CSRs.

## 1. Frontend Requirements (HTML/JavaScript)

* **Library**: Include `node-forge` via CDN for CSR creation and PKCS#12 (.p12) bundling.
* **Key Generation**: Use `window.crypto.subtle.generateKey` to create an RSA-2048 or ECDSA P-256 key pair.
* **CSR Creation**: 
  * Extract the username from the `X-Authentik-Username` header (passed via the backend template).
  * Create a CSR using the public key with `CN=[Username]`.
* **The "Sign" Request**: `POST` the PEM-encoded CSR to the backend.
* **The Bundle**:
  * Receive the signed Public Certificate and the Root CA certificate from the backend.
  * Use `forge.js` to combine the **locally held private key**, the signed cert, and the root cert into a `.p12` file.
  * Prompt the user for a "Transport Password" to encrypt the `.p12`.
* **Download**: Trigger a browser download of `[username].p12`.

Note: please use `Tailwind CSS` for a much more professional-looking
"Vending Machine".

## 2. Backend Requirements (Python/FastAPI)

* **Endpoint `GET /`**:
  * Read `X-Authentik-Username`.
  * Serve the frontend HTML, injecting the username into the JS context.
* **Endpoint `POST /sign`**:
  * Accept a JSON payload containing a PEM-encoded CSR.
  * Validation: Ensure the CSR's Subject CN matches the `X-Authentik-Username` header to prevent users from spoofing other identities.
  * **Smallstep Interaction**: Use `subprocess` to run:
    ```
    step ca sign --provisioner [PROVISIONER_NAME] --provisioner-password-file [PASS_FILE] [CSR_FILE] [OUTPUT_CERT_FILE]
    ```
  * Return a JSON response containing the signed certificate PEM and the Root CA PEM.

* Environment Variables:
  * `STEP_CA_URL`, `STEP_PROVISIONER`, `STEP_PROVISIONER_PASSWORD`, `ROOT_CA_PATH`.

## 3. Dockerization

* **Base Image**: `python:3.11-slim`.
* **Installation**: The Dockerfile must download and install the `step` CLI binary from Smallstep's GitHub releases.
* **Permissions**: Ensure the app has read access to the `root_ca.crt` and a way to store the provisioner password securely (e.g., a file in `/run/secrets/`).

## 4. Example Logic Flow

1. User logs in via Authentik $\rightarrow$ Redirected to Portal.
1. JS generates Private Key $\rightarrow$ Browser Memory.
1. JS creates CSR $\rightarrow$ Sent to FastAPI.
1. FastAPI calls step ca sign $\rightarrow$ Returns Signed Cert.
1. JS takes Private Key + Signed Cert $\rightarrow$ Creates .p12 $\rightarrow$ Download.

## 5. Security Guardrails for Coder

* Ensure the FastAPI backend strictly validates the CN in the CSR against the header.
* The backend should **never** request or store the private key.
* Set a short TTL (e.g., 24h or 1 year) for the certificates in the `step ca sign` command using the `--not-after` flag.

