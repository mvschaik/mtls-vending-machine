# Technical Specification: Secure mTLS Vending Machine

## Overview

Build a self-service web portal that allows authenticated users to generate mTLS client certificates without the private key ever touching the server.

## Architecture

1. **Identity**: The app sits behind Traefik + Authentik (Forward Auth). It must trust `X-Authentik-Username` for the Certificate Common Name (CN).
1. **Frontend** (The "Secure" Zone): Uses **Forge.js** (via CDN) to generate keys, create CSRs, and package the final PKCS#12 bundle. Using Forge.js consistently avoids interoperability issues with browser Web Crypto keys.
1. **Backend** (The "Signer"): A FastAPI app that interfaces with a `step-ca` instance to sign CSRs.

## 1. Frontend Requirements (HTML/JavaScript)

* **Library**: Include `node-forge` via CDN.
* **Styling**: **Tailwind CSS** for a professional "Vending Machine" UI.
* **Key Generation**: Use `forge.pki.rsa.generateKeyPair` (2048-bit) or ECDSA.
* **CSR Creation**: 
  * Extract the username from the `X-Authentik-Username` header (injected into the template).
  * Create a CSR using the public key with `CN=[Username]`.
* **The "Sign" Request**: `POST` the PEM-encoded CSR to the backend.
* **The Bundle**:
  * Receive the signed Public Certificate and the Root CA certificate from the backend.
  * Use `forge.js` to combine the **locally held private key**, the signed cert, and the root cert into a `.p12` file.
  * Prompt the user for a "Transport Password" to encrypt the `.p12`.
* **Download**: Trigger a browser download of `[username].p12`.
* **UX**: A clean, single-card interface with a progress stepper:
    1. Initializing & Key Generation
    2. Submitting to Signer
    3. Finalizing Bundle & Password Prompt

## 2. Backend Requirements (Python/FastAPI)

* **Endpoint `GET /`**:
  * Read `X-Authentik-Username`.
  * Serve the frontend HTML, injecting the username into the JS context.
* **Endpoint `POST /sign`**:
  * Accept a JSON payload containing a PEM-encoded CSR.
  * **Validation**: Use the `cryptography` library to parse the CSR and ensure the Subject CN matches the `X-Authentik-Username` header.
  * **Smallstep Interaction**: Use `asyncio.create_subprocess_exec` to run:
    ```
    step ca sign --provisioner [PROVISIONER_NAME] --provisioner-password-file [PASS_FILE] --not-after [TTL] [CSR_FILE] [OUTPUT_CERT_FILE]
    ```
  * Return a JSON response containing the signed certificate PEM and the Root CA PEM.

* Environment Variables:
  * `STEP_CA_URL`, `STEP_PROVISIONER`, `STEP_PROVISIONER_PASSWORD`, `ROOT_CA_PATH`, `CERT_DURATION` (e.g., `8760h`).

## 3. Dockerization

* **Base Image**: `python:3.11-slim`.
* **Installation**: The Dockerfile must install the `step` CLI binary.
* **Security**: The app must run as a non-root user but have read access to the `root_ca.crt` and the provisioner password file.

## 4. Example Logic Flow

1. User logs in via Authentik $\rightarrow$ Redirected to Portal.
1. JS generates Private Key $\rightarrow$ Browser Memory.
1. JS creates CSR $\rightarrow$ Sent to FastAPI.
1. FastAPI validates CN, then calls `step ca sign` $\rightarrow$ Returns Signed Cert + Root CA.
1. JS takes Private Key + Signed Cert + Root CA $\rightarrow$ Creates .p12 $\rightarrow$ Download.

## 5. Security Guardrails

* **Validation**: The backend strictly validates the CSR CN against the Authentik header to prevent spoofing.
* **No Private Keys**: The backend **never** requests, receives, or stores the private key.
* **Header Trust**: The application should be configured to only trust headers from the trusted proxy (Traefik).
* **TTL**: Certificates are issued with a restricted lifetime (configured via `CERT_DURATION`).
