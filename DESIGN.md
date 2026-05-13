# Technical Specification: Secure mTLS Vending Machine

## Overview

Build a self-service web portal that allows authenticated users to generate mTLS client certificates without the private key ever touching the server.

## Architecture

1. **Identity**: The app sits behind Traefik + Authentik (Forward Auth). It must trust `X-Authentik-Username` for the Certificate Common Name (CN).
1. **Frontend** (The "Secure" Zone): Uses **Web Crypto API** for key generation and **pkijs** for CSR creation and PKCS#12 bundling. This avoids node-forge encoding issues and leverages native performance.
1. **Backend** (The "Signer"): A FastAPI app that interfaces with a `step-ca` instance to sign CSRs.

## 1. Frontend Requirements (HTML/JavaScript)

* **Libraries**: `pkijs`, `asn1js`, `pvtsutils`.
* **Styling**: **Tailwind CSS** for a professional "Vending Machine" UI.
* **Key Generation**: Use browser-native `crypto.subtle.generateKey` (ECDSA P-256).
* **CSR Creation**:
  * Extract the username from the `X-Authentik-Username` header (injected into the template).
  * Create a PKCS#10 CSR using `pkijs` with `CN=[Username]`.
* **The "Sign" Request**: `POST` the PEM-encoded CSR to the backend.
* **The Bundle**:
  * Receive the signed Public Certificate from the backend.
  * Use `pkijs` to combine the **locally held private key** and the signed cert into a password-protected `.p12` file.
  * Encryption: Use AES-CBC and PBKDF2 (SHA-256) for the P12 bundle.
  * Download: Trigger a browser download of `[username].p12`.

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
