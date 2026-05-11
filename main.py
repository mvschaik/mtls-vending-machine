import asyncio
import os
import tempfile
import ipaddress
from typing import Dict

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from config import settings

app = FastAPI(title="mTLS Vending Machine")

# Mount static files if the directory exists
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

class SignRequest(BaseModel):
    csr: str

def verify_proxy(request: Request):
    client_host = request.client.host
    # If TRUSTED_PROXIES contains "*", we trust everyone (not recommended for prod)
    if "*" in settings.TRUSTED_PROXIES:
        return True
    
    for trusted in settings.TRUSTED_PROXIES:
        try:
            if ipaddress.ip_address(client_host) in ipaddress.ip_network(trusted):
                return True
        except ValueError:
            continue
    return False

@app.get("/api/me")
async def get_me(request: Request, x_authentik_username: str = Header(None, alias=settings.AUTHENTIK_USERNAME_HEADER)):
    if not verify_proxy(request) and not settings.MOCK_STEP_CLI:
        raise HTTPException(status_code=403, detail="Untrusted proxy source")
    
    return {"username": x_authentik_username or "Guest"}

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, x_authentik_username: str = Header(None, alias=settings.AUTHENTIK_USERNAME_HEADER)):
    # Verify proxy if not in mock/dev mode
    if not verify_proxy(request) and not settings.MOCK_STEP_CLI:
        raise HTTPException(status_code=403, detail="Untrusted proxy source")

    static_index = os.path.join("static", "index.html")
    if os.path.exists(static_index):
        return FileResponse(static_index)
    
    # Fallback for development if static/ is not built yet
    dev_index = os.path.join("frontend", "index.html")
    if os.path.exists(dev_index):
        return FileResponse(dev_index)

    raise HTTPException(status_code=404, detail="Frontend not built. Run 'npm run build' in the frontend directory.")

@app.post("/sign")
async def sign_csr(
    request: Request,
    sign_data: SignRequest,
    x_authentik_username: str = Header(None, alias=settings.AUTHENTIK_USERNAME_HEADER)
):
    # Verify proxy
    if not verify_proxy(request) and not settings.MOCK_STEP_CLI:
        raise HTTPException(status_code=403, detail="Untrusted proxy source")

    if not x_authentik_username:
        raise HTTPException(status_code=401, detail="Missing authentication header")

    try:
        csr = x509.load_pem_x509_csr(sign_data.csr.encode())
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid CSR: {str(e)}")

    # Validate CN
    common_name = csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not common_name:
        raise HTTPException(status_code=400, detail="CSR missing Common Name")
    
    if common_name[0].value != x_authentik_username:
        raise HTTPException(
            status_code=403, 
            detail=f"CSR CN '{common_name[0].value}' does not match username '{x_authentik_username}'"
        )

    # Validate SANs (Subject Alternative Names)
    # We strictly forbid SANs or require them to match the username
    try:
        ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in ext.value:
            # If any SAN is present, it must match the username (as a DNS name or other)
            # Simplest policy: Forbid SANs in this vending machine to prevent spoofing
            raise HTTPException(status_code=403, detail="SANs are not allowed in CSR")
    except x509.ExtensionNotFound:
        pass # Good, no SANs

    if settings.MOCK_STEP_CLI:
        return {
            "cert": "-----BEGIN CERTIFICATE-----\nMIIC5jCCAo2gAwIBAgIQW6jt5asWS0JDgwJqf+VUdDAKBggqhkjOPQQDAjA0MRAw\nDgYDVQQKEwdTbWVoLUNBMSAwHgYDVQQDExdTbWVoLUNBIEludGVybWVkaWF0ZSBD\nQTAeFw0yNjA1MTExNDEyMTlaFw0yNjA1MTExNTEzMTlaMBAxDjAMBgNVBAMTBWVt\ncHR5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA890okuokIeWFLcrv\n5hKVZBx7cFt/HmhJQRNVnzI4VwIQfac7nwbz6IKH9LjTrAFCL/Wz3qZHxrUeIMnM\n8LhPvEtMVoZw5uobbRe5cg6M+p9yiEnRGqECjN+w0hEn4dYV40qEkV3NiGLZ4jib\nLgc56kwH8LL+FpIKTcb75P1HOp4+hHQJ712qFQhzDqS74ORyyATLKEn8vtpWlybV\n4UZxjR3h6h2nfQJ6sVQ4de8fVEdC09bH71aanuCzD90FUtuGS7BePRQPvb3Mc1Ey\n0oofqloB+xPOYfkpFtoU6d9GILWkSkvp+G8r+x4QY6apwDM5XhXGg0iDncSCbfx9\nSK1B4wIDAQABo4HZMIHWMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEF\nBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFL1kX0FVoiDBUQH/RaN1+vyV3ilGMB8G\nA1UdIwQYMBaAFP4QrYTa9kj41bPNzEgmHc1evzUgMBAGA1UdEQQJMAeCBWVtcHR5\nMFMGDCsGAQQBgqRkxihAAQRDMEECAQEED3ZlbmRpbmctbWFjaGluZQQrQW5BN0Fx\nd2haWUxKLXdyRnIwZUItb3J5aWN4YlE0Y1NNQ3FhOG5Vc0o1RTAKBggqhkjOPQQD\nAgNHADBEAiBWms2czETq5LITHbrDhamuhVPYgdVwXW6JnY8duDDBDQIgQ8wXbayb\nB02B/hCxUZ9FqPtrlF80/XmVlSPi1HnMGEs=\n-----END CERTIFICATE-----",
            "root_ca": "-----BEGIN CERTIFICATE-----\nMIIBwzCCAWqgAwIBAgIQEukyXu5Sy7883+B2w5gBnzAKBggqhkjOPQQDAjAsMRAw\nDgYDVQQKEwdTbWVoLUNBMRgwFgYDVQQDEw9TbWVoLUNBIFJvb3QgQ0EwHhcNMjYw\nNTEwMDgwODU1WhcNMzYwNTA3MDgwODU1WjA0MRAwDgYDVQQKEwdTbWVoLUNBMSAw\nHgYDVQQDExdTbWVoLUNBIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqG\nSM49AwEHA0IABLz+5gcw8B87A5rrokqBKCJElZ34uPJKZcHQKMoRERpA7RTTbvfN\nf8oUvSmbZt+XPEzqqQvuFiOAp4e8B6G1RsajZjBkMA4GA1UdDwEB/wQEAwIBBjAS\nBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBT+EK2E2vZI+NWzzcxIJh3NXr81\nIDAfBgNVHSMEGDAWgBR0PNTRbxJ9hKeNjjKYIZxcWPjD/DAKBggqhkjOPQQDAgNH\nADBEAiBBUbCh+29QNsz+G/SKMkV22bD5MXEitcEqe2Dh4DTi+AIgZ6TMz6Lge3Xp\nUy0+h+OZx57W9giY4f6WuFrm841jU2w=\n-----END CERTIFICATE-----",
        }

    return await call_step_ca_sign(sign_data.csr)

async def call_step_ca_sign(csr_pem: str) -> Dict[str, str]:
    with tempfile.TemporaryDirectory() as tmpdir:
        csr_path = os.path.join(tmpdir, "request.csr")
        cert_path = os.path.join(tmpdir, "signed.crt")
        
        with open(csr_path, "w") as f:
            f.write(csr_pem)
        
        cmd = [
            "step", "ca", "sign",
            "--provisioner", settings.STEP_PROVISIONER,
            "--not-after", settings.CERT_DURATION,
            "--ca-url", settings.STEP_CA_URL,
            "--root", settings.ROOT_CA_PATH,
        ]
        
        if settings.STEP_PROVISIONER_PASSWORD_FILE:
            cmd.extend(["--provisioner-password-file", settings.STEP_PROVISIONER_PASSWORD_FILE])
        
        cmd.extend([csr_path, cert_path])
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Add timeout to prevent hanging
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=10.0)
            
            if process.returncode != 0:
                raise HTTPException(status_code=500, detail=f"Step CA sign failed: {stderr.decode()}")
            
            with open(cert_path, "r") as f:
                signed_cert = f.read()
                
            with open(settings.ROOT_CA_PATH, "r") as f:
                root_ca = f.read()
                
            return {
                "cert": signed_cert,
                "root_ca": root_ca
            }
        except asyncio.TimeoutError:
            process.kill()
            raise HTTPException(status_code=504, detail="Step CA signing timed out")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
