import asyncio
import os
import tempfile
import ipaddress
from typing import Dict

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from config import settings

app = FastAPI(title="mTLS Vending Machine")
templates = Jinja2Templates(directory="templates")

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

    if not x_authentik_username:
        x_authentik_username = "Guest"
    
    # Try to serve built frontend if it exists
    static_index = os.path.join("static", "index.html")
    if os.path.exists(static_index):
        with open(static_index, "r") as f:
            content = f.read()
            # Still use Jinja2 to inject username if the placeholder is there
            # Vite's index.html might have the placeholder if we kept it
            return HTMLResponse(content=content.replace('{{ username | tojson | safe if username is defined else \'"Guest"\' }}', f'"{x_authentik_username}"'))

    return templates.TemplateResponse(request, "index.html", {"username": x_authentik_username})

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
            "cert": "-----BEGIN CERTIFICATE-----\nMOCKED_CERT\n-----END CERTIFICATE-----",
            "root_ca": "-----BEGIN CERTIFICATE-----\nMOCKED_ROOT_CA\n-----END CERTIFICATE-----"
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
