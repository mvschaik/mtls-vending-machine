import asyncio
import os
import tempfile
from typing import Dict

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from config import settings

app = FastAPI(title="mTLS Vending Machine")
templates = Jinja2Templates(directory="templates")

class SignRequest(BaseModel):
    csr: str

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, x_authentik_username: str = Header(None, alias=settings.AUTHENTIK_USERNAME_HEADER)):
    if not x_authentik_username:
        # In a real scenario, Authentik should always provide this.
        # For development/testing, we might want a fallback or error.
        x_authentik_username = "Guest"
    
    return templates.TemplateResponse(request, "index.html", {"username": x_authentik_username})

@app.post("/sign")
async def sign_csr(
    request: SignRequest,
    x_authentik_username: str = Header(None, alias=settings.AUTHENTIK_USERNAME_HEADER)
):
    if not x_authentik_username:
        raise HTTPException(status_code=401, detail="Missing authentication header")

    try:
        csr = x509.load_pem_x509_csr(request.csr.encode())
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

    if settings.MOCK_STEP_CLI:
        return {
            "cert": "-----BEGIN CERTIFICATE-----\nMOCKED_CERT\n-----END CERTIFICATE-----",
            "root_ca": "-----BEGIN CERTIFICATE-----\nMOCKED_ROOT_CA\n-----END CERTIFICATE-----"
        }

    return await call_step_ca_sign(request.csr)

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
        
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
