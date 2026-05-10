import pytest
from httpx import AsyncClient, ASGITransport
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from main import app
from config import settings

@pytest.fixture(scope="module")
def anyio_backend():
    return "asyncio"

def generate_csr(common_name: str):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])).sign(key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM).decode()

@pytest.mark.anyio
async def test_read_root():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/", headers={settings.AUTHENTIK_USERNAME_HEADER: "testuser"})
    assert response.status_code == 200
    assert "testuser" in response.text

@pytest.mark.anyio
async def test_sign_valid_csr():
    settings.MOCK_STEP_CLI = True
    username = "testuser"
    csr_pem = generate_csr(username)
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post(
            "/sign",
            json={"csr": csr_pem},
            headers={settings.AUTHENTIK_USERNAME_HEADER: username}
        )
    
    assert response.status_code == 200
    data = response.json()
    assert "cert" in data
    assert "root_ca" in data
    assert "MOCKED_CERT" in data["cert"]

@pytest.mark.anyio
async def test_sign_invalid_cn():
    settings.MOCK_STEP_CLI = True
    username = "testuser"
    csr_pem = generate_csr("wronguser")
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post(
            "/sign",
            json={"csr": csr_pem},
            headers={settings.AUTHENTIK_USERNAME_HEADER: username}
        )
    
    assert response.status_code == 403
    assert "does not match" in response.json()["detail"]

@pytest.mark.anyio
async def test_sign_missing_header():
    csr_pem = generate_csr("testuser")
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post(
            "/sign",
            json={"csr": csr_pem}
        )
    
    assert response.status_code == 401
    assert "Missing authentication header" in response.json()["detail"]

@pytest.mark.anyio
async def test_sign_invalid_csr_format():
    username = "testuser"
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.post(
            "/sign",
            json={"csr": "not a pem"},
            headers={settings.AUTHENTIK_USERNAME_HEADER: username}
        )
    
    assert response.status_code == 400
    assert "Invalid CSR" in response.json()["detail"]
