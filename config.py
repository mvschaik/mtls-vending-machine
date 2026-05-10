from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path
from typing import Optional

class Settings(BaseSettings):
    STEP_CA_URL: str = "https://ca.internal"
    STEP_PROVISIONER: str = "vending-machine"
    STEP_PROVISIONER_PASSWORD_FILE: Optional[str] = None
    ROOT_CA_PATH: str = "/etc/step-ca/certs/root_ca.crt"
    CERT_DURATION: str = "8760h"
    
    # Trusted proxy headers
    AUTHENTIK_USERNAME_HEADER: str = "X-Authentik-Username"
    TRUSTED_PROXIES: list[str] = ["127.0.0.1"]  # Default to localhost
    
    # Mocking for tests
    MOCK_STEP_CLI: bool = False

    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()
