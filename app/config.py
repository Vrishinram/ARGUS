from pathlib import Path
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Server Configuration
    ARGUS_ENV: str = "development"
    ARGUS_HOST: str = "0.0.0.0"
    ARGUS_PORT: int = 8000
    ARGUS_DEBUG: bool = True

    # Security & Auth
    ARGUS_API_KEYS: str = "sk-argus-test-client-key-1,sk-argus-admin-master-key"
    ARGUS_ADMIN_API_KEY: str = "sk-argus-admin-master-key"

    # Rate Limiting
    ARGUS_RATE_LIMIT_ENABLED: bool = True
    ARGUS_RATE_LIMIT_REQUESTS_PER_MINUTE: int = 60

    # Upstream LLM Configuration
    ARGUS_UPSTREAM_PROVIDER: str = "mock"  # mock | openai | gemini | anthropic | custom
    ARGUS_UPSTREAM_BASE_URL: str = "https://api.openai.com/v1"
    ARGUS_UPSTREAM_API_KEY: Optional[str] = None
    ARGUS_UPSTREAM_MODEL: str = "gpt-4o-mini"
    ARGUS_UPSTREAM_TIMEOUT_SECONDS: float = 30.0

    # Storage & Policy Paths
    ARGUS_DB_PATH: str = "argus_gateway.db"
    ARGUS_POLICY_PATH: str = "policies/default_policy.yaml"

    @property
    def valid_api_keys(self) -> List[str]:
        return [k.strip() for k in self.ARGUS_API_KEYS.split(",") if k.strip()]

    @property
    def db_full_path(self) -> Path:
        return Path(self.ARGUS_DB_PATH).resolve()

    @property
    def policy_full_path(self) -> Path:
        return Path(self.ARGUS_POLICY_PATH).resolve()


settings = Settings()
