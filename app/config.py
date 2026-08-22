from pathlib import Path
from typing import List, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
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
    ARGUS_ALLOWED_ORIGINS: str = "http://localhost:3000,http://localhost:8000,http://127.0.0.1:3000,http://127.0.0.1:8000"

    # Rate Limiting
    ARGUS_RATE_LIMIT_ENABLED: bool = True
    ARGUS_RATE_LIMIT_REQUESTS_PER_MINUTE: int = 60

    # Upstream LLM Configuration
    ARGUS_UPSTREAM_PROVIDER: str = "mock"  # mock | openai | gemini | anthropic | custom
    ARGUS_UPSTREAM_BASE_URL: str = "https://api.openai.com/v1"
    ARGUS_UPSTREAM_API_KEY: Optional[str] = None
    ARGUS_UPSTREAM_MODEL: str = "gpt-4o-mini"
    ARGUS_UPSTREAM_TIMEOUT_SECONDS: float = 30.0

    # Storage & Policy Paths (relative to PROJECT_ROOT)
    ARGUS_DB_PATH: str = "argus_gateway.db"
    ARGUS_POLICY_PATH: str = "policies/default_policy.yaml"

    @property
    def valid_api_keys(self) -> List[str]:
        return [k.strip() for k in self.ARGUS_API_KEYS.split(",") if k.strip()]

    @property
    def allowed_origins(self) -> List[str]:
        return [o.strip() for o in self.ARGUS_ALLOWED_ORIGINS.split(",") if o.strip()]

    @property
    def db_full_path(self) -> Path:
        path = Path(self.ARGUS_DB_PATH)
        return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()

    @property
    def policy_full_path(self) -> Path:
        path = Path(self.ARGUS_POLICY_PATH)
        return path if path.is_absolute() else (PROJECT_ROOT / path).resolve()


settings = Settings()
