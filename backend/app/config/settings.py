import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


_backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_env_path = os.path.join(_backend_dir, ".env")

class Settings(BaseSettings):
    # Application Info
    APP_NAME: str = "PhishGuard AI Backend"
    APP_VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api/v1"
    DEBUG: bool = False

    # MongoDB Atlas Connection
    MONGODB_URI: str = os.getenv("MONGODB_URI", "")
    DATABASE_NAME: str = os.getenv("DATABASE_NAME", "phishguard")

    # JWT Authentication
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "phishguard_default_dev_secret_change_in_production_min32chars")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))

    # Cookie Configuration
    COOKIE_NAME: str = "phishguard_access_token"
    COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "false").lower() == "true"
    COOKIE_SAMESITE: str = os.getenv("COOKIE_SAMESITE", "lax")
    COOKIE_DOMAIN: Optional[str] = os.getenv("COOKIE_DOMAIN", None)

    # CORS Frontend Domain
    FRONTEND_URL: str = os.getenv("FRONTEND_URL", "http://localhost:3000")

    # Threat Intelligence API Keys (Optional)
    PHISHTANK_API_KEY: Optional[str] = os.getenv("PHISHTANK_API_KEY", None)
    OPENPHISH_API_KEY: Optional[str] = os.getenv("OPENPHISH_API_KEY", None)

    # Machine Learning Model Path
    MODEL_PATH: str = os.getenv("MODEL_PATH", "../model/artifacts/phishing_model.pkl")

    # Rate Limiting Settings
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_AUTH: str = "10/minute"
    RATE_LIMIT_SCAN: str = "30/minute"

    model_config = SettingsConfigDict(
        env_file=(_env_path, ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()

