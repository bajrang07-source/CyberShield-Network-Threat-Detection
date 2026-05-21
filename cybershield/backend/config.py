import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "cybershield-secret-key-change-in-prod")
    JWT_SECRET: str = os.getenv("JWT_SECRET", "cybershield-jwt-secret-change-in-prod")

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///cybershield.db")

    # Redis
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")

    # Blocking
    BLOCK_DURATION_SECONDS: int = int(os.getenv("BLOCK_DURATION_SECONDS", "86400"))

    # Detection thresholds
    CRITICAL_THRESHOLD: int = int(os.getenv("CRITICAL_THRESHOLD", "80"))
    HIGH_THRESHOLD: int = int(os.getenv("HIGH_THRESHOLD", "60"))
    MEDIUM_THRESHOLD: int = int(os.getenv("MEDIUM_THRESHOLD", "40"))

    # ML & Rate limiting
    ML_WEIGHT: float = float(os.getenv("ML_WEIGHT", "0.6"))
    BRUTE_FORCE_RATE_LIMIT: int = int(os.getenv("BRUTE_FORCE_RATE_LIMIT", "10"))

    # Admin credentials
    ADMIN_USER: str = os.getenv("ADMIN_USER", "admin")
    ADMIN_PASS: str = os.getenv("ADMIN_PASS", "cybershield123")

    # Webhook
    WEBHOOK_URL: str = os.getenv("WEBHOOK_URL", "")

    # Phase 4 — IR Agent
    # Set AUTO_CONTAINMENT_ENABLED=true in .env to allow the IR agent to
    # automatically flag IPs for containment on CRITICAL incidents.
    AUTO_CONTAINMENT_ENABLED: bool = (
        os.getenv("AUTO_CONTAINMENT_ENABLED", "false").lower() == "true"
    )

    # JWT config for Flask-JWT-Extended
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET", "cybershield-jwt-secret-change-in-prod")
    JWT_ACCESS_TOKEN_EXPIRES: int = int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", "3600"))

    SQLALCHEMY_DATABASE_URI: str = os.getenv("DATABASE_URL", "sqlite:///cybershield.db")
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False


config = Config()
