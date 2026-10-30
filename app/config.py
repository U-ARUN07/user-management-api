from functools import lru_cache
from typing import Literal
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )

    APP_NAME: str = "User Management API"
    APP_VERSION: str = "1.0.0"
    APP_ENV: Literal["development", "testing", "production"] = "development"
    DEBUG: bool = True

    # PostgreSQL Database URL (psycopg3 driver)
    DATABASE_URL: str = Field(
        ...,
        description="PostgreSQL connection string using psycopg driver, e.g. postgresql+psycopg://user:password@localhost:5432/dbname",
    )

    # JWT Authentication configuration
    JWT_SECRET_KEY: str = Field(
        ...,
        description="Cryptographically secure secret key for signing JWT tokens",
    )
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Password Reset token configuration
    PASSWORD_RESET_EXPIRE_MINUTES: int = 15

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def validate_jwt_secret_key(cls, v: str) -> str:
        if not v or len(v.strip()) < 32:
            raise ValueError(
                "JWT_SECRET_KEY must be a strong secret of at least 32 characters."
            )
        return v.strip()

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        stripped = v.strip()
        if not (
            stripped.startswith("postgresql://")
            or stripped.startswith("postgresql+psycopg://")
            or stripped.startswith("postgresql+psycopg2://")
            or stripped.startswith("sqlite")
        ):
            raise ValueError(
                "DATABASE_URL must be a valid PostgreSQL connection URL, "
                "e.g., postgresql+psycopg://username:password@localhost:5432/user_management_db"
            )
        return stripped


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings instance."""
    return Settings()
