# backend/app/config.py
"""
OgunAI Lean Configuration

Philosophy: one environment variable controls each decision.
No Redis. No Celery. No vector store. No Docker.
Everything that works without a server uses SQLite, local files,
and Groq for the LLM.

12-Factor compliant: all config comes from environment, never from code.
"""

import os
import sys
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator
from typing import List


class Settings(BaseSettings):

    # ────────────────────────────────────────────────────────────────
    # APPLICATION IDENTITY
    # ────────────────────────────────────────────────────────────────
    APP_NAME: str = "OgunAI"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = Field(
        default="development",
        description="development | production. Controls docs visibility and error verbosity."
    )
    DEBUG: bool = Field(
        default=False,
        description="Enables SQL echo, detailed tracebacks. Never True in production."
    )

    # ────────────────────────────────────────────────────────────────
    # API SERVER
    # ────────────────────────────────────────────────────────────────
    API_HOST: str = "0.0.0.0"
    API_PORT: int = Field(default=8000, ge=1, le=65535)

    # CORS: list the actual frontend URL(s) here.
    # "*" is fine for local development but wrong for anything internet-facing.
    ALLOWED_ORIGINS_RAW: str = Field(
    default="http://localhost:5173,http://localhost:3000",
    alias="ALLOWED_ORIGINS",  # still reads ALLOWED_ORIGINS from .env
    description="Comma-separated list of allowed CORS origins"
    )

    @property
    def ALLOWED_ORIGINS(self) -> List[str]:
        """Parse the comma-separated string into a list at access time."""
        raw = self.ALLOWED_ORIGINS_RAW.strip()
        if not raw:
            return ["http://localhost:5173", "http://localhost:3000"]
        return [o.strip() for o in raw.split(",") if o.strip()]

    # ────────────────────────────────────────────────────────────────
    # DATABASE
    # SQLite for local use. One env var change moves you to PostgreSQL.
    # ────────────────────────────────────────────────────────────────
    DATABASE_URL: str = Field(
        default="sqlite:///./ogunai.db",
        description="SQLite for dev. Change to postgresql://user:pass@host/db for prod."
    )

    # ────────────────────────────────────────────────────────────────
    # AUTHENTICATION
    # ────────────────────────────────────────────────────────────────
    SECRET_KEY: str = Field(
        default="CHANGE_ME_IN_PRODUCTION_USE_OPENSSL_RAND_HEX_32",
        description="JWT signing secret. Generate with: openssl rand -hex 32"
    )
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=60, ge=5, le=1440)

    # ────────────────────────────────────────────────────────────────
    # LLM BACKEND
    # Default is Groq (free tier, no GPU needed, OpenAI-compatible API).
    # Set LLM_PROVIDER=ollama to use a local model.
    # ────────────────────────────────────────────────────────────────
    LLM_PROVIDER: str = Field(
        default="openai_compatible",
        description="openai_compatible | ollama | anthropic"
    )

    # Groq / vLLM / LM Studio / any OpenAI-compatible endpoint
    OPENAI_BASE_URL: str = Field(
        default="https://api.groq.com/openai/v1",
        description="Base URL for OpenAI-compatible API"
    )
    OPENAI_API_KEY: str = Field(
        default="",
        description="API key for Groq/OpenAI/vLLM. Leave empty for local Ollama."
    )
    OPENAI_MODEL: str = Field(
        default="llama-3.1-70b-versatile",
        description="Model name. Groq free tier: llama-3.1-70b-versatile"
    )

    # Ollama (local, GPU or CPU, no API key)
    OLLAMA_BASE_URL: str = Field(default="http://localhost:11434")
    OLLAMA_MODEL: str = Field(default="qwen2.5-coder:7b")  # 7b fits in 8GB RAM

    # Anthropic Claude
    ANTHROPIC_API_KEY: str = Field(default="")
    ANTHROPIC_MODEL: str = Field(default="claude-haiku-4-5-20251001")

    # LLM behaviour
    LLM_TEMPERATURE_PLAN: float = Field(default=0.4, ge=0.0, le=2.0)
    LLM_MAX_TOKENS: int = Field(default=4096, ge=256)

    # ────────────────────────────────────────────────────────────────
    # AGENT LOOP LIMITS
    # ────────────────────────────────────────────────────────────────
    MAX_ITERATIONS: int = Field(
        default=20,
        description="Max tool calls per audit session. Each call costs LLM tokens."
    )
    REQUEST_DELAY_SECONDS: float = Field(
        default=1.0,
        description="Minimum sleep between HTTP requests to the target. Be polite."
    )

    # ────────────────────────────────────────────────────────────────
    # OUTPUT
    # ────────────────────────────────────────────────────────────────
    REPORTS_DIR: str = Field(default="./reports")
    MEMORY_FILE: str = Field(default="./agent_memory.json")

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
        "extra": "ignore",
        "populate_by_name": True
    }


settings = Settings()


# ── Startup safety check ────────────────────────────────────────────────────
# This is exactly the kind of issue OgunAI would flag in someone else's app.
# A default SECRET_KEY in production means any attacker can forge JWT tokens.
if settings.ENVIRONMENT == "production":
    if settings.SECRET_KEY == "CHANGE_ME_IN_PRODUCTION_USE_OPENSSL_RAND_HEX_32":
        print(
            "\n[FATAL] SECRET_KEY is set to the default placeholder value.\n"
            "        In production this allows attackers to forge authentication tokens.\n"
            "        Generate a real key: openssl rand -hex 32\n"
            "        Then set it: SECRET_KEY=<your_key> in your .env or environment.\n"
        )
        sys.exit(1)