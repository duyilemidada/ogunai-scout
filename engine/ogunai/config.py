

# engine/ogunai/config.py
"""
Engine Configuration

The engine reads from the same environment variables as the backend.
This file is the engine's own config, separate from the backend's Pydantic settings.
It's a simple dict so the engine can run standalone (in a script or Kaggle notebook)
without needing the full FastAPI stack.
"""

import os
from typing import Any, Dict


ENGINE_CONFIG: Dict[str, Any] = {
    # LLM provider — same as backend
    "llm_provider": os.getenv("LLM_PROVIDER", "openai_compatible"),

    # Groq / vLLM / any OpenAI-compatible endpoint
    "openai_base_url": os.getenv("OPENAI_BASE_URL", "https://api.groq.com/openai/v1"),
    "openai_api_key": os.getenv("OPENAI_API_KEY", ""),
    "openai_model": os.getenv("OPENAI_MODEL", "llama-3.1-70b-versatile"),

    # Local Ollama (no API key, no internet)
    "ollama_base_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
    "ollama_model": os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b"),

    # Anthropic Claude
    "anthropic_api_key": os.getenv("ANTHROPIC_API_KEY", ""),
    "anthropic_model": os.getenv("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001"),

    # LLM behaviour
    "temperature_plan": float(os.getenv("LLM_TEMPERATURE_PLAN", "0.4")),
    "max_tokens": int(os.getenv("LLM_MAX_TOKENS", "4096")),

    # Agent loop limits
    "max_iterations": int(os.getenv("MAX_ITERATIONS", "20")),
    "request_delay_seconds": float(os.getenv("REQUEST_DELAY_SECONDS", "1.0")),

    # Output paths
    "memory_file": os.getenv("MEMORY_FILE", "./agent_memory.json"),
    "reports_dir": os.getenv("REPORTS_DIR", "./reports"),

    # ── Offensive Mode Configuration ─────────────────────────────────
    "audit_mode": os.getenv("AUDIT_MODE", "passive"),  # passive | offensive | both

    # WAF evasion
    "max_waf_triggers": int(os.getenv("MAX_WAF_TRIGGERS", "3")),
    "stealth_delay_multiplier": float(os.getenv("STEALTH_DELAY_MULTIPLIER", "2.0")),

    # JWT testing
    "jwt_common_secrets": os.getenv("JWT_COMMON_SECRETS", "secret,password,123456,jwt,token,auth,admin,test,changeme"),
    "jwt_test_endpoint": os.getenv("JWT_TEST_ENDPOINT", "/api/v1/user"),

    # Race condition testing
    "race_concurrency": int(os.getenv("RACE_CONCURRENCY", "10")),
    "race_endpoints": os.getenv("RACE_ENDPOINTS", "/api/v1/transfer,/api/v1/payment,/api/v1/redeem"),

    # Business logic fuzzing
    "bl_fuzz_fields": os.getenv("BL_FUZZ_FIELDS", "amount,quantity,price,balance,limit"),
}


def get_config(key: str, default: Any = None) -> Any:
    return ENGINE_CONFIG.get(key, default)


def get_llm_config() -> Dict[str, Any]:
    """Return only the LLM-relevant keys for the adapter factory."""
    provider = ENGINE_CONFIG["llm_provider"]

    if provider == "openai_compatible":
        return {
            "base_url": ENGINE_CONFIG["openai_base_url"],
            "api_key": ENGINE_CONFIG["openai_api_key"],
            "model": ENGINE_CONFIG["openai_model"],
        }
    elif provider == "ollama":
        return {
            "base_url": ENGINE_CONFIG["ollama_base_url"],
            "model": ENGINE_CONFIG["ollama_model"],
        }
    elif provider == "anthropic":
        return {
            "api_key": ENGINE_CONFIG["anthropic_api_key"],
            "model": ENGINE_CONFIG["anthropic_model"],
        }
    else:
        raise ValueError(f"Unknown LLM provider: {provider}")