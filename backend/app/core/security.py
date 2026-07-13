# backend/app/core/security.py
"""
Security Utilities — JWT and API Key Management

Uses bcrypt directly (no passlib wrapper).
passlib 1.7.4 is incompatible with bcrypt >= 4.x and is abandoned.
Direct bcrypt is simpler and has no compatibility issues.
"""

import secrets
import string
import bcrypt
from datetime import datetime, UTC, timedelta
from typing import Optional

from jose import JWTError, jwt

from ..config import settings


# ── Passwords ─────────────────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    """Hash a plain-text password using bcrypt."""
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plain-text password against a bcrypt hash."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


# ── JWT Tokens ────────────────────────────────────────────────────────────────

def create_access_token(subject: str, expires_minutes: Optional[int] = None) -> str:
    expire = datetime.now(UTC) + timedelta(
        minutes=expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "sub": subject,
        "exp": expire,
        "iat": datetime.now(UTC)
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")


def decode_access_token(token: str) -> str:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        subject: Optional[str] = payload.get("sub")
        if subject is None:
            raise ValueError("Token missing 'sub' claim")
        return subject
    except JWTError as e:
        raise ValueError(f"Invalid token: {e}")


# ── API Keys ──────────────────────────────────────────────────────────────────

def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new API key. Returns (raw_key, prefix, hashed_key).
    Format: ogunai_{8_char_prefix}_{40_char_random}
    """
    alphabet = string.ascii_lowercase + string.digits
    random_part = "".join(secrets.choice(alphabet) for _ in range(40))
    prefix = random_part[:8]
    raw_key = f"ogunai_{prefix}_{random_part}"
    hashed = bcrypt.hashpw(raw_key.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    return raw_key, prefix, hashed


def extract_key_prefix(raw_key: str) -> Optional[str]:
    parts = raw_key.split("_", 2)
    if len(parts) != 3 or parts[0] != "ogunai":
        return None
    return parts[1]


def verify_api_key(raw_key: str, stored_hash: str) -> bool:
    return bcrypt.checkpw(raw_key.encode("utf-8"), stored_hash.encode("utf-8"))