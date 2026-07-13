# backend/app/dependencies.py
"""
FastAPI Dependencies — Auth, DB, RBAC

Three types of auth:
1. JWT Bearer token  → for dashboard users (humans)
2. API key header    → for programmatic access (scripts, CI/CD)
3. Role check        → layered on top of either, controls what you can do

The O(n) bcrypt fix:
v3 looped through all keys calling bcrypt.verify() on each.
This version extracts the prefix from the key, looks it up in the DB
(1 indexed query), then does exactly 1 bcrypt verify.
Fast regardless of how many keys exist.
"""

from fastapi import Depends, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from typing import Optional
from datetime import datetime, UTC

from .database import get_db
from .models import User, ApiKey
from .core.security import decode_access_token, extract_key_prefix, verify_api_key
from .core.exceptions import AuthenticationError, AuthorizationError

# Reuse get_db — it's the same function as in database.py
# The import here just makes it importable from dependencies too
get_db = get_db

security = HTTPBearer(auto_error=False)


# ── JWT Authentication ─────────────────────────────────────────────────────────

async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Validate JWT Bearer token and return the authenticated user.

    Raises AuthenticationError if:
    - No token provided
    - Token is expired or invalid
    - User doesn't exist or is deactivated
    """
    if not credentials:
        raise AuthenticationError("No authentication token provided")

    try:
        email = decode_access_token(credentials.credentials)
    except ValueError as e:
        raise AuthenticationError(str(e))

    user = db.query(User).filter(User.email == email, User.is_active == True).first()
    if not user:
        raise AuthenticationError("User not found or account deactivated")

    return user


# ── API Key Authentication ─────────────────────────────────────────────────────

async def get_api_key_user(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    Authenticate via X-API-Key header.

    Fast lookup (O(1)):
    1. Extract 8-char prefix from the provided key
    2. Query DB WHERE key_prefix = prefix (indexed column)
    3. Verify with bcrypt (exactly 1 bcrypt call, not N)
    4. Return associated user

    Returns None if no API key provided (endpoint may allow this).
    Raises AuthenticationError if key provided but invalid.
    """
    if not x_api_key:
        return None

    # Extract prefix for fast DB lookup
    prefix = extract_key_prefix(x_api_key)
    if not prefix:
        raise AuthenticationError("Invalid API key format")

    # One indexed query instead of scanning all keys
    api_key = db.query(ApiKey).filter(
        ApiKey.key_prefix == prefix,
        ApiKey.is_active == True
    ).first()

    if not api_key:
        raise AuthenticationError("API key not found")

    # One bcrypt verify instead of N
    if not verify_api_key(x_api_key, api_key.key_hash):
        raise AuthenticationError("API key verification failed")

    # Update last used timestamp
    api_key.last_used_at = datetime.now(UTC)
    db.commit()

    user = db.query(User).filter(User.id == api_key.user_id, User.is_active == True).first()
    if not user:
        raise AuthenticationError("API key owner not found")

    return user


# ── Role-Based Access Control ──────────────────────────────────────────────────

ROLE_LEVELS = {"viewer": 0, "analyst": 1, "admin": 2}


def require_role(minimum_role: str):
    """
    Dependency factory for role-based access control.

    Usage:
        @router.delete("/clients/{id}")
        def delete_client(current_user=Depends(require_role("admin"))):
            ...

    Roles in ascending order: viewer < analyst < admin
    """
    async def check_role(current_user: User = Depends(get_current_user)) -> User:
        user_level = ROLE_LEVELS.get(current_user.role, -1)
        required_level = ROLE_LEVELS.get(minimum_role, 999)
        if user_level < required_level:
            raise AuthorizationError(
                f"Role '{current_user.role}' is insufficient. "
                f"Required: '{minimum_role}'"
            )
        return current_user

    return check_role