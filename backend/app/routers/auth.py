# backend/app/routers/auth.py
"""
Authentication Router

POST /api/v1/auth/login    → returns JWT token
POST /api/v1/auth/register → creates new user
POST /api/v1/auth/keys     → create an API key for the current user
GET  /api/v1/auth/keys     → list your API keys
DELETE /api/v1/auth/keys/{id} → revoke an API key

Registration is open ONLY for the first user (who becomes admin).
After that, only existing admins can register new users.
This removes the need for a separate CLI setup step.
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from datetime import datetime, UTC

from ..database import get_db
from ..models import User, ApiKey
from ..schemas import LoginRequest, Token, UserCreate, UserResponse, ApiKeyCreate, ApiKeyResponse
from ..core.security import (
    hash_password, verify_password, create_access_token, generate_api_key
)
from ..dependencies import get_current_user, require_role
from ..core.exceptions import AuthenticationError, ConflictError, AuthorizationError

router = APIRouter(prefix="/auth")


@router.post("/login", response_model=Token)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    """
    Authenticate with email and password, receive a JWT token.

    The token goes in the Authorization: Bearer {token} header for subsequent requests.
    """
    user = db.query(User).filter(User.email == data.email).first()

    if not user or not verify_password(data.password, user.hashed_password):
        # Same error message for both "user not found" and "wrong password"
        # — never reveal which one failed, that's user enumeration
        raise AuthenticationError("Invalid email or password")

    if not user.is_active:
        raise AuthenticationError("Account is deactivated")

    # Update last login timestamp
    user.last_login = datetime.now(UTC)
    db.commit()

    token = create_access_token(subject=user.email)
    return Token(access_token=token)


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(data: UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user.

    First registration: open to anyone, first user gets admin role.
    Subsequent registrations: require an authenticated admin.

    This avoids needing a CLI setup script while still being secure after the first user.
    """
    # Check if any users exist
    user_count = db.query(User).count()

    # If users already exist, require admin authentication
    # We do this by checking the Authorization header directly
    # (can't use Depends here without making it optional, so we check manually)
    if user_count > 0:
        # After first user, you must be an admin to create more users
        # This endpoint becomes admin-only. Clients should use the JWT flow.
        # For simplicity: we just raise — admins can use the direct DB script
        # or we can add an admin-authenticated version later.
        raise AuthorizationError(
            "Registration is closed. Contact your admin to create new accounts."
        )

    # Check for duplicate email
    existing = db.query(User).filter(User.email == data.email).first()
    if existing:
        raise ConflictError(f"Email '{data.email}' is already registered")

    # First user always gets admin role regardless of requested role
    role = "admin" if user_count == 0 else data.role

    user = User(
        email=data.email,
        hashed_password=hash_password(data.password),
        full_name=data.full_name,
        role=role
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return user


@router.post("/register/admin", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_by_admin(
    data: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin"))
):
    """
    Admin-only endpoint to add new users after the first one exists.
    """
    existing = db.query(User).filter(User.email == data.email).first()
    if existing:
        raise ConflictError(f"Email '{data.email}' is already registered")

    user = User(
        email=data.email,
        hashed_password=hash_password(data.password),
        full_name=data.full_name,
        role=data.role
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/keys", response_model=ApiKeyResponse, status_code=status.HTTP_201_CREATED)
def create_api_key(
    data: ApiKeyCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generate a new API key for the authenticated user.

    The raw key is returned ONCE in this response.
    We store only the prefix + bcrypt hash — the raw key is not recoverable.
    If the user loses it, they must generate a new one.
    """
    raw_key, prefix, key_hash = generate_api_key()

    api_key = ApiKey(
        user_id=current_user.id,
        key_prefix=prefix,
        key_hash=key_hash,
        name=data.name
    )
    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    # Return the raw key in the response — this is the ONLY time it's visible
    response = ApiKeyResponse(
        id=api_key.id,
        key_prefix=prefix,
        name=api_key.name,
        raw_key=raw_key,  # Only in creation response
        created_at=api_key.created_at
    )
    return response


@router.get("/keys", response_model=list[ApiKeyResponse])
def list_api_keys(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List your API keys. Raw key is NOT shown — only prefix and metadata."""
    keys = db.query(ApiKey).filter(
        ApiKey.user_id == current_user.id,
        ApiKey.is_active == True
    ).all()
    return keys


@router.delete("/keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_api_key(
    key_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Revoke (soft-delete) an API key."""
    api_key = db.query(ApiKey).filter(
        ApiKey.id == key_id,
        ApiKey.user_id == current_user.id  # can only revoke your own keys
    ).first()

    if not api_key:
        from ..core.exceptions import NotFoundError
        raise NotFoundError("API key")

    api_key.is_active = False
    db.commit()