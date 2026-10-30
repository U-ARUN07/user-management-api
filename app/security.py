from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets
from typing import Any, Dict, Optional
import uuid

import jwt
from pwdlib import PasswordHash

from app.config import get_settings

settings = get_settings()

# Initialize Argon2 password hasher via pwdlib recommended configuration
password_hash = PasswordHash.recommended()


# ==============================================================
# Password Hashing & Verification
# ==============================================================

def hash_password(plain_password: str) -> str:
    """Hash a plaintext password using Argon2."""
    return password_hash.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a stored Argon2 hash."""
    return password_hash.verify(plain_password, hashed_password)


# ==============================================================
# JWT Access Token Operations
# ==============================================================

def create_access_token(
    user_id: str | uuid.UUID,
    expires_delta: Optional[timedelta] = None,
    custom_claims: Optional[Dict[str, Any]] = None,
) -> tuple[str, str, int]:
    """Create a signed JWT access token.

    Args:
        user_id: The UUID or string ID of the authenticated user.
        expires_delta: Optional custom lifetime duration.
        custom_claims: Optional dictionary with additional JWT claims.

    Returns:
        tuple of (encoded_jwt_string, jti, expires_in_seconds)
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
        expires_in = int(expires_delta.total_seconds())
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    jti = str(uuid.uuid4())
    payload = {
        "sub": str(user_id),
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }

    if custom_claims:
        payload.update(custom_claims)

    encoded_jwt = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    return encoded_jwt, jti, expires_in


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT access token.

    Args:
        token: The raw JWT string.

    Returns:
        Dict containing decoded payload claims.

    Raises:
        jwt.ExpiredSignatureError: If token has passed its expiration time.
        jwt.InvalidTokenError: If token signature or format is invalid.
    """
    return jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        options={"require": ["sub", "jti", "exp", "iat"]},
    )


# ==============================================================
# Password Reset Token Operations
# ==============================================================

def generate_reset_token() -> str:
    """Generate a cryptographically secure random token for password resets."""
    return secrets.token_urlsafe(32)


def hash_reset_token(raw_token: str) -> str:
    """Hash a raw reset token with SHA-256 for secure database storage.
    
    Storing token hashes ensures database compromises do not leak valid reset tokens.
    """
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def verify_reset_token_hash(raw_token: str, stored_hash: str) -> bool:
    """Securely compare candidate raw token with stored hash using constant time."""
    candidate_hash = hash_reset_token(raw_token)
    return hmac.compare_digest(candidate_hash, stored_hash)
