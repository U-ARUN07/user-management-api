from datetime import datetime, timezone
from typing import Annotated, Dict, Any, Tuple
import uuid

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import RevokedToken, User
from app.security import decode_access_token

# Configure OAuth2 Bearer scheme pointing to the login endpoint for Swagger UI
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="/api/v1/auth/login",
    description="Enter the Bearer token obtained from /api/v1/auth/login",
)


def get_token_payload(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> Dict[str, Any]:
    """Validate and decode Bearer token, verifying it is not expired or revoked."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = decode_access_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Access token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise credentials_exception

    jti: str = payload.get("jti")
    sub: str = payload.get("sub")

    if not jti or not sub:
        raise credentials_exception

    # Check whether this token has been revoked / logged out
    stmt = select(RevokedToken).where(RevokedToken.jti == jti)
    revoked = db.scalars(stmt).first()
    if revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


def get_current_user(
    token_payload: Annotated[Dict[str, Any], Depends(get_token_payload)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Dependency that resolves the authenticated, active User model instance."""
    sub: str = token_payload.get("sub")
    try:
        user_id = uuid.UUID(sub)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid subject claim in token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive user account.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def get_current_user_with_token(
    user: Annotated[User, Depends(get_current_user)],
    token_payload: Annotated[Dict[str, Any], Depends(get_token_payload)],
) -> Tuple[User, Dict[str, Any]]:
    """Convenience dependency returning both the authenticated User and token payload."""
    return user, token_payload
