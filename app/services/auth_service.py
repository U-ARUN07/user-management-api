from datetime import datetime, timedelta, timezone
import logging
from typing import Optional, Tuple, Dict, Any

from fastapi import HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import PasswordResetToken, RevokedToken, User
from app.schemas import UserRegister
from app.security import (
    create_access_token,
    generate_reset_token,
    hash_password,
    hash_reset_token,
    verify_password,
)

logger = logging.getLogger(__name__)
settings = get_settings()


class AuthService:
    """Service handling all authentication and password management operations."""

    @staticmethod
    def register_user(db: Session, user_in: UserRegister) -> User:
        """Register a new user account with hashed password."""
        # Check for existing email address
        stmt = select(User).where(User.email == user_in.email)
        existing_user = db.scalars(stmt).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A user with this email address already exists.",
            )

        hashed = hash_password(user_in.password)
        new_user = User(
            full_name=user_in.full_name,
            email=user_in.email,
            hashed_password=hashed,
            is_active=True,
            is_verified=False,
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        logger.info("New user registered successfully: %s", new_user.email)
        return new_user

    @staticmethod
    def authenticate_user(
        db: Session, email: str, password: str
    ) -> Tuple[str, str, int]:
        """Verify user credentials and generate a signed JWT access token."""
        stmt = select(User).where(User.email == email.strip().lower())
        user = db.scalars(stmt).first()

        # Constant-time security: always verify hash even if user not found to thwart timing attacks
        dummy_hash = "$argon2id$v=19$m=65536,t=3,p=4$dummyhashdummyhash$dummyhashdummyhashdummyhash"
        if not user or not verify_password(password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is inactive. Please contact support.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token, jti, expires_in = create_access_token(user.id)
        logger.info("User authenticated: %s (jti: %s)", user.email, jti)
        return token, jti, expires_in

    @staticmethod
    def logout_user(
        db: Session, user: User, token_payload: Dict[str, Any]
    ) -> None:
        """Revoke current access token until expiration by persisting its jti."""
        jti = token_payload.get("jti")
        exp = token_payload.get("exp")
        if not jti or not exp:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token structure for revocation.",
            )

        # Check if already revoked
        stmt = select(RevokedToken).where(RevokedToken.jti == jti)
        already_revoked = db.scalars(stmt).first()
        if already_revoked:
            return

        exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
        revoked_record = RevokedToken(
            jti=jti,
            user_id=user.id,
            expires_at=exp_dt,
        )
        db.add(revoked_record)
        db.commit()
        logger.info("Token jti %s revoked for user %s", jti, user.id)

    @staticmethod
    def request_password_reset(
        db: Session, email: str
    ) -> Tuple[str, Optional[str]]:
        """Generate a password-reset token if the user exists.

        Returns generic success message to prevent user enumeration.
        """
        generic_msg = "If the account exists, password-reset instructions will be provided."
        stmt = select(User).where(User.email == email.strip().lower())
        user = db.scalars(stmt).first()

        if not user or not user.is_active:
            return generic_msg, None

        # Invalidate any older unused reset tokens for this user
        now = datetime.now(timezone.utc)
        db.execute(
            update(PasswordResetToken)
            .where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.used_at.is_(None),
            )
            .values(used_at=now)
        )

        raw_token = generate_reset_token()
        token_hash = hash_reset_token(raw_token)
        expires_at = now + timedelta(minutes=settings.PASSWORD_RESET_EXPIRE_MINUTES)

        reset_record = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
        )
        db.add(reset_record)
        db.commit()

        # In development mode, provide token for testing convenience
        dev_token = raw_token if settings.APP_ENV == "development" else None
        logger.info("Password reset token generated for user %s", user.id)
        return generic_msg, dev_token

    @staticmethod
    def reset_password(db: Session, token: str, new_password: str) -> None:
        """Reset a user password using a verified, unused, unexpired reset token."""
        token_hash = hash_reset_token(token)
        stmt = select(PasswordResetToken).where(
            PasswordResetToken.token_hash == token_hash
        )
        reset_record = db.scalars(stmt).first()

        now = datetime.now(timezone.utc)
        if not reset_record or reset_record.used_at is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid, expired, or already used reset token.",
            )

        # Check expiration
        expires_at = reset_record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Reset token has expired.",
            )

        user = db.get(User, reset_record.user_id)
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User associated with token is not active or not found.",
            )

        # Update password
        user.hashed_password = hash_password(new_password)
        reset_record.used_at = now

        # Invalidate all other active reset tokens for this user
        db.execute(
            update(PasswordResetToken)
            .where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.used_at.is_(None),
            )
            .values(used_at=now)
        )
        db.commit()
        logger.info("Password successfully reset for user %s", user.id)

    @staticmethod
    def change_password(
        db: Session,
        user: User,
        current_password: str,
        new_password: str,
        token_payload: Dict[str, Any],
    ) -> None:
        """Change user password after verifying current password, and revoke current token."""
        if not verify_password(current_password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect current password.",
            )

        if current_password == new_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password must be different from the current password.",
            )

        user.hashed_password = hash_password(new_password)

        # Revoke the current access token so client is prompted to log in anew
        jti = token_payload.get("jti")
        exp = token_payload.get("exp")
        if jti and exp:
            exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
            revoked_record = RevokedToken(
                jti=jti,
                user_id=user.id,
                expires_at=exp_dt,
            )
            db.add(revoked_record)

        db.commit()
        logger.info("Password successfully changed for user %s", user.id)
