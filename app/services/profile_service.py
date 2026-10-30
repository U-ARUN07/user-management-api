from datetime import datetime, timezone
import logging
from typing import Any, Dict

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import RevokedToken, User, UserProfile
from app.schemas import UserProfileCreate, UserProfileUpdate

logger = logging.getLogger(__name__)


class ProfileService:
    """Service handling user profile management and account deletion."""

    @staticmethod
    def create_profile(
        db: Session, user: User, profile_in: UserProfileCreate
    ) -> UserProfile:
        """Create a profile for the authenticated user.

        Raises:
            HTTPException 409: If a profile already exists for this user.
        """
        stmt = select(UserProfile).where(UserProfile.user_id == user.id)
        existing = db.scalars(stmt).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A profile already exists for this user account.",
            )

        profile_data = profile_in.model_dump(exclude_unset=True)
        # Ensure profile is strictly bound to the authenticated user ID
        new_profile = UserProfile(user_id=user.id, **profile_data)
        db.add(new_profile)
        db.commit()
        db.refresh(new_profile)
        logger.info("Profile created for user %s", user.id)
        return new_profile

    @staticmethod
    def get_profile(db: Session, user: User) -> UserProfile:
        """Fetch profile belonging to the authenticated user.

        Raises:
            HTTPException 404: If no profile exists yet.
        """
        stmt = select(UserProfile).where(UserProfile.user_id == user.id)
        profile = db.scalars(stmt).first()
        if not profile:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Profile not found for this user account.",
            )
        return profile

    @staticmethod
    def update_profile(
        db: Session, user: User, profile_in: UserProfileUpdate
    ) -> UserProfile:
        """Update an existing profile belonging to the authenticated user.

        Supports full and partial updates. Fields not set are left untouched.
        Disallows changing user_id or profile id.
        """
        stmt = select(UserProfile).where(UserProfile.user_id == user.id)
        profile = db.scalars(stmt).first()
        if not profile:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Profile not found. Please create a profile first.",
            )

        update_data = profile_in.model_dump(exclude_unset=True)
        # Disallow updating identity keys
        update_data.pop("user_id", None)
        update_data.pop("id", None)

        for field, value in update_data.items():
            setattr(profile, field, value)

        db.commit()
        db.refresh(profile)
        logger.info("Profile updated for user %s", user.id)
        return profile

    @staticmethod
    def delete_account(
        db: Session, user: User, token_payload: Dict[str, Any]
    ) -> None:
        """Permanently delete user account, associated profile, and invalidate active token."""
        # Record current token in revocation table before account removal
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
            db.flush()

        # Cascading foreign keys will clean up profile and reset tokens
        db.delete(user)
        db.commit()
        logger.info("User account and all related records deleted for user %s", user.id)
