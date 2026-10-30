from typing import Annotated, Any, Dict, Tuple

from fastapi import APIRouter, Depends, status, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user, get_current_user_with_token
from app.models import User
from app.schemas import (
    UserProfileCreate,
    UserProfileDetailResponse,
    UserProfileResponse,
    UserProfileUpdate,
)
from app.services.profile_service import ProfileService

router = APIRouter(prefix="/profile", tags=["User Profile & Account"])


@router.post(
    "/",
    response_model=UserProfileResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create profile for authenticated user",
    description="Creates an extended profile for the authenticated user. Only one profile is permitted per user.",
    responses={
        201: {"description": "Profile successfully created"},
        401: {"description": "Unauthorized access"},
        409: {"description": "Profile already exists for this account"},
        422: {"description": "Validation error in profile fields"},
    },
)
def create_profile(
    profile_in: UserProfileCreate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> Any:
    return ProfileService.create_profile(db, current_user, profile_in)


@router.get(
    "/me",
    response_model=UserProfileDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get authenticated user's profile",
    description="Fetches the profile and public account details for the authenticated user.",
    responses={
        200: {"description": "Profile retrieved successfully"},
        401: {"description": "Unauthorized access"},
        404: {"description": "Profile not found"},
    },
)
def get_profile(
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> Any:
    return ProfileService.get_profile(db, current_user)


@router.put(
    "/me",
    response_model=UserProfileResponse,
    status_code=status.HTTP_200_OK,
    summary="Update authenticated user's profile",
    description="Updates supplied profile fields for the authenticated user. Omitted fields remain unchanged.",
    responses={
        200: {"description": "Profile updated successfully"},
        401: {"description": "Unauthorized access"},
        404: {"description": "Profile not found"},
        422: {"description": "Validation error in updated fields"},
    },
)
def update_profile(
    profile_in: UserProfileUpdate,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> Any:
    return ProfileService.update_profile(db, current_user, profile_in)


@router.delete(
    "/account",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete user account and all associated data",
    description="Permanently deletes the authenticated user's account, profile, and active tokens using cascading deletes.",
    responses={
        204: {"description": "Account deleted successfully"},
        401: {"description": "Unauthorized access"},
    },
)
def delete_account(
    user_token: Annotated[Tuple[User, Dict[str, Any]], Depends(get_current_user_with_token)],
    db: Annotated[Session, Depends(get_db)],
) -> Response:
    user, token_payload = user_token
    ProfileService.delete_account(db, user, token_payload)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
