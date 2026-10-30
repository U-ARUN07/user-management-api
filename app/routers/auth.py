from typing import Annotated, Any, Dict, Tuple

from fastapi import APIRouter, Depends, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.database import get_db
from app.dependencies import get_current_user_with_token
from app.models import User
from app.schemas import (
    ChangePasswordRequest,
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    MessageResponse,
    ResetPasswordRequest,
    TokenResponse,
    UserRegister,
    UserResponse,
)
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication & Password Management"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
    description="Registers a new user with full name, normalized email, and an Argon2-hashed password.",
    responses={
        201: {"description": "User created successfully"},
        409: {"description": "Email address already registered"},
        422: {"description": "Validation error (invalid email or weak password)"},
    },
)
def register(
    user_in: UserRegister,
    db: Annotated[Session, Depends(get_db)],
) -> Any:
    return AuthService.register_user(db, user_in)


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="User login with credentials",
    description="Authenticates with email (form field `username`) and password, returning a signed JWT access token.",
    responses={
        200: {"description": "Authentication successful, returns JWT bearer token"},
        401: {"description": "Invalid credentials or inactive account"},
    },
)
def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Annotated[Session, Depends(get_db)],
) -> Any:
    token, _, expires_in = AuthService.authenticate_user(
        db, form_data.username, form_data.password
    )
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in,
    )


@router.post(
    "/logout",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Log out and revoke current access token",
    description="Invalidates the current JWT access token by storing its unique jti in the revocation blocklist.",
    responses={
        200: {"description": "Successfully logged out"},
        401: {"description": "Missing, invalid, or revoked token"},
    },
)
def logout(
    user_token: Annotated[Tuple[User, Dict[str, Any]], Depends(get_current_user_with_token)],
    db: Annotated[Session, Depends(get_db)],
) -> Any:
    user, token_payload = user_token
    AuthService.logout_user(db, user, token_payload)
    return MessageResponse(message="Successfully logged out")


@router.post(
    "/forgot-password",
    response_model=ForgotPasswordResponse,
    status_code=status.HTTP_200_OK,
    summary="Request a password-reset token",
    description="Initiates password reset flow. Returns a generic message to prevent email enumeration.",
    responses={
        200: {"description": "Instructions returned generically"},
    },
)
def forgot_password(
    body: ForgotPasswordRequest,
    db: Annotated[Session, Depends(get_db)],
) -> Any:
    msg, dev_token = AuthService.request_password_reset(db, body.email)
    return ForgotPasswordResponse(message=msg, dev_reset_token=dev_token)


@router.post(
    "/reset-password",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Reset password using reset token",
    description="Resets the user's password using a valid, unused, and unexpired password reset token.",
    responses={
        200: {"description": "Password successfully reset"},
        400: {"description": "Invalid, expired, or reused token, or weak password"},
    },
)
def reset_password(
    body: ResetPasswordRequest,
    db: Annotated[Session, Depends(get_db)],
) -> Any:
    AuthService.reset_password(db, body.token, body.new_password)
    return MessageResponse(message="Password reset successfully")


@router.post(
    "/change-password",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Change password for authenticated user",
    description="Changes password after validating the existing password, and invalidates the current session token.",
    responses={
        200: {"description": "Password changed successfully"},
        400: {"description": "Incorrect current password or matching old/new password"},
        401: {"description": "Unauthorized access"},
    },
)
def change_password(
    body: ChangePasswordRequest,
    user_token: Annotated[Tuple[User, Dict[str, Any]], Depends(get_current_user_with_token)],
    db: Annotated[Session, Depends(get_db)],
) -> Any:
    user, token_payload = user_token
    AuthService.change_password(
        db,
        user=user,
        current_password=body.current_password,
        new_password=body.new_password,
        token_payload=token_payload,
    )
    return MessageResponse(message="Password changed successfully")
