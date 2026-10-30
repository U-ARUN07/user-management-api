from datetime import date, datetime
import re
from typing import Optional
import uuid

from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)


def validate_password_complexity(password: str) -> str:
    """Enforce a strong password policy:
    - Minimum 8 characters, maximum 128 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one numeric digit
    """
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if len(password) > 128:
        raise ValueError("Password must not exceed 128 characters.")
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not any(c.islower() for c in password):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one number.")
    return password


# ==============================================================
# Authentication Schemas
# ==============================================================

class UserRegister(BaseModel):
    """Schema for user registration."""

    full_name: str = Field(
        ...,
        min_length=2,
        max_length=150,
        description="User's full legal name",
        examples=["Arun Kumar"],
    )
    email: EmailStr = Field(
        ...,
        description="Unique email address",
        examples=["arun@example.com"],
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Password with upper, lower, and digit requirements",
        examples=["StrongPassword123"],
    )

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v: str) -> str:
        cleaned = v.strip()
        if len(cleaned) < 2:
            raise ValueError("Full name must contain at least 2 characters.")
        return cleaned

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: EmailStr) -> str:
        return str(v).strip().lower()

    @field_validator("password")
    @classmethod
    def check_password(cls, v: str) -> str:
        return validate_password_complexity(v)


class UserLogin(BaseModel):
    """Schema for direct JSON login requests."""

    email: EmailStr = Field(..., examples=["arun@example.com"])
    password: str = Field(..., examples=["StrongPassword123"])

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: EmailStr) -> str:
        return str(v).strip().lower()


class UserResponse(BaseModel):
    """Public user response schema without sensitive fields."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    full_name: str
    email: EmailStr
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: Optional[datetime] = None


class TokenResponse(BaseModel):
    """OAuth2 / JWT Bearer access token response."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(
        ...,
        description="Token lifetime in seconds",
        examples=[1800],
    )


class ForgotPasswordRequest(BaseModel):
    """Request schema for initiating a password reset."""

    email: EmailStr = Field(..., examples=["arun@example.com"])

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: EmailStr) -> str:
        return str(v).strip().lower()


class ForgotPasswordResponse(BaseModel):
    """Response returned upon password reset request."""

    message: str = "If the account exists, password-reset instructions will be provided."
    dev_reset_token: Optional[str] = Field(
        default=None,
        description="Included only in local development mode for testing convenience",
    )


class ResetPasswordRequest(BaseModel):
    """Schema for resetting a password using a received reset token."""

    token: str = Field(
        ...,
        min_length=16,
        description="The raw password reset token received",
        examples=["safe_random_reset_token_here"],
    )
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="New password meeting complexity criteria",
        examples=["NewStrongPassword123"],
    )

    @field_validator("new_password")
    @classmethod
    def check_new_password(cls, v: str) -> str:
        return validate_password_complexity(v)


class ChangePasswordRequest(BaseModel):
    """Schema for changing password when authenticated."""

    current_password: str = Field(
        ...,
        min_length=1,
        description="Current account password",
        examples=["StrongPassword123"],
    )
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="New password meeting complexity criteria",
        examples=["NewStrongPassword123"],
    )

    @field_validator("new_password")
    @classmethod
    def check_new_password(cls, v: str) -> str:
        return validate_password_complexity(v)

    @model_validator(mode="after")
    def passwords_differ(self) -> "ChangePasswordRequest":
        if self.current_password == self.new_password:
            raise ValueError("New password must be different from the current password.")
        return self


# ==============================================================
# User Profile Schemas
# ==============================================================

class ProfileBase(BaseModel):
    """Base fields for user profile creation and updating."""

    phone_number: Optional[str] = Field(
        default=None,
        max_length=30,
        examples=["+919876543210"],
    )
    date_of_birth: Optional[date] = Field(
        default=None,
        examples=["2002-05-15"],
    )
    address: Optional[str] = Field(
        default=None,
        max_length=500,
        examples=["Hyderabad"],
    )
    city: Optional[str] = Field(
        default=None,
        max_length=100,
        examples=["Hyderabad"],
    )
    state: Optional[str] = Field(
        default=None,
        max_length=100,
        examples=["Telangana"],
    )
    country: Optional[str] = Field(
        default=None,
        max_length=100,
        examples=["India"],
    )
    college: Optional[str] = Field(
        default=None,
        max_length=255,
        examples=["Example Engineering College"],
    )
    degree: Optional[str] = Field(
        default=None,
        max_length=150,
        examples=["B.Tech CSE"],
    )
    graduation_year: Optional[int] = Field(
        default=None,
        examples=[2027],
    )
    bio: Optional[str] = Field(
        default=None,
        max_length=1000,
        examples=["Computer Science student"],
    )
    linkedin_url: Optional[str] = Field(
        default=None,
        max_length=500,
        examples=["https://www.linkedin.com/in/example"],
    )
    github_url: Optional[str] = Field(
        default=None,
        max_length=500,
        examples=["https://github.com/example"],
    )

    @field_validator("phone_number")
    @classmethod
    def validate_phone(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            cleaned = v.strip()
            if cleaned:
                # Basic international phone regex: optional +, digits, dashes, spaces
                if not re.match(r"^\+?[0-9\s\-]{7,25}$", cleaned):
                    raise ValueError("Invalid phone number format.")
                return cleaned
            return None
        return None

    @field_validator("graduation_year")
    @classmethod
    def validate_grad_year(cls, v: Optional[int]) -> Optional[int]:
        if v is not None:
            if v < 1950 or v > 2040:
                raise ValueError("Graduation year must be between 1950 and 2040.")
        return v

    @field_validator("linkedin_url", "github_url")
    @classmethod
    def validate_url(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            cleaned = v.strip()
            if cleaned:
                if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
                    raise ValueError("URL must start with http:// or https://")
                return cleaned
            return None
        return None


class UserProfileCreate(ProfileBase):
    """Schema for profile creation."""
    pass


class UserProfileUpdate(ProfileBase):
    """Schema for updating profile fields."""
    pass


class UserProfileResponse(BaseModel):
    """Schema for profile responses."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    phone_number: Optional[str] = None
    date_of_birth: Optional[date] = None
    address: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    college: Optional[str] = None
    degree: Optional[str] = None
    graduation_year: Optional[int] = None
    bio: Optional[str] = None
    linkedin_url: Optional[str] = None
    github_url: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class UserProfileDetailResponse(UserProfileResponse):
    """Detailed profile response including public user account information."""

    user: UserResponse


class UserProfileWithUserResponse(BaseModel):
    """Combined response returning both user account and profile data."""

    model_config = ConfigDict(from_attributes=True)

    user: UserResponse
    profile: UserProfileResponse


class MessageResponse(BaseModel):
    """Generic message response."""

    message: str
