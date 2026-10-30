from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
import jwt
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import PasswordResetToken, User
from app.security import (
    create_access_token,
    generate_reset_token,
    hash_password,
    hash_reset_token,
    verify_password,
)

settings = get_settings()


# ==============================================================
# Registration Tests
# ==============================================================

def test_register_success(client: TestClient):
    """Test successful user registration returns 201 and public user data."""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Priya Sharma",
            "email": "priya@example.com",
            "password": "StrongPassword123",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["full_name"] == "Priya Sharma"
    assert data["email"] == "priya@example.com"
    assert data["is_active"] is True
    assert data["is_verified"] is False
    assert "id" in data
    assert "password" not in data
    assert "hashed_password" not in data


def test_register_duplicate_email(client: TestClient, test_user: User):
    """Test registering with an existing email returns 409 Conflict."""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Arun Duplicate",
            "email": test_user.email,
            "password": "StrongPassword123",
        },
    )
    assert response.status_code == 409
    assert "already exists" in response.json()["detail"].lower()


def test_register_invalid_email(client: TestClient):
    """Test registering with an invalid email returns 422 Unprocessable Entity."""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "full_name": "Invalid Email User",
            "email": "not-an-email",
            "password": "StrongPassword123",
        },
    )
    assert response.status_code == 422


def test_register_weak_password(client: TestClient):
    """Test registering with passwords failing complexity criteria returns 422."""
    # Too short
    res_short = client.post(
        "/api/v1/auth/register",
        json={"full_name": "User One", "email": "user1@example.com", "password": "Sh1"},
    )
    assert res_short.status_code == 422

    # No uppercase
    res_no_upper = client.post(
        "/api/v1/auth/register",
        json={"full_name": "User Two", "email": "user2@example.com", "password": "password123"},
    )
    assert res_no_upper.status_code == 422

    # No digit
    res_no_digit = client.post(
        "/api/v1/auth/register",
        json={"full_name": "User Three", "email": "user3@example.com", "password": "PasswordOnly"},
    )
    assert res_no_digit.status_code == 422


# ==============================================================
# Login Tests
# ==============================================================

def test_login_success(client: TestClient, test_user: User):
    """Test login with valid OAuth2 credentials returns JWT access token."""
    response = client.post(
        "/api/v1/auth/login",
        data={"username": test_user.email, "password": "StrongPassword123"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0


def test_login_incorrect_password(client: TestClient, test_user: User):
    """Test login with wrong password returns 401 Unauthorized."""
    response = client.post(
        "/api/v1/auth/login",
        data={"username": test_user.email, "password": "WrongPassword999"},
    )
    assert response.status_code == 401
    assert "incorrect" in response.json()["detail"].lower()


def test_login_unknown_email(client: TestClient):
    """Test login with non-existent email returns 401 Unauthorized."""
    response = client.post(
        "/api/v1/auth/login",
        data={"username": "unknown@example.com", "password": "StrongPassword123"},
    )
    assert response.status_code == 401
    assert "incorrect" in response.json()["detail"].lower()


def test_login_inactive_account(client: TestClient, db_session: Session):
    """Test login with an inactive account is rejected with 401."""
    inactive_user = User(
        full_name="Inactive Person",
        email="inactive@example.com",
        hashed_password=hash_password("StrongPassword123"),
        is_active=False,
    )
    db_session.add(inactive_user)
    db_session.commit()

    response = client.post(
        "/api/v1/auth/login",
        data={"username": "inactive@example.com", "password": "StrongPassword123"},
    )
    assert response.status_code == 401
    assert "inactive" in response.json()["detail"].lower()


def test_expired_or_invalid_jwt(client: TestClient, test_user: User):
    """Test requests using expired or corrupt tokens return 401."""
    # 1. Expired token
    expired_token, _, _ = create_access_token(
        user_id=test_user.id,
        expires_delta=timedelta(seconds=-10),
    )
    res_expired = client.get(
        "/api/v1/profile/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert res_expired.status_code == 401
    assert "expired" in res_expired.json()["detail"].lower()

    # 2. Corrupted signature token
    bad_token = expired_token[:-5] + "XXXXX"
    res_bad = client.get(
        "/api/v1/profile/me",
        headers={"Authorization": f"Bearer {bad_token}"},
    )
    assert res_bad.status_code == 401


# ==============================================================
# Logout Tests
# ==============================================================

def test_logout_and_revocation(client: TestClient, auth_headers: dict):
    """Test logging out revokes the token so subsequent requests are rejected."""
    # Successfully log out
    logout_res = client.post("/api/v1/auth/logout", headers=auth_headers)
    assert logout_res.status_code == 200
    assert logout_res.json()["message"] == "Successfully logged out"

    # Attempting to reuse revoked token must be rejected
    reuse_res = client.get("/api/v1/profile/me", headers=auth_headers)
    assert reuse_res.status_code == 401
    assert "revoked" in reuse_res.json()["detail"].lower()


# ==============================================================
# Password Management Tests
# ==============================================================

def test_forgot_password_generic_response(client: TestClient, test_user: User):
    """Test forgot-password returns identical generic responses for both existing and non-existing emails."""
    res_known = client.post(
        "/api/v1/auth/forgot-password",
        json={"email": test_user.email},
    )
    assert res_known.status_code == 200
    assert "instructions will be provided" in res_known.json()["message"]

    res_unknown = client.post(
        "/api/v1/auth/forgot-password",
        json={"email": "nobody@example.com"},
    )
    assert res_unknown.status_code == 200
    assert "instructions will be provided" in res_unknown.json()["message"]


def test_reset_password_workflow(client: TestClient, test_user: User, db_session: Session):
    """Test successful password reset and verification with new password."""
    raw_token = generate_reset_token()
    token_hash = hash_reset_token(raw_token)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

    reset_record = PasswordResetToken(
        user_id=test_user.id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    db_session.add(reset_record)
    db_session.commit()

    # Reset password with valid token
    new_pass = "BrandNewPassword123"
    res = client.post(
        "/api/v1/auth/reset-password",
        json={"token": raw_token, "new_password": new_pass},
    )
    assert res.status_code == 200
    assert res.json()["message"] == "Password reset successfully"

    # Login with new password
    login_res = client.post(
        "/api/v1/auth/login",
        data={"username": test_user.email, "password": new_pass},
    )
    assert login_res.status_code == 200


def test_reset_password_invalid_token(client: TestClient):
    """Test reset-password with invalid token returns 400 Bad Request."""
    res = client.post(
        "/api/v1/auth/reset-password",
        json={"token": "invalid_fake_reset_token_123456", "new_password": "NewValidPassword123"},
    )
    assert res.status_code == 400


def test_reset_password_expired_token(client: TestClient, test_user: User, db_session: Session):
    """Test reset-password with expired token returns 400 Bad Request."""
    raw_token = generate_reset_token()
    token_hash = hash_reset_token(raw_token)
    expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)  # Expired

    reset_record = PasswordResetToken(
        user_id=test_user.id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    db_session.add(reset_record)
    db_session.commit()

    res = client.post(
        "/api/v1/auth/reset-password",
        json={"token": raw_token, "new_password": "NewValidPassword123"},
    )
    assert res.status_code == 400
    assert "expired" in res.json()["detail"].lower()


def test_reset_password_reuse_rejected(client: TestClient, test_user: User, db_session: Session):
    """Test that an already used reset token cannot be reused."""
    raw_token = generate_reset_token()
    token_hash = hash_reset_token(raw_token)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

    reset_record = PasswordResetToken(
        user_id=test_user.id,
        token_hash=token_hash,
        expires_at=expires_at,
        used_at=datetime.now(timezone.utc),  # Marked as used
    )
    db_session.add(reset_record)
    db_session.commit()

    res = client.post(
        "/api/v1/auth/reset-password",
        json={"token": raw_token, "new_password": "NewValidPassword123"},
    )
    assert res.status_code == 400
    assert "used" in res.json()["detail"].lower() or "invalid" in res.json()["detail"].lower()


def test_change_password_success(client: TestClient, auth_headers: dict, test_user: User):
    """Test changing password while authenticated."""
    res = client.post(
        "/api/v1/auth/change-password",
        headers=auth_headers,
        json={
            "current_password": "StrongPassword123",
            "new_password": "ChangedPassword987",
        },
    )
    assert res.status_code == 200
    assert res.json()["message"] == "Password changed successfully"

    # Verify that the old token was revoked upon password change
    old_token_res = client.get("/api/v1/profile/me", headers=auth_headers)
    assert old_token_res.status_code == 401


def test_change_password_wrong_current(client: TestClient, auth_headers: dict):
    """Test change password with wrong current password returns 400."""
    res = client.post(
        "/api/v1/auth/change-password",
        headers=auth_headers,
        json={
            "current_password": "IncorrectPassword123",
            "new_password": "ChangedPassword987",
        },
    )
    assert res.status_code == 400
    assert "incorrect" in res.json()["detail"].lower()


def test_change_password_identical_rejected(client: TestClient, auth_headers: dict):
    """Test change password with new password equal to current password returns 422."""
    res = client.post(
        "/api/v1/auth/change-password",
        headers=auth_headers,
        json={
            "current_password": "StrongPassword123",
            "new_password": "StrongPassword123",
        },
    )
    assert res.status_code == 422
