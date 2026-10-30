from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models import User
from app.security import create_access_token, hash_password


# ==============================================================
# Profile CRUD Tests
# ==============================================================

def test_create_profile_success(client: TestClient, auth_headers: dict):
    """Test creating a profile for the authenticated user returns 201."""
    profile_payload = {
        "phone_number": "+919876543210",
        "address": "HiTech City",
        "city": "Hyderabad",
        "state": "Telangana",
        "country": "India",
        "college": "Infosys Training Institute",
        "degree": "B.Tech CSE",
        "graduation_year": 2027,
        "bio": "Passionate backend engineer.",
        "linkedin_url": "https://www.linkedin.com/in/arun-kumar",
        "github_url": "https://github.com/arun-kumar",
    }
    response = client.post("/api/v1/profile/", headers=auth_headers, json=profile_payload)
    assert response.status_code == 201
    data = response.json()
    assert data["city"] == "Hyderabad"
    assert data["graduation_year"] == 2027
    assert "id" in data
    assert "user_id" in data


def test_create_duplicate_profile_rejected(client: TestClient, auth_headers: dict):
    """Test creating a second profile for the same user returns 409 Conflict."""
    payload = {
        "city": "Hyderabad",
        "degree": "B.Tech",
    }
    # First creation
    res1 = client.post("/api/v1/profile/", headers=auth_headers, json=payload)
    assert res1.status_code == 201

    # Second creation attempt
    res2 = client.post("/api/v1/profile/", headers=auth_headers, json=payload)
    assert res2.status_code == 409
    assert "already exists" in res2.json()["detail"].lower()


def test_get_profile_success(client: TestClient, auth_headers: dict, test_user: User):
    """Test retrieving user profile returns both profile data and public user account information."""
    # First create
    client.post("/api/v1/profile/", headers=auth_headers, json={"city": "Bengaluru"})

    # Then retrieve
    response = client.get("/api/v1/profile/me", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["city"] == "Bengaluru"
    assert "user" in data
    assert data["user"]["email"] == test_user.email
    assert "hashed_password" not in data["user"]


def test_get_missing_profile_returns_404(client: TestClient, auth_headers: dict):
    """Test retrieving profile when none has been created returns 404 Not Found."""
    response = client.get("/api/v1/profile/me", headers=auth_headers)
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_update_profile_success(client: TestClient, auth_headers: dict):
    """Test updating existing profile updates supplied fields."""
    # Create initial
    client.post("/api/v1/profile/", headers=auth_headers, json={"city": "Hyderabad", "bio": "Initial bio"})

    # Update bio and add github
    update_res = client.put(
        "/api/v1/profile/me",
        headers=auth_headers,
        json={"bio": "Updated bio", "github_url": "https://github.com/updated"},
    )
    assert update_res.status_code == 200
    updated_data = update_res.json()
    assert updated_data["bio"] == "Updated bio"
    assert updated_data["github_url"] == "https://github.com/updated"
    assert updated_data["city"] == "Hyderabad"  # Preserved untouched field


def test_update_missing_profile_returns_404(client: TestClient, auth_headers: dict):
    """Test updating profile before creating one returns 404."""
    update_res = client.put(
        "/api/v1/profile/me",
        headers=auth_headers,
        json={"city": "Pune"},
    )
    assert update_res.status_code == 404


def test_profile_validation_errors(client: TestClient, auth_headers: dict):
    """Test invalid graduation year and invalid URL formats are rejected with 422."""
    # Invalid graduation year (out of bounds)
    res_year = client.post(
        "/api/v1/profile/",
        headers=auth_headers,
        json={"graduation_year": 1800},
    )
    assert res_year.status_code == 422

    # Invalid URL format (missing scheme)
    res_url = client.post(
        "/api/v1/profile/",
        headers=auth_headers,
        json={"linkedin_url": "invalid_url_not_http"},
    )
    assert res_url.status_code == 422


def test_unauthorized_profile_requests(client: TestClient):
    """Test protected profile endpoints return 401 when no token is provided."""
    assert client.get("/api/v1/profile/me").status_code == 401
    assert client.post("/api/v1/profile/", json={}).status_code == 401
    assert client.put("/api/v1/profile/me", json={}).status_code == 401
    assert client.delete("/api/v1/profile/account").status_code == 401


def test_isolation_between_users(client: TestClient, auth_headers: dict, db_session: Session):
    """Test that User B cannot access User A's profile data."""
    # User A creates profile
    client.post("/api/v1/profile/", headers=auth_headers, json={"city": "Mumbai"})

    # Create User B
    user_b = User(
        full_name="User B",
        email="user_b@example.com",
        hashed_password=hash_password("StrongPassword123"),
        is_active=True,
    )
    db_session.add(user_b)
    db_session.commit()
    db_session.refresh(user_b)

    token_b, _, _ = create_access_token(user_id=user_b.id)
    headers_b = {"Authorization": f"Bearer {token_b}"}

    # User B checks their profile (which does not exist yet) -> 404
    res_b = client.get("/api/v1/profile/me", headers=headers_b)
    assert res_b.status_code == 404

    # User B creates their own profile in Chennai
    client.post("/api/v1/profile/", headers=headers_b, json={"city": "Chennai"})
    res_b_profile = client.get("/api/v1/profile/me", headers=headers_b)
    assert res_b_profile.json()["city"] == "Chennai"

    # User A's profile is still Mumbai
    res_a_profile = client.get("/api/v1/profile/me", headers=auth_headers)
    assert res_a_profile.json()["city"] == "Mumbai"


def test_delete_account_and_token_invalidation(client: TestClient, auth_headers: dict, test_user: User):
    """Test deleting account returns 204 and permanently invalidates existing access token."""
    # Delete account
    del_res = client.delete("/api/v1/profile/account", headers=auth_headers)
    assert del_res.status_code == 204

    # Subsequent request using the token must return 401
    res_after = client.get("/api/v1/profile/me", headers=auth_headers)
    assert res_after.status_code == 401


# ==============================================================
# General & Health Check Tests
# ==============================================================

def test_root_endpoint(client: TestClient):
    """Test root endpoint returns welcome message and docs links."""
    res = client.get("/")
    assert res.status_code == 200
    data = res.json()
    assert "version" in data
    assert "documentation" in data


def test_health_check_endpoint(client: TestClient):
    """Test health check returns system status and timestamp."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert "status" in data
    assert "timestamp" in data
