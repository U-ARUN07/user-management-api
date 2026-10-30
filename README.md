# User Management API — Infosys Springboard Virtual Internship Program 7.0

> **Assignment 1:** User Management REST APIs with FastAPI, PostgreSQL, SQLAlchemy 2.x, Alembic, and JWT/Argon2 Authentication.

---

## Table of Contents
1. [Project Overview](#1-project-overview)
2. [Assignment Objectives](#2-assignment-objectives)
3. [Technology Stack](#3-technology-stack)
4. [Folder Structure](#4-folder-structure)
5. [Prerequisites](#5-prerequisites)
6. [PostgreSQL Database Setup](#6-postgresql-database-setup)
7. [Python Virtual Environment Setup](#7-python-virtual-environment-setup)
8. [Dependency Installation](#8-dependency-installation)
9. [Environment Variable Configuration](#9-environment-variable-configuration)
10. [Alembic Database Migration Commands](#10-alembic-database-migration-commands)
11. [Running the Application Server](#11-running-the-application-server)
12. [Interactive Swagger UI & ReDoc](#12-interactive-swagger-ui--redoc)
13. [API Endpoints Overview](#13-api-endpoints-overview)
14. [Sample Requests and Responses](#14-sample-requests-and-responses)
15. [Authentication & Authorization Guide](#15-authentication--authorization-guide)
16. [Password Reset Workflow](#16-password-reset-workflow)
17. [Running Automated Tests](#17-running-automated-tests)
18. [Database Schema & Entity Relationships](#18-database-schema--entity-relationships)
19. [How to Safely Upload to GitHub](#19-how-to-safely-upload-to-github)
20. [File-by-File Explanation (Mentor Review Guide)](#20-file-by-file-explanation-mentor-review-guide)
21. [Security Limitations & Production Considerations](#21-security-limitations--production-considerations)

---

## 1. Project Overview

The **User Management API** is a secure, production-grade RESTful backend built using **FastAPI** and **PostgreSQL**. Designed as part of Assignment 1 for the **Infosys Springboard Virtual Internship Program 7.0**, the system implements comprehensive authentication, authorization, profile management, and password lifecycle operations.

The API adheres to modern software engineering best practices:
- **Clean Architecture:** Strict separation between routing, business logic (`services`), persistence (`models`), schemas (`Pydantic`), and cross-cutting concerns (`security`, `dependencies`).
- **Defensive Security:** State-of-the-art **Argon2** password hashing via `pwdlib`, cryptographically signed **JWT access tokens** with revocation tracking, SHA-256 token hashing for password resets, and user enumeration protection.
- **Data Integrity:** Fully typed SQLAlchemy 2.0 ORM models with cascading deletions, unique constraints, and database migrations via Alembic.

---

## 2. Assignment Objectives

The key learning and evaluation objectives demonstrated in this project include:
1. Building high-performance asynchronous REST APIs using **FastAPI**.
2. Strict request validation and response filtering using **Pydantic 2.x**.
3. Implementing **OAuth2 Bearer Token Authentication** with PyJWT.
4. Token revocation blocklist mechanics for deterministic user logout.
5. Implementing **Argon2** password hashing (winner of the Password Hashing Competition) via `pwdlib`.
6. Relational database modeling using **SQLAlchemy 2.x** declarative syntax and **PostgreSQL (Psycopg 3)** driver.
7. Database schema version control using **Alembic migrations**.
8. Comprehensive test-driven validation using **pytest** and **TestClient**.

---

## 3. Technology Stack

| Layer | Component | Version / Library |
|---|---|---|
| **Language** | Python | 3.11+ (Tested on Python 3.14) |
| **Framework** | FastAPI | >= 0.115.0 |
| **ASGI Server** | Uvicorn | >= 0.34.0 |
| **Database** | PostgreSQL | 15+ / 16+ |
| **ORM** | SQLAlchemy | >= 2.0.30 |
| **Database Driver** | Psycopg 3 | >= 3.1.18 (`psycopg[binary]`) |
| **Migrations** | Alembic | >= 1.13.0 |
| **Data Validation** | Pydantic 2 & Settings | >= 2.7.0 (`pydantic-settings`, `email-validator`) |
| **Password Hashing**| Argon2 | `pwdlib[argon2]` (argon2-cffi) |
| **JWT Tokens** | PyJWT | >= 2.8.0 |
| **Testing** | Pytest & TestClient | `pytest` >= 8.0, `httpx` >= 0.27, `pytest-cov` |

---

## 4. Folder Structure

```
ai-career-companion-apis/
│
├── app/
│   ├── __init__.py           # Application package marker
│   ├── main.py               # FastAPI application entrypoint, middleware, exception handlers
│   ├── config.py             # Pydantic BaseSettings environment configuration
│   ├── database.py           # SQLAlchemy engine, sessionmaker, and get_db dependency
│   ├── models.py             # SQLAlchemy 2.x ORM models (User, UserProfile, etc.)
│   ├── schemas.py            # Pydantic 2.x input validation and output serialization schemas
│   ├── security.py           # Argon2 hashing, JWT creation/decoding, reset token hashing
│   ├── dependencies.py       # Authentication dependencies and token verification
│   │
│   ├── routers/
│   │   ├── __init__.py
│   │   ├── auth.py           # Registration, login, logout, and password management routes
│   │   └── profile.py        # User profile CRUD and account deletion routes
│   │
│   └── services/
│       ├── __init__.py
│       ├── auth_service.py   # Business logic for authentication and reset workflows
│       └── profile_service.py# Business logic for profile operations and deletion
│
├── alembic/
│   ├── env.py                # Alembic migration runner reading app metadata & config
│   └── versions/
│       └── 001_initial_schema.py # Initial database migration
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py           # Pytest test fixtures and isolated database setup
│   ├── test_auth.py          # 18 test cases for authentication & password flows
│   └── test_profile.py       # 12 test cases for profile CRUD and account lifecycle
│
├── .env                      # Local environment variables (excluded from git)
├── .env.example              # Template configuration for deployment
├── .gitignore                # Git exclusion rules for secrets, venv, and caches
├── alembic.ini               # Alembic CLI configuration
├── requirements.txt          # Python package dependencies
└── README.md                 # Complete documentation
```

---

## 5. Prerequisites

Before running the project, ensure you have:
1. **Python 3.11 or newer** installed:
   ```powershell
   python --version
   ```
2. **PostgreSQL** installed and running on localhost (default port: `5432`).
3. **Git** installed on your system.

---

## 6. PostgreSQL Database Setup

Connect to PostgreSQL using `psql` or pgAdmin and create the dedicated database:

```sql
-- Connect to PostgreSQL as admin (e.g. postgres user)
CREATE DATABASE user_management_db;

-- Verify database exists
\l
```

Ensure the credentials (user and password) match your local PostgreSQL configuration.

---

## 7. Python Virtual Environment Setup

### On Windows (PowerShell):
```powershell
# Navigate to the workspace directory
python -m venv venv

# Activate the virtual environment
venv\Scripts\activate
```

### On Linux / macOS:
```bash
python3 -m venv venv
source venv/bin/activate
```

---

## 8. Dependency Installation

Install all required production and testing dependencies:
```powershell
pip install -r requirements.txt
```

Verify installed packages:
```powershell
pip list
```

---

## 9. Environment Variable Configuration

Copy `.env.example` to create your local `.env` file:

```powershell
# On Windows PowerShell
Copy-Item .env.example .env
```

Open `.env` and fill in your PostgreSQL password and a strong JWT secret:

```env
# Application Configuration
APP_NAME="User Management API"
APP_ENV=development
APP_VERSION=1.0.0
DEBUG=True

# Database Configuration (PostgreSQL with Psycopg 3 driver)
DATABASE_URL=postgresql+psycopg://postgres:YOUR_POSTGRES_PASSWORD@localhost:5432/user_management_db

# Security & JWT Authentication (Minimum 32 characters)
JWT_SECRET_KEY=development_jwt_secret_key_springboard_internship_assignment_2026_secure
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Password Reset Configuration
PASSWORD_RESET_EXPIRE_MINUTES=15
```

> **Note:** The application validates that `JWT_SECRET_KEY` is at least 32 characters long and `DATABASE_URL` is a valid database connection string. If missing or invalid, startup fails immediately with a clear explanation.

---

## 10. Alembic Database Migration Commands

Apply the database migrations to create the required tables and indices in PostgreSQL:

```powershell
# Apply all pending migrations to the latest revision
alembic upgrade head
```

### Useful Alembic Commands:
- Check current revision status:
  ```powershell
  alembic current
  ```
- Inspect generated migration SQL without executing (Offline Mode):
  ```powershell
  alembic upgrade head --sql
  ```
- Rollback one migration:
  ```powershell
  alembic downgrade -1
  ```

---

## 11. Running the Application Server

Start the FastAPI application with Uvicorn:

```powershell
uvicorn app.main:app --reload
```

The server will start at:
- **Base URL:** `http://127.0.0.1:8000`
- **Health Check:** `http://127.0.0.1:8000/health`

---

## 12. Interactive Swagger UI & ReDoc

FastAPI automatically generates interactive OpenAPI documentation:

- **Swagger UI:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc:** [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
- **OpenAPI Schema (JSON):** [http://127.0.0.1:8000/openapi.json](http://127.0.0.1:8000/openapi.json)

### Using the Swagger "Authorize" Button:
1. Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).
2. Click the green **Authorize** button on the top right.
3. In the OAuth2 form:
   - **username**: enter your registered email address (e.g. `arun@example.com`).
   - **password**: enter your password (e.g. `StrongPassword123`).
4. Click **Authorize**. Swagger UI will call `/api/v1/auth/login`, extract the Bearer token, and automatically attach `Authorization: Bearer <token>` to all protected endpoints!

---

## 13. API Endpoints Overview

All APIs are prefixed with `/api/v1`:

| # | HTTP Method | Endpoint | Description | Auth Required |
|---|---|---|---|:---:|
| 1 | `POST` | `/api/v1/auth/register` | Register a new user account | No |
| 2 | `POST` | `/api/v1/auth/login` | Authenticate and obtain JWT access token | No |
| 3 | `POST` | `/api/v1/auth/logout` | Revoke current access token (logout) | **Yes** |
| 4 | `POST` | `/api/v1/auth/forgot-password` | Request password reset token | No |
| 5 | `POST` | `/api/v1/auth/reset-password` | Reset password using reset token | No |
| 6 | `POST` | `/api/v1/auth/change-password` | Change password for logged-in user | **Yes** |
| 7 | `POST` | `/api/v1/profile/` | Create profile for current user | **Yes** |
| 8 | `GET` | `/api/v1/profile/me` | Get profile and public account details | **Yes** |
| 9 | `PUT` | `/api/v1/profile/me` | Update profile fields | **Yes** |
| 10 | `DELETE` | `/api/v1/profile/account` | Delete user account and profile data | **Yes** |
| — | `GET` | `/` | Service information and docs links | No |
| — | `GET` | `/health` | Liveness and database connectivity check | No |

---

## 14. Sample Requests and Responses

### API 1: User Registration
**`POST /api/v1/auth/register`**

**Request Body:**
```json
{
  "full_name": "Arun Kumar",
  "email": "arun@example.com",
  "password": "StrongPassword123"
}
```

**Success Response (HTTP 201 Created):**
```json
{
  "id": "e30e6258-c0b7-44bc-b532-6a6c0cba4837",
  "full_name": "Arun Kumar",
  "email": "arun@example.com",
  "is_active": true,
  "is_verified": false,
  "created_at": "2026-10-30T19:25:00.123456Z",
  "updated_at": "2026-10-30T19:25:00.123456Z"
}
```

**Error Response: Duplicate Email (HTTP 409 Conflict):**
```json
{
  "detail": "A user with this email address already exists."
}
```

---

### API 2: User Login
**`POST /api/v1/auth/login`**

Accepts `application/x-www-form-urlencoded` standard OAuth2 form:
- `username`: `arun@example.com`
- `password`: `StrongPassword123`

**Success Response (HTTP 200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

**Error Response: Invalid Credentials (HTTP 401 Unauthorized):**
```json
{
  "detail": "Incorrect email or password."
}
```

---

### API 3: User Logout
**`POST /api/v1/auth/logout`**

**Headers:**
```
Authorization: Bearer <your_jwt_access_token>
```

**Success Response (HTTP 200 OK):**
```json
{
  "message": "Successfully logged out"
}
```

> **Security Note:** Once logged out, the token's `jti` is stored in the `revoked_tokens` table. Any subsequent request attempting to reuse this token is rejected with `HTTP 401 Unauthorized`.

---

### API 4: Forgot Password
**`POST /api/v1/auth/forgot-password`**

**Request Body:**
```json
{
  "email": "arun@example.com"
}
```

**Success Response (HTTP 200 OK):**
```json
{
  "message": "If the account exists, password-reset instructions will be provided.",
  "dev_reset_token": "vU7s9Y..." 
}
```
*(In development mode, `dev_reset_token` is returned for effortless local testing. In production, this field is `null` and instructions are sent via email).*

---

### API 5: Reset Password
**`POST /api/v1/auth/reset-password`**

**Request Body:**
```json
{
  "token": "vU7s9Y_sample_reset_token_here",
  "new_password": "NewStrongPassword456"
}
```

**Success Response (HTTP 200 OK):**
```json
{
  "message": "Password reset successfully"
}
```

---

### API 6: Change Password
**`POST /api/v1/auth/change-password`**

**Headers:**
```
Authorization: Bearer <your_jwt_access_token>
```

**Request Body:**
```json
{
  "current_password": "NewStrongPassword456",
  "new_password": "AnotherStrongPassword789"
}
```

**Success Response (HTTP 200 OK):**
```json
{
  "message": "Password changed successfully"
}
```

---

### API 7: Create User Profile
**`POST /api/v1/profile/`**

**Headers:**
```
Authorization: Bearer <your_jwt_access_token>
```

**Request Body:**
```json
{
  "phone_number": "+919876543210",
  "address": "HiTech City",
  "city": "Hyderabad",
  "state": "Telangana",
  "country": "India",
  "college": "Infosys Training Institute",
  "degree": "B.Tech CSE",
  "graduation_year": 2027,
  "bio": "Aspiring Cloud Backend Developer",
  "linkedin_url": "https://www.linkedin.com/in/arunkumar",
  "github_url": "https://github.com/arunkumar"
}
```

**Success Response (HTTP 201 Created):**
```json
{
  "id": "7fa84d72-475a-4b9b-9c24-4fdfd3701449",
  "user_id": "e30e6258-c0b7-44bc-b532-6a6c0cba4837",
  "phone_number": "+919876543210",
  "date_of_birth": null,
  "address": "HiTech City",
  "city": "Hyderabad",
  "state": "Telangana",
  "country": "India",
  "college": "Infosys Training Institute",
  "degree": "B.Tech CSE",
  "graduation_year": 2027,
  "bio": "Aspiring Cloud Backend Developer",
  "linkedin_url": "https://www.linkedin.com/in/arunkumar",
  "github_url": "https://github.com/arunkumar",
  "created_at": "2026-10-30T19:25:30.123456Z",
  "updated_at": "2026-10-30T19:25:30.123456Z"
}
```

---

### API 8: Get User Profile
**`GET /api/v1/profile/me`**

**Headers:**
```
Authorization: Bearer <your_jwt_access_token>
```

**Success Response (HTTP 200 OK):**
```json
{
  "id": "7fa84d72-475a-4b9b-9c24-4fdfd3701449",
  "user_id": "e30e6258-c0b7-44bc-b532-6a6c0cba4837",
  "phone_number": "+919876543210",
  "date_of_birth": null,
  "address": "HiTech City",
  "city": "Hyderabad",
  "state": "Telangana",
  "country": "India",
  "college": "Infosys Training Institute",
  "degree": "B.Tech CSE",
  "graduation_year": 2027,
  "bio": "Aspiring Cloud Backend Developer",
  "linkedin_url": "https://www.linkedin.com/in/arunkumar",
  "github_url": "https://github.com/arunkumar",
  "created_at": "2026-10-30T19:25:30.123456Z",
  "updated_at": "2026-10-30T19:25:30.123456Z",
  "user": {
    "id": "e30e6258-c0b7-44bc-b532-6a6c0cba4837",
    "full_name": "Arun Kumar",
    "email": "arun@example.com",
    "is_active": true,
    "is_verified": false,
    "created_at": "2026-10-30T19:25:00.123456Z",
    "updated_at": "2026-10-30T19:25:00.123456Z"
  }
}
```

---

### API 9: Update User Profile
**`PUT /api/v1/profile/me`**

Supports partial updates; omitted fields remain untouched:

**Request Body:**
```json
{
  "city": "Bengaluru",
  "bio": "Senior Cloud Backend Developer"
}
```

**Success Response (HTTP 200 OK):**
```json
{
  "id": "7fa84d72-475a-4b9b-9c24-4fdfd3701449",
  "user_id": "e30e6258-c0b7-44bc-b532-6a6c0cba4837",
  "phone_number": "+919876543210",
  "date_of_birth": null,
  "address": "HiTech City",
  "city": "Bengaluru",
  "state": "Telangana",
  "country": "India",
  "college": "Infosys Training Institute",
  "degree": "B.Tech CSE",
  "graduation_year": 2027,
  "bio": "Senior Cloud Backend Developer",
  "linkedin_url": "https://www.linkedin.com/in/arunkumar",
  "github_url": "https://github.com/arunkumar",
  "created_at": "2026-10-30T19:25:30.123456Z",
  "updated_at": "2026-10-30T19:26:15.123456Z"
}
```

---

### API 10: Delete User Account
**`DELETE /api/v1/profile/account`**

**Headers:**
```
Authorization: Bearer <your_jwt_access_token>
```

**Success Response (HTTP 204 No Content):**
*(Empty Response Body)*

> **Cascade Deletion:** The user record, associated profile, reset tokens, and active session tokens are permanently wiped from the database. Any old access tokens can never authenticate again.

---

## 15. Authentication & Authorization Guide

### Architecture:
```
Client Request
      │
      ▼  Authorization: Bearer <token>
dependencies.get_token_payload()
      │
      ├── 1. Decodes JWT using JWT_SECRET_KEY and algorithm (HS256)
      ├── 2. Checks token expiration (exp claim)
      └── 3. Checks revoked_tokens table for token identifier (jti)
              │
              ├── If found in blocklist ──> 401 Unauthorized (Token Revoked)
              └── If valid ───────────────> dependencies.get_current_user()
                                                  │
                                                  ├── Look up User by sub UUID in DB
                                                  └── Verify user is active
                                                        │
                                                        └── Inject User into Route Handler
```

---

## 16. Password Reset Workflow

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant API as FastAPI Router
    participant Svc as AuthService
    participant DB as PostgreSQL

    User->>API: POST /auth/forgot-password {email}
    API->>Svc: request_password_reset(email)
    Svc->>DB: Check if user exists
    alt User exists
        Svc->>Svc: Generate secure token (secrets.token_urlsafe)
        Svc->>Svc: Calculate SHA-256 hash(raw_token)
        Svc->>DB: Invalidate old tokens & Store token_hash
    end
    Svc-->>API: Generic message
    API-->>User: 200 OK (Generic response prevents email enumeration)

    User->>API: POST /auth/reset-password {raw_token, new_password}
    API->>Svc: reset_password(token, new_password)
    Svc->>Svc: Hash raw_token with SHA-256
    Svc->>DB: Query token_hash where used_at is NULL and expires_at > now()
    alt Token is valid & unexpired
        Svc->>Svc: Hash new_password with Argon2
        Svc->>DB: Update user.hashed_password & set token.used_at = now()
        Svc-->>API: Success
        API-->>User: 200 OK (Password reset successfully)
    else Token invalid or expired
        API-->>User: 400 Bad Request
    end
```

---

## 17. Running Automated Tests

The project includes **30 comprehensive automated tests** with **94% test coverage** using `pytest` and `FastAPI TestClient`.

The test suite runs against an isolated in-memory test database fixture (via SQLite with `PRAGMA foreign_keys=ON`) so tests never mutate or depend on production databases.

### Run All Tests:
```powershell
python -m pytest -v
```

### Run Tests with Coverage Report:
```powershell
python -m pytest --cov=app tests/
```

### Test Suite Execution Output:
```
============================= test session starts =============================
collected 30 items

tests/test_auth.py::test_register_success PASSED                         [  3%]
tests/test_auth.py::test_register_duplicate_email PASSED                 [  6%]
tests/test_auth.py::test_register_invalid_email PASSED                   [ 10%]
tests/test_auth.py::test_register_weak_password PASSED                   [ 13%]
tests/test_auth.py::test_login_success PASSED                            [ 16%]
tests/test_auth.py::test_login_incorrect_password PASSED                 [ 20%]
tests/test_auth.py::test_login_unknown_email PASSED                      [ 23%]
tests/test_auth.py::test_login_inactive_account PASSED                   [ 26%]
tests/test_auth.py::test_expired_or_invalid_jwt PASSED                   [ 30%]
tests/test_auth.py::test_logout_and_revocation PASSED                    [ 33%]
tests/test_auth.py::test_forgot_password_generic_response PASSED         [ 36%]
tests/test_auth.py::test_reset_password_workflow PASSED                  [ 40%]
tests/test_auth.py::test_reset_password_invalid_token PASSED             [ 43%]
tests/test_auth.py::test_reset_password_expired_token PASSED             [ 46%]
tests/test_auth.py::test_reset_password_reuse_rejected PASSED            [ 50%]
tests/test_auth.py::test_change_password_success PASSED                  [ 53%]
tests/test_auth.py::test_change_password_wrong_current PASSED            [ 56%]
tests/test_auth.py::test_change_password_identical_rejected PASSED       [ 60%]
tests/test_profile.py::test_create_profile_success PASSED                [ 63%]
tests/test_profile.py::test_create_duplicate_profile_rejected PASSED     [ 66%]
tests/test_profile.py::test_get_profile_success PASSED                   [ 70%]
tests/test_profile.py::test_get_missing_profile_returns_404 PASSED       [ 73%]
tests/test_profile.py::test_update_profile_success PASSED                [ 76%]
tests/test_profile.py::test_update_missing_profile_returns_404 PASSED    [ 80%]
tests/test_profile.py::test_profile_validation_errors PASSED             [ 83%]
tests/test_profile.py::test_unauthorized_profile_requests PASSED         [ 86%]
tests/test_profile.py::test_isolation_between_users PASSED               [ 90%]
tests/test_profile.py::test_delete_account_and_token_invalidation PASSED [ 93%]
tests/test_profile.py::test_root_endpoint PASSED                         [ 96%]
tests/test_profile.py::test_health_check_endpoint PASSED                 [100%]

======================= 30 passed in 2.28s =======================
```

---

## 18. Database Schema & Entity Relationships

```mermaid
erDiagram
    users ||--o| user_profiles : "has profile (1:1)"
    users ||--o{ password_reset_tokens : "owns reset tokens (1:N)"
    users ||--o{ revoked_tokens : "owns revoked tokens (1:N)"

    users {
        UUID id PK
        VARCHAR(150) full_name
        VARCHAR(255) email UK,IX
        VARCHAR(255) hashed_password
        BOOLEAN is_active
        BOOLEAN is_verified
        TIMESTAMPTZ created_at
        TIMESTAMPTZ updated_at
    }

    user_profiles {
        UUID id PK
        UUID user_id FK,UK,IX
        VARCHAR(30) phone_number
        DATE date_of_birth
        TEXT address
        VARCHAR(100) city
        VARCHAR(100) state
        VARCHAR(100) country
        VARCHAR(255) college
        VARCHAR(150) degree
        INTEGER graduation_year
        TEXT bio
        VARCHAR(500) linkedin_url
        VARCHAR(500) github_url
        TIMESTAMPTZ created_at
        TIMESTAMPTZ updated_at
    }

    password_reset_tokens {
        UUID id PK
        UUID user_id FK,IX
        VARCHAR(255) token_hash UK,IX
        TIMESTAMPTZ expires_at
        TIMESTAMPTZ used_at
        TIMESTAMPTZ created_at
    }

    revoked_tokens {
        UUID id PK
        VARCHAR(64) jti UK,IX
        UUID user_id FK,IX
        TIMESTAMPTZ expires_at
        TIMESTAMPTZ created_at
    }
```

---

## 19. How to Safely Upload to GitHub

1. **Verify Git Status:**
   ```powershell
   git status
   ```
2. **Confirm `.env` is Ignored:**
   ```powershell
   git check-ignore -v .env
   ```
   *(Should confirm that `.env` is ignored by `.gitignore`)*.
3. **Initialize Repository & Commit:**
   ```powershell
   git init
   git add .
   git commit -m "feat: complete assignment 1 user management API with FastAPI and PostgreSQL"
   ```
4. **Create Remote Repository on GitHub:**
   - Go to [GitHub](https://github.com) -> New Repository.
   - Name it `user-management-api` or `infosys-assignment-1`.
   - Set visibility to **Public** or **Private** as desired.
5. **Push Code:**
   ```powershell
   git branch -M main
   git remote add origin https://github.com/<YOUR_USERNAME>/<YOUR_REPO_NAME>.git
   git push -u origin main
   ```

---

## 20. File-by-File Explanation (Mentor Review Guide)

When presenting this project to your mentor, use these explanations:

1. **`app/main.py`**:
   The entrypoint of the application. Initializes FastAPI, sets up CORS middleware, registers routers under the `/api/v1` prefix, configures standardized exception handlers (preventing stack traces from leaking to clients), and provides root (`/`) and health check (`/health`) endpoints.

2. **`app/config.py`**:
   Implements 12-factor application configuration using Pydantic's `BaseSettings`. Loads variables from `.env` and enforces validation (e.g. requiring at least 32 characters for `JWT_SECRET_KEY` and checking `DATABASE_URL` format).

3. **`app/database.py`**:
   Configures the SQLAlchemy 2.0 engine, the sessionmaker factory with `pool_pre_ping=True`, and exports the declarative `Base` class. Contains the `get_db()` dependency generator which ensures database sessions are cleanly closed in `finally` blocks and rolled back upon transaction errors. Never silently falls back to SQLite.

4. **`app/models.py`**:
   Declares the database tables using modern SQLAlchemy 2.0 `Mapped` and `mapped_column` type annotations: `User`, `UserProfile`, `PasswordResetToken`, and `RevokedToken`. Configures explicit foreign keys and `cascade="all, delete-orphan"` so deleting a user cleanly removes their child records.

5. **`app/schemas.py`**:
   Defines request validation and response serialization schemas using Pydantic 2.x. Enforces strong password criteria (uppercase, lowercase, number, 8-128 chars), validates email formats, strips whitespace, normalizes emails to lowercase, and uses `from_attributes=True` for ORM conversion without exposing password hashes.

6. **`app/security.py`**:
   Encapsulates all cryptographic operations. Uses `pwdlib` to hash and verify passwords with the memory-hard **Argon2** algorithm. Manages JWT signing, verification, and decoding with PyJWT. Implements SHA-256 token hashing for password resets and timing-safe comparison (`hmac.compare_digest`).

7. **`app/dependencies.py`**:
   Provides FastAPI dependency injection for authentication. Implements `get_current_user` using `OAuth2PasswordBearer`. Checks token expiration, validates the `jti` against the `revoked_tokens` database table, and ensures the user exists and is active.

8. **`app/routers/auth.py` & `app/routers/profile.py`**:
   Thin controller layer that declares HTTP routes, response models, Swagger documentation tags, summaries, and status codes. Delegates all business logic to the service layer.

9. **`app/services/auth_service.py` & `app/services/profile_service.py`**:
   Encapsulates the core business logic separate from HTTP requests. Handles duplicate email/profile detection, credential checks, token revocation, secure password resets, and atomic account deletion.

10. **`alembic/` & `alembic.ini`**:
    Database migration infrastructure. Dynamically connects using `app.config.get_settings().DATABASE_URL` and tracks changes against `Base.metadata`. Contains `001_initial_schema.py`.

11. **`tests/conftest.py`, `tests/test_auth.py`, `tests/test_profile.py`**:
    Comprehensive automated test suite covering 30 scenarios (registration, login, logout, password reset, token revocation, profile CRUD, account deletion, validation errors, and health checks). Uses an in-memory SQLite fixture with full foreign-key support for isolation.

---

## 21. Security Limitations & Production Considerations

1. **Email Delivery**:
   In this assignment, password reset tokens are logged and returned in dev mode (`dev_reset_token`). For production deployment, integrate an SMTP or transactional email provider (such as Amazon SES, SendGrid, or Mailgun) to dispatch tokens exclusively via email.

2. **Revocation Table Cleanup**:
   Over time, the `revoked_tokens` table accumulates expired tokens. In production, schedule a lightweight periodic cron job (e.g. daily) to delete rows where `expires_at < NOW()`.

3. **Rate Limiting**:
   To prevent brute-force attacks against `/api/v1/auth/login` and `/api/v1/auth/forgot-password`, integrate a Redis-backed rate limiter (such as `slowapi`).

4. **HTTPS / TLS**:
   Always terminate TLS (HTTPS) via a reverse proxy (e.g., Nginx, Caddy, or AWS ALB) in production so tokens and passwords are encrypted in transit.
