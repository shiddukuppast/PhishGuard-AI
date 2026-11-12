import pytest
from app.config.settings import settings


@pytest.mark.asyncio
async def test_user_signup_success(client, mock_db):
    response = await client.post(
        "/api/v1/auth/signup",
        json={
            "full_name": "Marcus Kane",
            "email": "marcus.kane@defense-labs.sec",
            "password": "StrongSecurityPassword123!",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["success"] is True
    assert data["user"]["email"] == "marcus.kane@defense-labs.sec"
    assert data["user"]["full_name"] == "Marcus Kane"
    assert "token" in data
    assert settings.COOKIE_NAME in response.cookies


@pytest.mark.asyncio
async def test_user_signup_duplicate_email(client, registered_user):
    response = await client.post(
        "/api/v1/auth/signup",
        json={
            "full_name": "Duplicate User",
            "email": "alex.vance@defense-ops.sec",  # already in mock_db
            "password": "ValidPassword999!",
        },
    )
    assert response.status_code == 409
    data = response.json()
    assert "already exists" in data["detail"].lower()


@pytest.mark.asyncio
async def test_user_signup_weak_password(client):
    response = await client.post(
        "/api/v1/auth/signup",
        json={
            "full_name": "Test Weak",
            "email": "weak@example.com",
            "password": "weak",
        },
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_user_login_success(client, registered_user):
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "alex.vance@defense-ops.sec",
            "password": "PhishGuard2026!",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["user"]["email"] == "alex.vance@defense-ops.sec"
    assert "token" in data
    assert settings.COOKIE_NAME in response.cookies


@pytest.mark.asyncio
async def test_user_login_invalid_password(client, registered_user):
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "alex.vance@defense-ops.sec",
            "password": "IncorrectPassword123!",
        },
    )
    assert response.status_code == 401
    data = response.json()
    assert "invalid email or password" in data["detail"].lower()


@pytest.mark.asyncio
async def test_user_login_nonexistent_email(client):
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "ghost@nonexistent.domain",
            "password": "SomePassword123!",
        },
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_protected_me_endpoint_with_cookie(client, registered_user):
    # 1. Login to get cookie
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "alex.vance@defense-ops.sec",
            "password": "PhishGuard2026!",
        },
    )
    assert login_resp.status_code == 200

    # 2. Call /me using the session cookie
    me_resp = await client.get("/api/v1/auth/me")
    assert me_resp.status_code == 200
    data = me_resp.json()
    assert data["email"] == "alex.vance@defense-ops.sec"
    assert data["full_name"] == "Alex Vance"


@pytest.mark.asyncio
async def test_protected_me_endpoint_unauthorized(client):
    # Without cookie or token
    response = await client.get("/api/v1/auth/me")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_logout_clears_cookie(client, registered_user):
    # Login first
    await client.post(
        "/api/v1/auth/login",
        json={
            "email": "alex.vance@defense-ops.sec",
            "password": "PhishGuard2026!",
        },
    )

    # Logout
    logout_resp = await client.post("/api/v1/auth/logout")
    assert logout_resp.status_code == 200
    assert logout_resp.json()["success"] is True


@pytest.mark.asyncio
async def test_login_when_database_unavailable_returns_503(client, monkeypatch):
    from app.config.database import db_manager
    monkeypatch.setattr(db_manager, "is_connected", False)
    monkeypatch.setattr(db_manager, "db", None)

    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "test@example.com",
            "password": "ValidPassword123!",
        },
    )
    assert response.status_code == 503
    data = response.json()
    assert "unavailable" in (data.get("detail") or data.get("message", "")).lower()


@pytest.mark.asyncio
async def test_health_check_when_database_disconnected_returns_503(client, monkeypatch):
    from app.config.database import db_manager
    monkeypatch.setattr(db_manager, "is_connected", False)
    monkeypatch.setattr(db_manager, "db", None)

    response = await client.get("/health")
    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "unhealthy"
    assert data["database"]["status"] == "disconnected"
    assert data["database"]["connected"] is False

