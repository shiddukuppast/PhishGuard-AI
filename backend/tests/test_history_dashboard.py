import pytest
from datetime import datetime, timezone
from bson import ObjectId


@pytest.mark.asyncio
async def test_history_list_and_ownership(client, registered_user, mock_db):
    # 1. Populate mock scans: 2 for registered_user, 1 for other_user
    user_id = str(registered_user["_id"])
    other_id = str(ObjectId())
    now = datetime.now(timezone.utc)

    await mock_db.scans.insert_one({
        "_id": ObjectId("650000000000000000000010"),
        "user_id": user_id,
        "original_url": "https://stripe.com",
        "domain": "stripe.com",
        "classification": "LEGITIMATE",
        "risk_score": 10,
        "risk_level": "LOW",
        "created_at": now,
    })
    await mock_db.scans.insert_one({
        "_id": ObjectId("650000000000000000000011"),
        "user_id": user_id,
        "original_url": "http://paypal-fake-login.xyz",
        "domain": "paypal-fake-login.xyz",
        "classification": "PHISHING",
        "risk_score": 95,
        "risk_level": "CRITICAL",
        "created_at": now,
    })
    await mock_db.scans.insert_one({
        "_id": ObjectId("650000000000000000000012"),
        "user_id": other_id,  # belonging to someone else
        "original_url": "https://other-user-link.com",
        "domain": "other-user-link.com",
        "classification": "LEGITIMATE",
        "risk_score": 5,
        "risk_level": "LOW",
        "created_at": now,
    })

    # Login as registered_user
    await client.post(
        "/api/v1/auth/login",
        json={"email": "alex.vance@defense-ops.sec", "password": "PhishGuard2026!"},
    )

    # Fetch history
    resp = await client.get("/api/v1/history/")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert len(data["scans"]) == 2
    # Verify other_user's scan is not exposed
    assert all(s["domain"] != "other-user-link.com" for s in data["scans"])


@pytest.mark.asyncio
async def test_history_search_and_filter(client, registered_user, mock_db):
    user_id = str(registered_user["_id"])
    now = datetime.now(timezone.utc)

    await mock_db.scans.insert_one({
        "_id": ObjectId("650000000000000000000020"),
        "user_id": user_id,
        "original_url": "https://apple-security.com",
        "domain": "apple-security.com",
        "classification": "PHISHING",
        "risk_score": 90,
        "risk_level": "CRITICAL",
        "created_at": now,
    })

    await client.post(
        "/api/v1/auth/login",
        json={"email": "alex.vance@defense-ops.sec", "password": "PhishGuard2026!"},
    )

    # Search match
    search_resp = await client.get("/api/v1/history/?search=apple")
    assert search_resp.status_code == 200
    assert len(search_resp.json()["scans"]) == 1

    # Filter match
    filter_resp = await client.get("/api/v1/history/?classification=PHISHING")
    assert filter_resp.status_code == 200
    assert len(filter_resp.json()["scans"]) == 1


@pytest.mark.asyncio
async def test_dashboard_stats_and_activity(client, registered_user, mock_db):
    user_id = str(registered_user["_id"])
    now = datetime.now(timezone.utc)

    await mock_db.scans.insert_one({
        "user_id": user_id,
        "original_url": "https://legit.org",
        "domain": "legit.org",
        "classification": "LEGITIMATE",
        "risk_score": 10,
        "created_at": now,
    })
    await mock_db.scans.insert_one({
        "user_id": user_id,
        "original_url": "http://phish.xyz",
        "domain": "phish.xyz",
        "classification": "PHISHING",
        "risk_score": 90,
        "created_at": now,
    })

    # Login as registered_user
    await client.post(
        "/api/v1/auth/login",
        json={"email": "alex.vance@defense-ops.sec", "password": "PhishGuard2026!"},
    )

    # Stats
    stats_resp = await client.get("/api/v1/dashboard/stats")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["total_scanned"] == 2
    assert stats["phishing_detected"] == 1
    assert stats["legitimate_urls"] == 1
    assert stats["average_risk_score"] == 50.0

    # Activity stream
    activity_resp = await client.get("/api/v1/dashboard/activity")
    assert activity_resp.status_code == 200
    assert len(activity_resp.json()["activity"]) == 7


@pytest.mark.asyncio
async def test_health_check_endpoint(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "database" in data
    assert "ml_model" in data
    assert "threat_intelligence" in data


@pytest.mark.asyncio
async def test_delete_own_scan_success(client, registered_user, mock_db):
    user_id = str(registered_user["_id"])
    now = datetime.now(timezone.utc)
    scan_id = "650000000000000000000030"

    await mock_db.scans.insert_one({
        "_id": ObjectId(scan_id),
        "user_id": user_id,
        "original_url": "https://suspicious-bank-login.net",
        "domain": "suspicious-bank-login.net",
        "classification": "PHISHING",
        "risk_score": 85,
        "risk_level": "HIGH",
        "created_at": now,
    })
    await mock_db.reports.insert_one({
        "_id": ObjectId("650000000000000000000031"),
        "scan_id": scan_id,
        "user_id": user_id,
        "title": "Forensic Phishing Report",
    })

    # Log in as registered user (sets cookie)
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "alex.vance@defense-ops.sec", "password": "PhishGuard2026!"},
    )
    assert login_resp.status_code == 200

    # Delete own scan
    del_resp = await client.delete(f"/api/v1/history/{scan_id}")
    assert del_resp.status_code == 200
    del_data = del_resp.json()
    assert del_data["success"] is True

    # Verify scan is removed from DB
    deleted_scan = await mock_db.scans.find_one({"_id": ObjectId(scan_id)})
    assert deleted_scan is None

    # Verify associated reports are removed from DB
    report = await mock_db.reports.find_one({"scan_id": scan_id})
    assert report is None


@pytest.mark.asyncio
async def test_delete_scan_unauthorized(client, mock_db):
    # No auth cookies or bearer header
    resp = await client.delete("/api/v1/history/650000000000000000000040")
    assert resp.status_code == 401
    assert "credentials" in resp.json()["detail"].lower() or "expired" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_delete_other_user_scan_returns_403(client, registered_user, mock_db):
    other_user_id = str(ObjectId("650000000000000000000099"))
    now = datetime.now(timezone.utc)
    other_scan_id = "650000000000000000000050"

    await mock_db.scans.insert_one({
        "_id": ObjectId(other_scan_id),
        "user_id": other_user_id,
        "original_url": "https://victim-portal.org",
        "domain": "victim-portal.org",
        "classification": "SUSPICIOUS",
        "risk_score": 60,
        "created_at": now,
    })

    # Log in as registered_user (not the owner of other_scan_id)
    await client.post(
        "/api/v1/auth/login",
        json={"email": "alex.vance@defense-ops.sec", "password": "PhishGuard2026!"},
    )

    # Attempt to delete someone else's scan
    del_resp = await client.delete(f"/api/v1/history/{other_scan_id}")
    assert del_resp.status_code == 403
    assert "permission" in del_resp.json()["detail"].lower()

    # Verify scan was NOT deleted
    persisted = await mock_db.scans.find_one({"_id": ObjectId(other_scan_id)})
    assert persisted is not None


@pytest.mark.asyncio
async def test_delete_nonexistent_scan_returns_404(client, registered_user):
    nonexistent_id = "650000000000000000000077"

    await client.post(
        "/api/v1/auth/login",
        json={"email": "alex.vance@defense-ops.sec", "password": "PhishGuard2026!"},
    )

    del_resp = await client.delete(f"/api/v1/history/{nonexistent_id}")
    assert del_resp.status_code == 404
    assert "not found" in del_resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_delete_invalid_scan_id_returns_400(client, registered_user):
    await client.post(
        "/api/v1/auth/login",
        json={"email": "alex.vance@defense-ops.sec", "password": "PhishGuard2026!"},
    )

    del_resp = await client.delete("/api/v1/history/invalid-non-hex-id")
    assert del_resp.status_code == 400
    assert "invalid scan id format" in del_resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_delete_scan_with_bearer_token(client, registered_user, mock_db):
    user_id = str(registered_user["_id"])
    now = datetime.now(timezone.utc)
    scan_id = "650000000000000000000080"

    await mock_db.scans.insert_one({
        "_id": ObjectId(scan_id),
        "user_id": user_id,
        "original_url": "https://bearer-test.com",
        "domain": "bearer-test.com",
        "classification": "LEGITIMATE",
        "risk_score": 10,
        "risk_level": "LOW",
        "created_at": now,
    })

    # Log in and get token from JSON response
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={"email": "alex.vance@defense-ops.sec", "password": "PhishGuard2026!"},
    )
    token = login_resp.json()["token"]

    # Delete scan using Bearer header without cookies
    client.cookies.clear()
    del_resp = await client.delete(
        f"/api/v1/history/{scan_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert del_resp.status_code == 200
    assert del_resp.json()["success"] is True


@pytest.mark.asyncio
async def test_delete_scan_expired_token_returns_401(client, registered_user, mock_db):
    from app.utils.security import create_access_token
    from datetime import timedelta

    user_id = str(registered_user["_id"])
    expired_token = create_access_token(
        data={"sub": user_id, "email": "alex.vance@defense-ops.sec"},
        expires_delta=timedelta(seconds=-10),  # expired 10 seconds ago
    )

    client.cookies.clear()
    del_resp = await client.delete(
        "/api/v1/history/650000000000000000000090",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert del_resp.status_code == 401
    assert "expired" in del_resp.json()["detail"].lower() or "credentials" in del_resp.json()["detail"].lower()

