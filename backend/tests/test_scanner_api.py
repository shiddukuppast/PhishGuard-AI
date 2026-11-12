import pytest


@pytest.mark.asyncio
async def test_scanner_api_guest_scan(client, mock_db):
    response = await client.post(
        "/api/v1/scanner/scan",
        json={"url": "https://stripe.com/docs"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "scan_id" in data
    assert data["domain"] == "stripe.com"
    assert data["classification"] in ("LEGITIMATE", "SUSPICIOUS", "PHISHING")
    assert 0 <= data["risk_score"] <= 100
    assert "ml_analysis" in data
    assert "security_indicators" in data
    assert len(data["security_indicators"]) == 6
    assert "threat_intelligence" in data
    assert len(data["recommendations"]) > 0


@pytest.mark.asyncio
async def test_scanner_api_phishing_url(client, mock_db):
    response = await client.post(
        "/api/v1/scanner/scan",
        json={"url": "http://secure-account-verification.example.test"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "PHISHING"
    assert data["risk_score"] >= 61
    assert data["risk_level"] in ("HIGH", "CRITICAL")


@pytest.mark.asyncio
async def test_scanner_api_invalid_url(client):
    # Empty URL
    resp1 = await client.post("/api/v1/scanner/scan", json={"url": "   "})
    assert resp1.status_code == 422

    # Malicious script pseudo-scheme
    resp2 = await client.post("/api/v1/scanner/scan", json={"url": "javascript:alert(1)"})
    assert resp2.status_code == 422


@pytest.mark.asyncio
async def test_scanner_api_authenticated_persists_user_id(client, registered_user, mock_db):
    # Login
    login_resp = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "alex.vance@defense-ops.sec",
            "password": "PhishGuard2026!",
        },
    )
    assert login_resp.status_code == 200

    # Scan
    scan_resp = await client.post(
        "/api/v1/scanner/scan",
        json={"url": "https://github.com/login"},
    )
    assert scan_resp.status_code == 200
    data = scan_resp.json()
    scan_id = data["scan_id"]

    # Verify MongoDB record has user_id
    from bson import ObjectId
    saved_doc = await mock_db.scans.find_one({"_id": ObjectId(scan_id)})
    assert saved_doc is not None
    assert saved_doc["user_id"] == str(registered_user["_id"])

