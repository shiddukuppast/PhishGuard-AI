import pytest
from datetime import datetime, timezone
from bson import ObjectId


@pytest.mark.asyncio
async def test_report_generation_and_pdf_download(client, registered_user, mock_db):
    user_id = str(registered_user["_id"])
    scan_id = str(ObjectId("650000000000000000000050"))
    now = datetime.now(timezone.utc)

    # Insert a scan record in mock_db
    await mock_db.scans.insert_one({
        "_id": ObjectId(scan_id),
        "user_id": user_id,
        "original_url": "http://secure-account-verification.example.test",
        "domain": "secure-account-verification.example.test",
        "classification": "PHISHING",
        "risk_score": 92,
        "risk_level": "CRITICAL",
        "model_prediction": {
            "available": False,
            "message": "Model evaluated through rule-based heuristics engine.",
        },
        "security_indicators": [
            {
                "id": "https",
                "name": "HTTPS Protocol",
                "status": "danger",
                "severity": "High",
                "detected": True,
                "description": "Insecure plaintext HTTP protocol",
            }
        ],
        "threat_intelligence": {
            "phishtank": {"message": "Service unconfigured"},
            "openphish": {"message": "Service unconfigured"},
        },
        "explanation": "High-risk deceptive token chaining detected on target hostname.",
        "recommendations": ["Avoid entering credentials on this website."],
        "created_at": now,
    })

    # Authenticate
    await client.post(
        "/api/v1/auth/login",
        json={"email": "alex.vance@defense-ops.sec", "password": "PhishGuard2026!"},
    )

    # 1. Create Report
    create_resp = await client.post("/api/v1/reports/", json={"scan_id": scan_id})
    assert create_resp.status_code == 201
    report_data = create_resp.json()
    assert report_data["scan_id"] == scan_id
    report_id = report_data["id"]

    # 2. List Reports
    list_resp = await client.get("/api/v1/reports/")
    assert list_resp.status_code == 200
    assert list_resp.json()["total"] == 1

    # 3. Get Report metadata
    get_resp = await client.get(f"/api/v1/reports/{report_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == report_id

    # 4. Download PDF
    download_resp = await client.get(f"/api/v1/reports/{report_id}/download")
    assert download_resp.status_code == 200
    assert download_resp.headers["content-type"] == "application/pdf"
    assert "attachment; filename=" in download_resp.headers["content-disposition"]
    # PDF magic bytes
    assert download_resp.content.startswith(b"%PDF")

