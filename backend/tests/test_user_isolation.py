import pytest
from datetime import datetime, timezone
from bson import ObjectId
from app.utils.security import hash_password


@pytest.mark.asyncio
async def test_unauthenticated_access_blocked(client):
    """
    Verify that unauthenticated users cannot access protected endpoints
    and receive 401 Unauthorized.
    """
    # Dashboard endpoints
    res_stats = await client.get("/api/v1/dashboard/stats")
    assert res_stats.status_code == 401, f"Expected 401, got {res_stats.status_code}"

    res_recent = await client.get("/api/v1/dashboard/recent-scans")
    assert res_recent.status_code == 401, f"Expected 401, got {res_recent.status_code}"

    res_activity = await client.get("/api/v1/dashboard/activity")
    assert res_activity.status_code == 401, f"Expected 401, got {res_activity.status_code}"

    # History endpoints
    res_history = await client.get("/api/v1/history/")
    assert res_history.status_code == 401, f"Expected 401, got {res_history.status_code}"

    # Reports endpoints
    res_reports = await client.get("/api/v1/reports/")
    assert res_reports.status_code == 401, f"Expected 401, got {res_reports.status_code}"


@pytest.mark.asyncio
async def test_two_user_complete_isolation(client, mock_db):
    """
    Demonstrate complete isolation between two users:
    - User A scans 3 URLs
    - User B scans 2 URLs
    - User A sees only 3 scans; User B sees only 2 scans
    - User B cannot view User A's scan details (403 Forbidden)
    - User B cannot delete User A's scan (403 Forbidden)
    - User B cannot generate a report for User A's scan (403 Forbidden)
    - User B cannot download/access User A's report (403 Forbidden)
    - User B dashboard stats reflect only 2 scans
    - User A dashboard stats reflect only 3 scans
    """
    # 1. Register User A
    res_signup_a = await client.post(
        "/api/v1/auth/signup",
        json={
            "full_name": "User Alpha",
            "email": "usera@example.com",
            "password": "Password123!",
        },
    )
    assert res_signup_a.status_code == 201
    user_a_token = res_signup_a.json()["token"]
    user_a_id = res_signup_a.json()["user"]["id"]
    headers_a = {"Authorization": f"Bearer {user_a_token}"}

    # 2. Register User B
    res_signup_b = await client.post(
        "/api/v1/auth/signup",
        json={
            "full_name": "User Beta",
            "email": "userb@example.com",
            "password": "Password123!",
        },
    )
    assert res_signup_b.status_code == 201
    user_b_token = res_signup_b.json()["token"]
    user_b_id = res_signup_b.json()["user"]["id"]
    headers_b = {"Authorization": f"Bearer {user_b_token}"}

    assert user_a_id != user_b_id

    # 3. User A scans 3 distinct URLs
    urls_a = [
        "https://paypal-fake-login.com",
        "https://legit-stripe.com",
        "https://bank-security-alert.xyz",
    ]
    user_a_scan_ids = []
    for u in urls_a:
        res = await client.post("/api/v1/scanner/scan", json={"url": u}, headers=headers_a)
        assert res.status_code == 200
        user_a_scan_ids.append(res.json()["scan_id"])

    assert len(user_a_scan_ids) == 3

    # 4. User B scans 2 distinct URLs
    urls_b = [
        "https://google-auth-fake.com",
        "https://github-legitimate.com",
    ]
    user_b_scan_ids = []
    for u in urls_b:
        res = await client.post("/api/v1/scanner/scan", json={"url": u}, headers=headers_b)
        assert res.status_code == 200
        user_b_scan_ids.append(res.json()["scan_id"])

    assert len(user_b_scan_ids) == 2

    # 5. Verify User A history has exactly 3 scans
    res_hist_a = await client.get("/api/v1/history/", headers=headers_a)
    assert res_hist_a.status_code == 200
    data_hist_a = res_hist_a.json()
    assert data_hist_a["total"] == 3
    retrieved_ids_a = {s["id"] for s in data_hist_a["scans"]}
    assert retrieved_ids_a == set(user_a_scan_ids)

    # 6. Verify User B history has exactly 2 scans (and 0 of User A's scans)
    res_hist_b = await client.get("/api/v1/history/", headers=headers_b)
    assert res_hist_b.status_code == 200
    data_hist_b = res_hist_b.json()
    assert data_hist_b["total"] == 2
    retrieved_ids_b = {s["id"] for s in data_hist_b["scans"]}
    assert retrieved_ids_b == set(user_b_scan_ids)
    assert retrieved_ids_b.isdisjoint(retrieved_ids_a)

    # 7. User B attempts to access User A's scan details -> 403 Forbidden
    target_scan_a = user_a_scan_ids[0]
    res_cross_get = await client.get(f"/api/v1/history/{target_scan_a}", headers=headers_b)
    assert res_cross_get.status_code == 403, f"Expected 403, got {res_cross_get.status_code}"
    assert "permission" in res_cross_get.json()["detail"].lower()

    # 8. User B attempts to delete User A's scan -> 403 Forbidden
    res_cross_del = await client.delete(f"/api/v1/history/{target_scan_a}", headers=headers_b)
    assert res_cross_del.status_code == 403, f"Expected 403, got {res_cross_del.status_code}"
    assert "permission" in res_cross_del.json()["detail"].lower()

    # Verify User A's scan was NOT deleted
    res_verify_a = await client.get(f"/api/v1/history/{target_scan_a}", headers=headers_a)
    assert res_verify_a.status_code == 200
    assert res_verify_a.json()["id"] == target_scan_a

    # 9. User B attempts to create a report from User A's scan -> 403 Forbidden
    res_cross_rep = await client.post(
        "/api/v1/reports/",
        json={"scan_id": target_scan_a},
        headers=headers_b,
    )
    assert res_cross_rep.status_code == 403, f"Expected 403, got {res_cross_rep.status_code}"

    res_cross_rep_gen = await client.post(
        f"/api/v1/reports/generate/{target_scan_a}",
        headers=headers_b,
    )
    assert res_cross_rep_gen.status_code == 403, f"Expected 403, got {res_cross_rep_gen.status_code}"

    # 10. User B attempts to download User A's scan as report -> 403 Forbidden
    res_cross_pdf = await client.get(
        f"/api/v1/reports/{target_scan_a}/download",
        headers=headers_b,
    )
    assert res_cross_pdf.status_code == 403, f"Expected 403, got {res_cross_pdf.status_code}"

    # 11. Dashboard metrics isolation:
    # User B's dashboard stats must reflect ONLY User B's 2 scans
    res_dash_stats_b = await client.get("/api/v1/dashboard/stats", headers=headers_b)
    assert res_dash_stats_b.status_code == 200
    stats_b = res_dash_stats_b.json()
    assert stats_b["total_scanned"] == 2

    # User B's recent scans must contain only User B's 2 scans
    res_dash_recent_b = await client.get("/api/v1/dashboard/recent-scans", headers=headers_b)
    assert res_dash_recent_b.status_code == 200
    recent_b = res_dash_recent_b.json()["recent_scans"]
    assert len(recent_b) == 2
    for item in recent_b:
        assert item["id"] in user_b_scan_ids
        assert item["id"] not in user_a_scan_ids

    # User A's dashboard stats must reflect ONLY User A's 3 scans
    res_dash_stats_a = await client.get("/api/v1/dashboard/stats", headers=headers_a)
    assert res_dash_stats_a.status_code == 200
    stats_a = res_dash_stats_a.json()
    assert stats_a["total_scanned"] == 3

    # 12. User A successfully deletes one of their own scans
    res_del_a = await client.delete(f"/api/v1/history/{target_scan_a}", headers=headers_a)
    assert res_del_a.status_code == 200

    # User A now has 2 scans
    res_hist_a_after = await client.get("/api/v1/history/", headers=headers_a)
    assert res_hist_a_after.json()["total"] == 2

    # User B still has 2 scans intact
    res_hist_b_after = await client.get("/api/v1/history/", headers=headers_b)
    assert res_hist_b_after.json()["total"] == 2


@pytest.mark.asyncio
async def test_legacy_unowned_scan_isolation(client, mock_db):
    """
    Verify that unowned or legacy records with user_id: None cannot be
    accessed, deleted, or retrieved by any logged-in user.
    """
    # 1. Seed an unowned scan directly into DB (simulating legacy data)
    unowned_id = ObjectId("650000000000000000000099")
    await mock_db.scans.insert_one({
        "_id": unowned_id,
        "user_id": None,
        "legacy_unowned": True,
        "quarantined": True,
        "original_url": "https://legacy-unowned-test.com",
        "domain": "legacy-unowned-test.com",
        "classification": "LEGITIMATE",
        "risk_score": 10,
        "risk_level": "LOW",
        "created_at": datetime.now(timezone.utc),
    })

    # 2. Register User C
    res_signup = await client.post(
        "/api/v1/auth/signup",
        json={
            "full_name": "User Charlie",
            "email": "userc@example.com",
            "password": "Password123!",
        },
    )
    token = res_signup.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. User C history must NOT include the unowned scan
    res_hist = await client.get("/api/v1/history/", headers=headers)
    assert res_hist.status_code == 200
    assert res_hist.json()["total"] == 0

    # 4. User C cannot access the unowned scan details (403 Forbidden)
    res_get = await client.get(f"/api/v1/history/{str(unowned_id)}", headers=headers)
    assert res_get.status_code == 403

    # 5. User C cannot delete the unowned scan (403 Forbidden)
    res_del = await client.delete(f"/api/v1/history/{str(unowned_id)}", headers=headers)
    assert res_del.status_code == 403

    # 6. User C dashboard stats shows 0 (unowned scan is ignored)
    res_stats = await client.get("/api/v1/dashboard/stats", headers=headers)
    assert res_stats.json()["total_scanned"] == 0
