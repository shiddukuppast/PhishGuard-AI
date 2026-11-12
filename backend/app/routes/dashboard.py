from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from app.config.database import get_db
from app.models.user import UserModel
from app.schemas.dashboard import (
    DashboardStatsResponse,
    DashboardActivityResponse,
    ActivityPoint,
    DashboardRecentScansResponse,
    RecentScanItem,
)
from app.utils.dependencies import get_optional_current_user

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get(
    "/stats",
    response_model=DashboardStatsResponse,
    status_code=status.HTTP_200_OK,
    summary="Dashboard Overview Metrics",
)
async def get_dashboard_stats(
    current_user: Optional[UserModel] = Depends(get_optional_current_user),
):
    """
    Calculate dynamic security metrics from real MongoDB scan records.
    Filters by user if authenticated, or system totals for guest overview.
    """
    db = get_db()
    if db is None:
        # Graceful default when DB is offline
        return DashboardStatsResponse(
            total_scanned=0,
            phishing_detected=0,
            suspicious_detected=0,
            legitimate_urls=0,
            average_risk_score=0.0,
            detection_rate=0.0,
            trends={"scanned": "+0%", "phishing": "+0%", "safe": "+0%"},
        )

    # Filter query: if user is logged in, show user's stats; if none, show all scans
    match_query: Dict[str, Any] = {"user_id": current_user.id} if current_user else {}

    # Aggregation for counts by classification and average score
    pipeline = [
        {"$match": match_query},
        {
            "$group": {
                "_id": "$classification",
                "count": {"$sum": 1},
                "avg_score": {"$avg": "$risk_score"},
            }
        },
    ]

    cursor = db.scans.aggregate(pipeline)
    counts = {"PHISHING": 0, "SUSPICIOUS": 0, "LEGITIMATE": 0}
    scores = []

    async for doc in cursor:
        cls_name = doc["_id"]
        if cls_name in counts:
            counts[cls_name] = doc["count"]
        if doc.get("avg_score") is not None:
            scores.append(doc["avg_score"] * doc["count"])

    total = sum(counts.values())
    phishing = counts["PHISHING"]
    suspicious = counts["SUSPICIOUS"]
    legitimate = counts["LEGITIMATE"]

    avg_score = round(sum(scores) / total, 1) if total > 0 else 0.0
    detection_rate = round((phishing / total) * 100, 1) if total > 0 else 0.0

    return DashboardStatsResponse(
        total_scanned=total,
        phishing_detected=phishing,
        suspicious_detected=suspicious,
        legitimate_urls=legitimate,
        average_risk_score=avg_score,
        detection_rate=detection_rate,
        trends={
            "scanned": f"+{total}" if total > 0 else "0",
            "phishing": f"+{phishing}" if phishing > 0 else "0",
            "safe": f"+{legitimate}" if legitimate > 0 else "0",
        },
    )


@router.get(
    "/activity",
    response_model=DashboardActivityResponse,
    status_code=status.HTTP_200_OK,
    summary="7-Day Threat Activity Stream",
)
async def get_dashboard_activity(
    current_user: Optional[UserModel] = Depends(get_optional_current_user),
):
    """
    Return rolling 7-day scan activity grouped by day from actual MongoDB records.
    """
    now = datetime.now(timezone.utc)
    # Generate past 7 day keys formatted as 'MMM DD'
    days = [(now - timedelta(days=i)) for i in range(6, -1, -1)]
    day_labels = [d.strftime("%b %d") for d in days]
    day_start = datetime(days[0].year, days[0].month, days[0].day, 0, 0, 0, tzinfo=timezone.utc)

    db = get_db()
    activity_map = {lbl: {"phishing": 0, "suspicious": 0, "safe": 0, "total": 0} for lbl in day_labels}

    if db is not None:
        match_query: Dict[str, Any] = {"created_at": {"$gte": day_start}}
        if current_user:
            match_query["user_id"] = current_user.id

        cursor = db.scans.find(match_query, {"created_at": 1, "classification": 1})
        async for doc in cursor:
            dt = doc.get("created_at")
            if isinstance(dt, datetime):
                label = dt.strftime("%b %d")
                if label in activity_map:
                    cls_name = doc.get("classification", "")
                    activity_map[label]["total"] += 1
                    if cls_name == "PHISHING":
                        activity_map[label]["phishing"] += 1
                    elif cls_name == "SUSPICIOUS":
                        activity_map[label]["suspicious"] += 1
                    else:
                        activity_map[label]["safe"] += 1

    # Format result list
    points = [
        ActivityPoint(
            date=lbl,
            phishing=activity_map[lbl]["phishing"],
            suspicious=activity_map[lbl]["suspicious"],
            safe=activity_map[lbl]["safe"],
            total=activity_map[lbl]["total"],
        )
        for lbl in day_labels
    ]

    return DashboardActivityResponse(activity=points)


@router.get(
    "/recent-scans",
    response_model=DashboardRecentScansResponse,
    status_code=status.HTTP_200_OK,
    summary="Recent Analyzed URLs",
)
async def get_dashboard_recent_scans(
    current_user: Optional[UserModel] = Depends(get_optional_current_user),
):
    """Return the most recent analyzed URLs."""
    db = get_db()
    if db is None:
        return DashboardRecentScansResponse(recent_scans=[])

    match_query: Dict[str, Any] = {"user_id": current_user.id} if current_user else {}
    cursor = db.scans.find(match_query).sort([("created_at", -1)]).limit(6)

    recent = []
    async for doc in cursor:
        recent.append(
            RecentScanItem(
                id=str(doc["_id"]),
                url=doc.get("original_url", ""),
                domain=doc.get("domain", ""),
                classification=doc.get("classification", "LEGITIMATE"),
                risk_score=doc.get("risk_score", 0),
                risk_level=doc.get("risk_level", "LOW"),
                created_at=doc.get("created_at", datetime.now(timezone.utc)),
                has_https=doc.get("url_characteristics", {}).get("has_https", False),
            )
        )

    return DashboardRecentScansResponse(recent_scans=recent)

