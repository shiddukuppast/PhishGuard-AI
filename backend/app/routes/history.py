from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Query, HTTPException, status
from bson import ObjectId
from pymongo import ASCENDING, DESCENDING
from app.config.database import get_db
from app.models.user import UserModel
from app.utils.dependencies import get_current_user

router = APIRouter(prefix="/history", tags=["Scan History"])


@router.get(
    "/",
    status_code=status.HTTP_200_OK,
    summary="List User Scan History",
)
async def list_user_scans(
    current_user: UserModel = Depends(get_current_user),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(10, ge=1, le=100, description="Items per page"),
    search: Optional[str] = Query(None, description="Search domain or URL"),
    classification: Optional[str] = Query(None, description="Filter by LEGITIMATE, SUSPICIOUS, or PHISHING"),
    risk_level: Optional[str] = Query(None, description="Filter by LOW, MEDIUM, HIGH, or CRITICAL"),
    start_date: Optional[str] = Query(None, description="ISO start date filter"),
    end_date: Optional[str] = Query(None, description="ISO end date filter"),
    sort_by: str = Query("created_at", description="Sort by 'created_at' or 'risk_score'"),
    order: str = Query("desc", description="Sort direction 'asc' or 'desc'"),
):
    """
    Retrieve authenticated user's scan history with pagination, search,
    classification filters, and sorting.
    """
    db = get_db()
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service is unavailable.",
        )

    # Base query restricted strictly to current user's records
    query: Dict[str, Any] = {"user_id": str(current_user.id)}

    # Classification filter
    if classification and classification.upper() != "ALL":
        query["classification"] = classification.upper()

    # Risk level filter
    if risk_level and risk_level.upper() != "ALL":
        query["risk_level"] = risk_level.upper()

    # Search filter across url or domain
    if search:
        regex_pattern = {"$regex": search.strip(), "$options": "i"}
        query["$or"] = [
            {"domain": regex_pattern},
            {"original_url": regex_pattern},
            {"normalized_url": regex_pattern},
        ]

    # Date range filters
    date_filter = {}
    if start_date:
        try:
            date_filter["$gte"] = datetime.fromisoformat(start_date.replace("Z", "+00:00"))
        except ValueError:
            pass
    if end_date:
        try:
            date_filter["$lte"] = datetime.fromisoformat(end_date.replace("Z", "+00:00"))
        except ValueError:
            pass
    if date_filter:
        query["created_at"] = date_filter

    # Sort configuration
    sort_field = "risk_score" if sort_by == "risk_score" else "created_at"
    sort_dir = ASCENDING if order.lower() == "asc" else DESCENDING

    skip = (page - 1) * limit

    total_count = await db.scans.count_documents(query)
    cursor = db.scans.find(query).sort([(sort_field, sort_dir)]).skip(skip).limit(limit)

    scans = []
    async for doc in cursor:
        doc["id"] = str(doc["_id"])
        del doc["_id"]
        scans.append(doc)

    return {
        "success": True,
        "scans": scans,
        "page": page,
        "limit": limit,
        "total": total_count,
        "total_pages": max(1, (total_count + limit - 1) // limit),
    }


@router.get(
    "/{scan_id}",
    status_code=status.HTTP_200_OK,
    summary="Get Scan Details",
)
async def get_scan_detail(
    scan_id: str,
    current_user: UserModel = Depends(get_current_user),
):
    """Retrieve complete scan analysis by scan ID for the authenticated owner."""
    db = get_db()
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service is unavailable.",
        )

    try:
        obj_id = ObjectId(scan_id)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid scan ID format.",
        )

    doc = await db.scans.find_one({"_id": obj_id})
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found.",
        )

    scan_owner = doc.get("user_id")
    if not scan_owner or str(scan_owner) != str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to access this scan record.",
        )

    doc["id"] = str(doc["_id"])
    del doc["_id"]
    return doc


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete Scan Record",
)
async def delete_scan(
    scan_id: str,
    current_user: UserModel = Depends(get_current_user),
):
    """Delete a specific scan belonging to the authenticated user."""
    db = get_db()
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service is unavailable.",
        )

    try:
        obj_id = ObjectId(scan_id)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid scan ID format.",
        )

    # 1. Look up the scan record by MongoDB ID
    scan_doc = await db.scans.find_one({"_id": obj_id})
    if not scan_doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found.",
        )

    # 2. Verify that the authenticated user strictly owns this record
    scan_owner = scan_doc.get("user_id")
    if not scan_owner or str(scan_owner) != str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to delete this scan record.",
        )

    # 3. Perform the deletion (strictly scoped by _id and user_id)
    await db.scans.delete_one({"_id": obj_id, "user_id": str(current_user.id)})

    # 4. Clean up any associated reports belonging to this user
    await db.reports.delete_many({"scan_id": scan_id, "user_id": str(current_user.id)})

    return {
        "success": True,
        "message": "Scan record and associated report metadata deleted successfully.",
    }

