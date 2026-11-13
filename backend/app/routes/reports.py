from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from bson import ObjectId
from app.config.database import get_db
from app.models.user import UserModel
from app.schemas.report import CreateReportRequest, ReportResponse, ReportListItem, ReportListResponse
from app.services.report_service import ReportService
from app.utils.dependencies import get_current_user

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post(
    "/",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Report from Scan",
)
async def create_report(
    req: CreateReportRequest,
    current_user: UserModel = Depends(get_current_user),
):
    """Generate and persist an incident report record from an existing scan ID."""
    db = get_db()
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service is unavailable.",
        )

    try:
        scan_obj_id = ObjectId(req.scan_id)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid scan ID format.",
        )

    scan_doc = await db.scans.find_one({"_id": scan_obj_id})
    if not scan_doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Referenced scan record not found.",
        )

    scan_owner = scan_doc.get("user_id")
    if not scan_owner or str(scan_owner) != str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to generate reports for this scan record.",
        )

    # Convert ObjectId to string
    scan_doc["id"] = str(scan_doc["_id"])
    del scan_doc["_id"]

    now = datetime.now(timezone.utc)
    report_doc = {
        "user_id": str(current_user.id),
        "scan_id": req.scan_id,
        "report_data": scan_doc,
        "created_at": now,
    }

    result = await db.reports.insert_one(report_doc)
    report_id_str = str(result.inserted_id)

    return ReportResponse(
        id=report_id_str,
        user_id=str(current_user.id),
        scan_id=req.scan_id,
        report_data=scan_doc,
        created_at=now,
    )


@router.post(
    "/generate/{scan_id}",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate Report for Scan ID",
)
async def generate_report_for_scan(
    scan_id: str,
    current_user: UserModel = Depends(get_current_user),
):
    """Generate report directly using path scan_id parameter."""
    return await create_report(CreateReportRequest(scan_id=scan_id), current_user)


@router.get(
    "/",
    response_model=ReportListResponse,
    status_code=status.HTTP_200_OK,
    summary="List User Reports",
)
async def list_reports(current_user: UserModel = Depends(get_current_user)):
    """List all security analysis reports created by or belonging to the authenticated user."""
    db = get_db()
    if db is None:
        return ReportListResponse(reports=[], total=0)

    cursor = db.reports.find({"user_id": str(current_user.id)}).sort([("created_at", -1)])
    reports_list = []

    async for doc in cursor:
        scan_info = doc.get("report_data", {})
        domain = scan_info.get("domain", "unknown")
        reports_list.append(
            ReportListItem(
                id=str(doc["_id"]),
                scan_id=doc.get("scan_id", ""),
                title=f"Incident Analysis: {domain}",
                target_url=scan_info.get("original_url", ""),
                domain=domain,
                classification=scan_info.get("classification", "LEGITIMATE"),
                risk_score=scan_info.get("risk_score", 0),
                risk_level=scan_info.get("risk_level", "LOW"),
                created_at=doc.get("created_at", datetime.now(timezone.utc)),
                file_size_estimate="184 KB",
                status="Ready",
            )
        )

    return ReportListResponse(reports=reports_list, total=len(reports_list))


@router.get(
    "/{report_id}",
    response_model=ReportResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Report Metadata",
)
async def get_report(
    report_id: str,
    current_user: UserModel = Depends(get_current_user),
):
    """Retrieve report information by report ID with strict user isolation."""
    db = get_db()
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service is unavailable.",
        )

    # 1. Look for report by ObjectId
    existing_report = None
    try:
        report_obj_id = ObjectId(report_id)
        existing_report = await db.reports.find_one({"_id": report_obj_id})
    except Exception:
        pass

    # 2. Look for report by scan_id
    if not existing_report:
        existing_report = await db.reports.find_one({"scan_id": report_id})

    if existing_report:
        if str(existing_report.get("user_id")) != str(current_user.id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this report.",
            )
        return ReportResponse(
            id=str(existing_report["_id"]),
            user_id=str(existing_report.get("user_id", "")),
            scan_id=existing_report.get("scan_id", ""),
            report_data=existing_report.get("report_data", {}),
            created_at=existing_report.get("created_at", datetime.now(timezone.utc)),
        )

    # 3. Fallback: check if report_id is a scan ID belonging to the user
    try:
        scan_obj = ObjectId(report_id)
        scan_doc = await db.scans.find_one({"_id": scan_obj})
        if scan_doc:
            if not scan_doc.get("user_id") or str(scan_doc.get("user_id")) != str(current_user.id):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You do not have permission to access this scan record.",
                )
            scan_doc["id"] = str(scan_doc["_id"])
            del scan_doc["_id"]
            pdf_buffer = ReportService.generate_pdf_report(scan_doc)
            filename = f"PhishGuard-Report-{report_id}.pdf"
            return StreamingResponse(
                pdf_buffer,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f"attachment; filename={filename}",
                    "Cache-Control": "no-cache",
                },
            )
    except HTTPException:
        raise
    except Exception:
        pass

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Report or scan record not found.",
    )


@router.get(
    "/{report_id}/download",
    status_code=status.HTTP_200_OK,
    summary="Download PDF Report",
)
@router.get(
    "/{report_id}/pdf",
    status_code=status.HTTP_200_OK,
    summary="Download PDF Report Stream",
)
async def download_pdf_report(
    report_id: str,
    current_user: UserModel = Depends(get_current_user),
):
    """Generate and stream a downloadable PDF report strictly for the owner."""
    db = get_db()
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service is unavailable.",
        )

    existing_report = None
    try:
        report_obj_id = ObjectId(report_id)
        existing_report = await db.reports.find_one({"_id": report_obj_id})
    except Exception:
        pass

    if not existing_report:
        existing_report = await db.reports.find_one({"scan_id": report_id})

    if existing_report:
        if str(existing_report.get("user_id")) != str(current_user.id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to download this report.",
            )
        scan_data = existing_report.get("report_data", {})
        scan_data["id"] = existing_report.get("scan_id")

        pdf_buffer = ReportService.generate_pdf_report(scan_data)
        filename = f"PhishGuard-Report-{report_id}.pdf"

        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Cache-Control": "no-cache",
            },
        )

    # Check if report_id is a scan ID
    try:
        scan_obj = ObjectId(report_id)
        scan_doc = await db.scans.find_one({"_id": scan_obj})
        if scan_doc:
            if not scan_doc.get("user_id") or str(scan_doc.get("user_id")) != str(current_user.id):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You do not have permission to download reports for this scan.",
                )
            scan_doc["id"] = str(scan_doc["_id"])
            del scan_doc["_id"]
            pdf_buffer = ReportService.generate_pdf_report(scan_doc)
            filename = f"PhishGuard-Report-{report_id}.pdf"
            return StreamingResponse(
                pdf_buffer,
                media_type="application/pdf",
                headers={
                    "Content-Disposition": f"attachment; filename={filename}",
                    "Cache-Control": "no-cache",
                },
            )
    except HTTPException:
        raise
    except Exception:
        pass

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Report or scan record not found.",
    )

