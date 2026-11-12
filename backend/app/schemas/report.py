from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class CreateReportRequest(BaseModel):
    scan_id: str


class ReportResponse(BaseModel):
    id: str
    user_id: str
    scan_id: str
    report_data: Dict[str, Any]
    created_at: datetime


class ReportListItem(BaseModel):
    id: str
    scan_id: str
    title: str
    target_url: str
    domain: str
    classification: str
    risk_score: int
    risk_level: str
    created_at: datetime
    file_size_estimate: str
    status: str = "Ready"


class ReportListResponse(BaseModel):
    reports: List[ReportListItem]
    total: int

