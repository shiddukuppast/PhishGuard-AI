from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class DashboardStatsResponse(BaseModel):
    total_scanned: int
    phishing_detected: int
    suspicious_detected: int
    legitimate_urls: int
    average_risk_score: float
    detection_rate: float
    trends: Dict[str, str] = Field(default_factory=dict)


class ActivityPoint(BaseModel):
    date: str
    phishing: int
    suspicious: int
    safe: int
    total: int


class DashboardActivityResponse(BaseModel):
    activity: List[ActivityPoint]


class RecentScanItem(BaseModel):
    id: str
    url: str
    domain: str
    classification: str
    risk_score: int
    risk_level: str
    created_at: datetime
    has_https: bool = False


class DashboardRecentScansResponse(BaseModel):
    recent_scans: List[RecentScanItem]

