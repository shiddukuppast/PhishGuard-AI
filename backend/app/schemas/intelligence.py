from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ThreatFeedItemResponse(BaseModel):
    id: str
    url: str
    domain: str
    target_brand: str
    confidence: float
    source: str
    reported_at: str
    category: str
    ip_address: str
    status: str


class SuspiciousPatternResponse(BaseModel):
    id: str
    pattern: str
    description: str
    frequency: str
    risk_weight: str
    example: str


class ThreatIntelOverviewResponse(BaseModel):
    sources: Dict[str, Dict[str, Any]]
    active_threats_sample: List[ThreatFeedItemResponse]
    suspicious_patterns: List[SuspiciousPatternResponse]
    metrics: Dict[str, Any]

