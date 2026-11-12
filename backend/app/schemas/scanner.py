from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, field_validator


class ScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url_string(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("URL cannot be empty.")
        if len(cleaned) > 2048:
            raise ValueError("URL exceeds maximum length of 2048 characters.")
        # Reject control characters and dangerous protocol schemes
        lower = cleaned.lower()
        if lower.startswith(("javascript:", "data:", "file:", "vbscript:", "blob:")):
            raise ValueError("Unsupported or insecure URL protocol scheme.")
        return cleaned


class SecurityIndicatorItem(BaseModel):
    id: str
    name: str
    status: str  # "safe", "warning", "danger"
    description: str
    severity: str  # "Low", "Medium", "High", "Critical", "Info"
    detected: bool
    technical_detail: Optional[str] = None


class MLAnalysisResponse(BaseModel):
    available: bool
    prediction: Optional[str] = None  # "LEGITIMATE", "SUSPICIOUS", "PHISHING"
    confidence: Optional[float] = None
    model_version: Optional[str] = None
    message: str


class ScanResponse(BaseModel):
    success: bool = True
    scan_id: str
    url: str
    domain: str
    classification: str  # "LEGITIMATE", "SUSPICIOUS", "PHISHING"
    risk_score: int  # 0 to 100
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    ml_analysis: MLAnalysisResponse
    security_indicators: List[SecurityIndicatorItem] = Field(default_factory=list)
    threat_intelligence: Dict[str, Any] = Field(default_factory=dict)
    url_characteristics: Dict[str, Any] = Field(default_factory=dict)
    explanation: str
    recommendations: List[str] = Field(default_factory=list)
    scanned_at: datetime

