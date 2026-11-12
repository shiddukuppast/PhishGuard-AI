from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class SecurityIndicator(BaseModel):
    id: str
    name: str
    status: str  # "safe", "warning", "danger"
    description: str
    severity: str  # "Low", "Medium", "High", "Critical", "Info"
    detected: bool
    technical_detail: Optional[str] = None


class ThreatIntelSourceResult(BaseModel):
    available: bool
    source: str
    is_phishing: Optional[bool] = None
    confidence: Optional[float] = None
    message: str
    verified_at: Optional[str] = None
    raw_details: Optional[Dict[str, Any]] = None


class ModelPredictionDetails(BaseModel):
    available: bool
    model_version: Optional[str] = None
    prediction: Optional[str] = None
    confidence: Optional[float] = None
    features_evaluated: Optional[int] = None
    message: str


class ScanModel(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    user_id: Optional[str] = None
    original_url: str
    normalized_url: str
    domain: str
    classification: str  # "LEGITIMATE", "SUSPICIOUS", "PHISHING"
    risk_score: int  # 0 to 100
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    confidence: Optional[float] = None
    model_prediction: ModelPredictionDetails
    security_indicators: List[SecurityIndicator] = Field(default_factory=list)
    threat_intelligence: Dict[str, Any] = Field(default_factory=dict)
    url_characteristics: Dict[str, Any] = Field(default_factory=dict)
    explanation: str
    recommendations: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)
