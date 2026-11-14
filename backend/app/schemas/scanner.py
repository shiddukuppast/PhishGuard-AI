from datetime import datetime
from typing import Optional, List, Dict, Any
import re
import ipaddress
from urllib.parse import urlsplit
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
        if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in cleaned) or "\\" in cleaned:
            raise ValueError("URL contains whitespace, control characters, or backslashes.")
        # Bare hosts are accepted; explicit schemes must be HTTP(S).
        target = cleaned
        if not re.match(r"^https?://", target, re.IGNORECASE):
            if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:(?![0-9]+(?:[/?#]|$))", target):
                raise ValueError("Only HTTP and HTTPS URLs are supported.")
            target = "http://" + target
        try:
            parsed = urlsplit(target)
            host = parsed.hostname
            port = parsed.port  # Validate malformed and out-of-range ports.
            if not host or (parsed.netloc.endswith(":") and port is None):
                raise ValueError("URL must contain a valid host.")
            try:
                ipaddress.ip_address(host)
            except ValueError:
                ascii_host = host.encode("idna").decode("ascii").rstrip(".")
                if len(ascii_host) > 253 or not all(
                    re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                    for label in ascii_host.split(".")
                ):
                    raise ValueError("URL must contain a valid host.")
        except (ValueError, UnicodeError) as exc:
            raise ValueError("URL must contain a valid host and port.") from exc
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
    phishing_probability: Optional[float] = None
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

