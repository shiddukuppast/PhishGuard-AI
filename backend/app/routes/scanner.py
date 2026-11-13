import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, Request, status, HTTPException
from bson import ObjectId
from app.config.settings import settings
from app.config.database import get_db
from app.models.user import UserModel
from app.schemas.scanner import ScanRequest, ScanResponse, MLAnalysisResponse, SecurityIndicatorItem
from app.services.url_analyzer import URLAnalyzer
from app.services.prediction_service import prediction_service
from app.services.threat_intelligence import threat_intel_service
from app.services.risk_engine import RiskEngine
from app.utils.dependencies import get_optional_current_user, limiter

router = APIRouter(prefix="/scanner", tags=["URL Scanner"])


@router.post(
    "/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze and Scan URL",
)
@limiter.limit(settings.RATE_LIMIT_SCAN)
async def scan_url(
    request: Request,
    scan_in: ScanRequest,
    current_user: Optional[UserModel] = Depends(get_optional_current_user),
):
    """
    Perform deep heuristic, structural, and threat intelligence analysis on submitted URL.
    Persists scan record in MongoDB and returns transparent risk evaluation.
    """
    raw_url = scan_in.url

    # 1. Feature extraction & normalization (Static, no SSRF)
    try:
        char = URLAnalyzer.extract_features(raw_url)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unable to parse or extract characteristics from submitted URL: {str(exc)}",
        )

    # 2. ML Prediction (Graceful fallback if model absent)
    ml_result = prediction_service.predict(char)

    # 3. Threat Intelligence Feeds (PhishTank & OpenPhish)
    threat_intel = await threat_intel_service.check_all_sources(
        target_url=char["normalized_url"],
        domain=char["domain"],
    )

    # 4. Risk Assessment Engine synthesis
    (
        risk_score,
        classification,
        risk_level,
        indicators,
        explanation,
        recommendations,
    ) = RiskEngine.evaluate(
        char=char,
        ml_result=ml_result,
        threat_intel=threat_intel,
    )

    now = datetime.now(timezone.utc)
    scan_id = str(ObjectId())
    user_id_val = str(current_user.id) if current_user and current_user.id else None

    # Build DB document
    scan_document = {
        "_id": ObjectId(scan_id),
        "user_id": user_id_val,
        "original_url": char["original_url"],
        "normalized_url": char["normalized_url"],
        "domain": char["domain"],
        "classification": classification,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": ml_result.get("confidence"),
        "phishing_probability": ml_result.get("phishing_probability"),
        "model_prediction": ml_result,
        "security_indicators": [ind.model_dump() for ind in indicators],
        "threat_intelligence": threat_intel,
        "url_characteristics": char,
        "explanation": explanation,
        "recommendations": recommendations,
        "created_at": now,
    }

    # 5. Persist to MongoDB if available
    db = get_db()
    if db is not None:
        try:
            # Check for immediate duplicate submission by the same user within 5 seconds
            query = {
                "original_url": char["original_url"],
                "user_id": user_id_val,
            }
            existing = await db.scans.find_one(query, sort=[("created_at", -1)])
            is_dup = False
            if existing and existing.get("created_at"):
                time_diff = (now - existing["created_at"].replace(tzinfo=timezone.utc)).total_seconds()
                if 0 <= time_diff < 5:
                    is_dup = True
                    scan_id = str(existing["_id"])

            if not is_dup:
                await db.scans.insert_one(scan_document)
        except Exception as exc:
            # If insert fails, log but do not prevent returning scan result to user
            pass

    # 6. Return response
    return ScanResponse(
        success=True,
        scan_id=scan_id,
        url=char["original_url"],
        domain=char["domain"],
        classification=classification,
        risk_score=risk_score,
        risk_level=risk_level,
        ml_analysis=MLAnalysisResponse(
            available=ml_result["available"],
            prediction=ml_result.get("prediction"),
            confidence=ml_result.get("confidence"),
            phishing_probability=ml_result.get("phishing_probability"),
            model_version=ml_result.get("model_version"),
            message=ml_result["message"],
        ),
        security_indicators=[
            SecurityIndicatorItem(
                id=i.id,
                name=i.name,
                status=i.status,
                description=i.description,
                severity=i.severity,
                detected=i.detected,
                technical_detail=i.technical_detail,
            )
            for i in indicators
        ],
        threat_intelligence=threat_intel,
        url_characteristics=char,
        explanation=explanation,
        recommendations=recommendations,
        scanned_at=now,
    )

