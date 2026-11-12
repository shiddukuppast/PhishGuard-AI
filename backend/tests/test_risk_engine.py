import pytest
from app.services.url_analyzer import URLAnalyzer
from app.services.risk_engine import RiskEngine


def test_risk_engine_legitimate_url():
    char = URLAnalyzer.extract_features("https://github.com/security")
    ml_result = {"available": False, "prediction": None, "confidence": None}
    threat_intel = {"has_threat_intel_match": False}

    score, classification, level, indicators, explanation, recs = RiskEngine.evaluate(
        char=char,
        ml_result=ml_result,
        threat_intel=threat_intel,
    )

    assert score <= 30
    assert classification == "LEGITIMATE"
    assert level == "LOW"
    assert len(indicators) == 6
    assert any(ind.name == "HTTPS Protocol" and ind.status == "safe" for ind in indicators)
    assert len(recs) > 0


def test_risk_engine_obvious_phishing():
    char = URLAnalyzer.extract_features("http://secure-account-verification.example.test")
    ml_result = {"available": False, "prediction": None, "confidence": None}
    threat_intel = {"has_threat_intel_match": False}

    score, classification, level, indicators, explanation, recs = RiskEngine.evaluate(
        char=char,
        ml_result=ml_result,
        threat_intel=threat_intel,
    )

    assert score >= 61
    assert classification == "PHISHING"
    assert level in ("HIGH", "CRITICAL")
    # Verify flagged indicators
    assert any(ind.name == "HTTPS Protocol" and ind.status == "danger" for ind in indicators)
    assert any(ind.name == "Suspicious Keywords" and ind.status == "danger" for ind in indicators)
    assert "personal information" in recs[0].lower() or "credentials" in recs[0].lower()


def test_risk_engine_threat_intel_match_escalation():
    char = URLAnalyzer.extract_features("https://unverified-domain.com")
    ml_result = {"available": False}
    threat_intel = {"has_threat_intel_match": True}

    score, classification, level, indicators, explanation, recs = RiskEngine.evaluate(
        char=char,
        ml_result=ml_result,
        threat_intel=threat_intel,
    )

    assert score >= 90
    assert classification == "PHISHING"
    assert level == "CRITICAL"
    assert "Threat Intelligence" in explanation or "threat intelligence" in explanation.lower()

