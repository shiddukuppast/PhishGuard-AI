"""
Unit Tests for Machine Learning Prediction Service
==================================================
Verifies:
- Model artifact loading
- Feature ordering & DataFrame column alignment
- Sample URL prediction with confidence output
- ML-unavailable fallback & graceful degradation
- Diagnostic subsystem status
"""

import os
import pytest
import pandas as pd
from app.services.prediction_service import PredictionService, CANONICAL_FEATURE_NAMES
from app.services.url_analyzer import URLAnalyzer


def test_prediction_service_missing_model():
    """Requirement 10: ML-unavailable fallback when model artifact is absent."""
    service = PredictionService(model_path="non_existent_model_artifact.pkl")
    loaded = service.load_model()

    assert loaded is False
    assert service.is_loaded is False

    status = service.get_status()
    assert status["available"] is False
    assert "not found" in status["message"].lower()

    # Inference call with unavailable model should gracefully degrade without crashing
    result = service.predict({"url_length": 50, "has_https": True})
    assert result["available"] is False
    assert result["prediction"] is None
    assert result["confidence"] is None
    assert "unavailable" in result["message"].lower()


def test_production_model_loading():
    """Requirement 6: Model artifact loading from model/artifacts/phishing_model.pkl."""
    service = PredictionService()
    loaded = service.load_model()

    assert loaded is True
    assert service.is_loaded is True
    assert service.model is not None
    assert len(service.feature_names) == 11
    assert set(service.feature_names) == set(CANONICAL_FEATURE_NAMES)

    status = service.get_status()
    assert status["available"] is True
    assert status["features_count"] == 11
    assert "ready" in status["message"].lower()


def test_feature_ordering_and_dataframe_alignment():
    """Requirement 5: Feature ordering and DataFrame alignment with ColumnTransformer."""
    service = PredictionService()
    assert service.load_model() is True

    # Build feature row from test URL
    char = URLAnalyzer.extract_features("https://github.com/torvalds/linux")
    row = service._build_feature_row(char)

    # Check all 11 canonical keys are present
    for key in CANONICAL_FEATURE_NAMES:
        assert key in row

    # Convert to DataFrame
    df = pd.DataFrame([row])
    assert list(df.columns) == CANONICAL_FEATURE_NAMES

    # Ensure model's ColumnTransformer transforms it without error
    preprocessor = service.model.named_steps["preprocessor"]
    transformed = preprocessor.transform(df)
    assert transformed.shape[0] == 1
    assert transformed.shape[1] > 10  # Scaled numericals + OneHot encoded TLDs


def test_sample_url_prediction_inference():
    """Requirement 7: Prediction for a sample URL with confidence and probability."""
    service = PredictionService()
    assert service.load_model() is True

    # 1. Benign sample URL
    benign_char = URLAnalyzer.extract_features("https://stripe.com/docs/api/payment_intents")
    benign_result = service.predict(benign_char)

    assert benign_result["available"] is True
    assert benign_result["prediction"] in ("LEGITIMATE", "PHISHING")
    assert isinstance(benign_result["confidence"], float)
    assert 0.0 <= benign_result["confidence"] <= 1.0
    assert benign_result["features_evaluated"] == 11
    assert "model_version" in benign_result

    # 2. Suspicious sample URL
    suspicious_char = URLAnalyzer.extract_features(
        "http://192.168.1.100/paypal-update/verification/login.php?session=92834&secure=true"
    )
    suspicious_result = service.predict(suspicious_char)

    assert suspicious_result["available"] is True
    assert suspicious_result["prediction"] in ("LEGITIMATE", "PHISHING")
    assert isinstance(suspicious_result["confidence"], float)
    assert 0.0 <= suspicious_result["confidence"] <= 1.0
    assert suspicious_result["features_evaluated"] == 11


def test_prediction_service_error_resilience():
    """Verify inference gracefully handles invalid feature types without crashing."""
    service = PredictionService()
    assert service.load_model() is True

    # Empty dict
    res_empty = service.predict({})
    assert res_empty["available"] is True
    assert res_empty["prediction"] in ("LEGITIMATE", "PHISHING")

    # Degenerate values
    res_degen = service.predict({
        "url_length": "invalid_str",
        "tld": None,
        "has_https": "not_a_bool"
    })
    assert res_degen["available"] is True
