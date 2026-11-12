"""
Unit Tests for URLAnalyzer & Canonical Feature Extraction
=========================================================
Verifies:
1. Normal URL feature extraction
2. Suspicious URL feature extraction
3. Missing TLD handling
4. Suspicious keyword counting
5. Invalid URL handling
6. Consistency between training feature extractor and backend URLAnalyzer
"""

import os
import sys
import pytest
from app.services.url_analyzer import URLAnalyzer, CANONICAL_FEATURE_NAMES, CANONICAL_KEYWORDS

# Add model/Code to sys.path to test consistency with training module
MODEL_CODE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "model", "Code"))
if MODEL_CODE_DIR not in sys.path:
    sys.path.insert(0, MODEL_CODE_DIR)

try:
    from feature_extractor import extract_canonical_features, count_suspicious_words as model_count_words
    TRAINING_EXTRACTOR_AVAILABLE = True
except ImportError:
    TRAINING_EXTRACTOR_AVAILABLE = False


def test_benign_url_feature_extraction():
    """Verify normal benign URL extraction."""
    url = "https://stripe.com/docs/api"
    features = URLAnalyzer.extract_features(url)

    assert features["domain"] == "stripe.com"
    assert features["has_https"] is True
    assert features["has_ip"] is False
    assert features["has_at_symbol"] is False
    assert features["dot_count"] == 1
    assert features["hyphen_count"] == 0
    assert features["subdomain_count"] == 0
    assert features["is_shortened"] is False
    assert features["url_entropy"] > 0
    assert isinstance(features["url_length"], int)

    # 11 Canonical ML features
    for key in CANONICAL_FEATURE_NAMES:
        assert key in features
    assert features["tld"] == "com"
    assert features["num_subdirs"] == 4  # https://stripe.com/docs/api -> 4 slashes


def test_ip_address_host_detection():
    """Verify raw IPv4 host detection."""
    url = "http://192.168.1.104/paypal-update/login.php"
    features = URLAnalyzer.extract_features(url)

    assert features["has_ip"] is True
    assert features["has_https"] is False
    assert features["suspicious_keywords"] is True
    assert "paypal" in features["suspicious_keywords_list"] or "login" in features["suspicious_keywords_list"]
    assert "update" in features["suspicious_keywords_list"]
    assert features["tld"] == "Unknown"  # IP address has no TLD


def test_subdomains_and_hyphens_extraction():
    """Verify subdomain and hyphen counting."""
    url = "http://secure-account-verification.example.test/auth"
    features = URLAnalyzer.extract_features(url)

    assert features["hyphen_count"] >= 2
    assert features["has_https"] is False
    assert features["suspicious_keywords"] is True
    assert features["matched_tld"] == ".test" or ".test" in features["normalized_url"]


def test_at_symbol_credential_spoofing():
    """Verify @ symbol detection."""
    url = "http://legit-service.com@malicious-harvest.xyz/login"
    features = URLAnalyzer.extract_features(url)

    assert features["has_at_symbol"] is True
    assert features["matched_tld"] == ".xyz"
    assert features["suspicious_tld"] is True


def test_url_shortener_detection():
    """Verify URL shortener detection."""
    url = "https://bit.ly/secure-redirect-token"
    features = URLAnalyzer.extract_features(url)

    assert features["is_shortened"] is True


def test_shannon_entropy_calculation():
    """Verify Shannon entropy computation."""
    low_entropy = URLAnalyzer.calculate_shannon_entropy("aaaaaaaaaaaa")
    high_entropy = URLAnalyzer.calculate_shannon_entropy("aB9$z!xQ7#mK2@")

    assert low_entropy == 0.0
    assert high_entropy > 3.0


def test_suspicious_url_feature_extraction():
    """Requirement 2: Feature extraction for suspicious-looking URLs."""
    suspicious_url = "http://192.168.1.50/secure-login/paypal/verify.php?token=4f9a&action=update"
    features = URLAnalyzer.extract_features(suspicious_url)

    assert features["has_ip"] is True
    assert features["has_https"] is False
    assert features["tld"] == "Unknown"
    assert features["num_params"] == 2
    assert features["suspicious_words"] >= 3  # secure, login, paypal, verify, update
    assert features["special_char_count"] >= 5


def test_missing_tld_handling():
    """Requirement 3: Missing TLD handling."""
    # 1. Direct IP address
    f_ip = URLAnalyzer.extract_features("http://10.0.0.1/admin/dashboard")
    assert f_ip["tld"] == "Unknown"

    # 2. Localhost
    f_local = URLAnalyzer.extract_features("http://localhost:8000/api")
    assert f_local["tld"] == "Unknown"

    # 3. Empty string
    f_empty = URLAnalyzer.extract_features("")
    assert f_empty["tld"] == "Unknown"


def test_suspicious_keyword_counting():
    """Requirement 4: Suspicious keyword counting using canonical keywords."""
    # Test string with 4 distinct canonical keywords: login, verify, password, paypal
    sample = "https://safe-domain.org/login/verify-password-paypal"
    count = URLAnalyzer.count_suspicious_words(sample)
    assert count == 4

    # Benign URL with 0 keywords
    sample_clean = "https://docs.python.org/3/tutorial/index.html"
    assert URLAnalyzer.count_suspicious_words(sample_clean) == 0


def test_invalid_url_handling():
    """Requirement 9: Invalid URL handling without unhandled exceptions."""
    invalid_cases = [
        "",
        "   ",
        ":::bad-url:::",
        "http:///no-host",
        "https://",
        "%%%%%",
    ]
    for bad in invalid_cases:
        result = URLAnalyzer.extract_features(bad)
        assert isinstance(result, dict)
        assert "url_length" in result
        assert "tld" in result
        assert result["tld"] == "Unknown"


@pytest.mark.skipif(not TRAINING_EXTRACTOR_AVAILABLE, reason="Training feature_extractor module not available")
def test_feature_consistency_between_training_and_backend():
    """Requirement 8: Consistency between training and backend feature extraction."""
    test_urls = [
        "https://www.google.com/search?q=cybersecurity&hl=en",
        "http://phishing-update.tk/banking/login.php?user=admin",
        "http://192.168.1.1:8080/router/firmware",
        "https://metamask-recovery-wallet.io/auth/confirm",
        "http://bare-domain.com",
    ]

    for url in test_urls:
        backend_feat = URLAnalyzer.extract_features(url)
        training_feat = extract_canonical_features(url)

        for col in CANONICAL_FEATURE_NAMES:
            b_val = backend_feat[col]
            t_val = training_feat[col]

            # Allow bool vs 0/1 equivalence
            if col in ("has_https", "has_ip"):
                assert bool(b_val) == bool(t_val), f"Mismatch in {col} for {url}: {b_val} vs {t_val}"
            elif col == "entropy":
                assert abs(b_val - t_val) < 0.001, f"Mismatch in entropy for {url}: {b_val} vs {t_val}"
            else:
                assert b_val == t_val, f"Mismatch in {col} for {url}: {b_val} vs {t_val}"
