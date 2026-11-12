"""
PhishGuard AI - Canonical Feature Extraction Module
===================================================
Provides deterministic, static feature extraction for URL phishing detection.
Used by both ML training/evaluation pipelines and FastAPI runtime inference.

Strictly static analysis - never executes outbound network requests (no SSRF).
"""

import math
import re
import ipaddress
from collections import Counter
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

# 15 Canonical suspicious keywords established in dataset audit
CANONICAL_KEYWORDS: List[str] = [
    "login",
    "verify",
    "update",
    "password",
    "secure",
    "banking",
    "account",
    "signin",
    "confirm",
    "wallet",
    "paypal",
    "credential",
    "authenticate",
    "suspended",
    "recover",
]

# Exact feature ordering expected by ML models
NUMERICAL_FEATURES: List[str] = [
    "url_length",
    "num_dots",
    "has_https",
    "has_ip",
    "num_subdirs",
    "num_params",
    "suspicious_words",
    "special_char_count",
    "digits_count",
    "entropy",
]

CATEGORICAL_FEATURES: List[str] = ["tld"]

CANONICAL_FEATURE_NAMES: List[str] = NUMERICAL_FEATURES + CATEGORICAL_FEATURES

# Regex for special characters in lexical analysis: [-_?=&%~+*!$#@]
SPECIAL_CHAR_REGEX = re.compile(r"[-_?=&%~+*!$#@]")


def is_ip_address(hostname: str) -> bool:
    """Check if hostname is a valid IPv4 or IPv6 address."""
    if not hostname:
        return False
    host = hostname.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def calculate_shannon_entropy(text: str) -> float:
    """
    Compute Shannon entropy with base 2.
    Entropy = -sum(p * log2(p))
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def count_suspicious_words(url: str, keywords: Optional[List[str]] = None) -> int:
    """
    Count matching canonical keywords in lowercased URL.
    Canonical method: count of unique canonical keywords present in the URL.
    """
    if not url:
        return 0
    kws = keywords or CANONICAL_KEYWORDS
    url_lower = str(url).lower()
    return sum(1 for kw in kws if kw in url_lower)


def extract_tld(raw_url: str, hostname: Optional[str] = None) -> str:
    """
    Extract top-level domain (TLD) from a URL or hostname.
    Returns 'Unknown' if missing, invalid, or an IP address.
    """
    if not raw_url and not hostname:
        return "Unknown"

    host = hostname
    if not host:
        cleaned = str(raw_url).strip()
        if not cleaned.startswith(("http://", "https://")):
            cleaned = "http://" + cleaned
        try:
            parsed = urlparse(cleaned)
            host = (parsed.hostname or "").lower()
        except Exception:
            return "Unknown"

    if not host:
        return "Unknown"

    # Direct IP addresses do not have TLDs
    if is_ip_address(host):
        return "Unknown"

    parts = host.split(".")
    if len(parts) >= 2:
        candidate = parts[-1].lower()
        if candidate.isalpha() and 2 <= len(candidate) <= 24:
            return candidate

    return "Unknown"


def extract_canonical_features(raw_url: str) -> Dict[str, Any]:
    """
    Extract the exact 11 features matching the ML training pipeline.
    Safe for any URL format without outbound HTTP requests.
    """
    cleaned_url = str(raw_url).strip() if raw_url else ""
    if not cleaned_url:
        return {
            "url_length": 0,
            "num_dots": 0,
            "has_https": 0,
            "has_ip": 0,
            "num_subdirs": 0,
            "num_params": 0,
            "suspicious_words": 0,
            "tld": "Unknown",
            "special_char_count": 0,
            "digits_count": 0,
            "entropy": 0.0,
        }

    # 1. URL Length
    url_length = len(cleaned_url)

    # 2. Dot count
    num_dots = cleaned_url.count(".")

    # 3. HTTPS protocol detection
    has_https = 1 if cleaned_url.lower().startswith("https") else 0

    # Parsing for hostname, IP, and query
    parse_target = cleaned_url if cleaned_url.lower().startswith(("http://", "https://")) else f"http://{cleaned_url}"
    try:
        parsed = urlparse(parse_target)
        hostname = (parsed.hostname or "").lower()
        query = parsed.query or ""
    except Exception:
        hostname = ""
        query = ""

    # 4. Host is raw IP address
    has_ip = 1 if is_ip_address(hostname) else 0

    # 5. Number of subdirectories (counted as slashes in the URL, matching training dataset)
    num_subdirs = cleaned_url.count("/")

    # 6. Number of parameters (from query string)
    num_params = len(query.split("&")) if query else 0

    # 7. Suspicious words count
    suspicious_words = count_suspicious_words(cleaned_url)

    # 8. TLD extraction (with Unknown fallback)
    tld = extract_tld(cleaned_url, hostname)

    # 9. Special character count
    special_char_count = len(SPECIAL_CHAR_REGEX.findall(cleaned_url))

    # 10. Digits count
    digits_count = sum(c.isdigit() for c in cleaned_url)

    # 11. Shannon entropy
    entropy = calculate_shannon_entropy(cleaned_url)

    return {
        "url_length": url_length,
        "num_dots": num_dots,
        "has_https": has_https,
        "has_ip": has_ip,
        "num_subdirs": num_subdirs,
        "num_params": num_params,
        "suspicious_words": suspicious_words,
        "tld": tld,
        "special_char_count": special_char_count,
        "digits_count": digits_count,
        "entropy": entropy,
    }

