"""
PhishGuard AI - URL Analyzer & Feature Extraction Service
=========================================================
Extracts lexical, syntactic, and structural characteristics from target URLs.
Provides the exact 11 ML features for model inference alongside rich heuristic
indicators for the rule-based RiskEngine.

Strictly static analysis - never visits target URLs to prevent SSRF and tracking.
"""

import math
import re
import ipaddress
from collections import Counter
from typing import Dict, Any, List, Tuple, Optional
from urllib.parse import urlparse, parse_qs

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

# High-risk phishing brand patterns for heuristic impersonation checks
SUSPICIOUS_BRANDS = [
    "paypal", "apple", "microsoft", "google", "netflix", "amazon", "chase",
    "wellsfargo", "bankofamerica", "coinbase", "binance", "metamask", "facebook",
    "instagram", "twitter", "dhl", "fedex", "usps", "dropbox", "onedrive"
]

# Extended heuristic keywords for deep risk analysis
EXTENDED_SUSPICIOUS_KEYWORDS = [
    "verify", "verification", "secure", "security", "account", "banking",
    "login", "signin", "auth", "authorize", "update", "confirm", "recovery",
    "wallet", "password", "credential", "validate", "billing", "invoice",
    "free-gift", "claim", "unlock", "suspended", "appeal", "support", "ebayisapi",
    "webscr", "appleid", "microsoft365"
]

# Frequently abused free/disposable TLDs for heuristic flagging
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".buzz", ".work",
    ".rest", ".fit", ".icu", ".club", ".stream", ".gdn", ".monster", ".live"
}

# Recognized URL shortening services
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "goo.gl",
    "rebrand.ly", "cutt.ly", "tiny.cc", "clck.ru", "shorte.st"
}

# Standard benign web ports
STANDARD_PORTS = {80, 443, 8080, 8443, None}

# Special character regex matching training dataset formula: [-_?=&%~+*!$#@]
SPECIAL_CHAR_REGEX = re.compile(r"[-_?=&%~+*!$#@]")

# Ordered list of 11 canonical features required by ML pipeline
CANONICAL_FEATURE_NAMES: List[str] = [
    "url_length",
    "num_dots",
    "has_https",
    "has_ip",
    "num_subdirs",
    "num_params",
    "suspicious_words",
    "tld",
    "special_char_count",
    "digits_count",
    "entropy",
]


class URLAnalyzer:
    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """
        Compute the Shannon entropy of a string (base 2).
        Higher entropy (> 4.2) often indicates obfuscated hashes or generated tokens.
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

    @staticmethod
    def is_ip_address(hostname: str) -> bool:
        """Check if hostname is a raw IPv4 or IPv6 address."""
        if not hostname:
            return False
        host = hostname.strip("[]")
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    @staticmethod
    def count_suspicious_words(url: str, keywords: Optional[List[str]] = None) -> int:
        """
        Count canonical keywords in URL (case-insensitive).
        Canonical method: count of unique canonical keywords present in the URL.
        """
        if not url:
            return 0
        kws = keywords or CANONICAL_KEYWORDS
        url_lower = str(url).lower()
        return sum(1 for kw in kws if kw in url_lower)

    @classmethod
    def extract_tld(cls, raw_url: str, hostname: Optional[str] = None) -> str:
        """
        Extract top-level domain (TLD) as lowercase string without dot.
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

        if cls.is_ip_address(host):
            return "Unknown"

        parts = host.split(".")
        if len(parts) >= 2:
            candidate = parts[-1].lower()
            if candidate.isalpha() and 2 <= len(candidate) <= 24:
                return candidate

        return "Unknown"

    @classmethod
    def normalize_url(cls, raw_url: str) -> Tuple[str, str, str]:
        """
        Normalize URL and extract components without fetching or visiting the target.
        Returns: (normalized_url, hostname, domain)
        """
        cleaned = raw_url.strip() if raw_url else ""
        has_scheme = cleaned.startswith(("http://", "https://"))

        parse_target = cleaned if has_scheme else f"http://{cleaned}"

        parsed = urlparse(parse_target)
        hostname = (parsed.hostname or "").lower()
        normalized_url = parsed.geturl()

        # Extract domain (second-level domain + TLD)
        parts = hostname.split(".")
        if len(parts) >= 2:
            domain = f"{parts[-2]}.{parts[-1]}"
        else:
            domain = hostname

        return normalized_url, hostname, domain

    @classmethod
    def extract_features(cls, raw_url: str) -> Dict[str, Any]:
        """
        Extract complete characteristics:
        - 11 Canonical ML features matching the model training pipeline
        - Comprehensive heuristic indicators for RiskEngine and dashboard UI
        """
        cleaned_url = raw_url.strip() if raw_url else ""
        normalized_url, hostname, domain = cls.normalize_url(cleaned_url)
        parsed = urlparse(normalized_url)

        # -------------------------------------------------------------
        # 11 Canonical ML Features (Identical to training pipeline)
        # -------------------------------------------------------------
        # 1. URL Length (raw cleaned URL length)
        url_length = len(cleaned_url)

        # 2. Number of dots
        num_dots = cleaned_url.count(".")

        # 3. HTTPS protocol detection
        has_https = cleaned_url.lower().startswith("https")

        # 4. Host is raw IP address
        has_ip = cls.is_ip_address(hostname)

        # 5. Number of subdirs (total slashes in URL, matching training formula)
        num_subdirs = cleaned_url.count("/")

        # 6. Number of parameters (from query string)
        query = parsed.query or ""
        num_params = len(query.split("&")) if query else 0

        # 7. Canonical suspicious words count
        suspicious_words = cls.count_suspicious_words(cleaned_url)

        # 8. TLD extraction (with Unknown fallback)
        tld = cls.extract_tld(cleaned_url, hostname)

        # 9. Special characters count (matching training regex)
        special_char_count = len(SPECIAL_CHAR_REGEX.findall(cleaned_url))

        # 10. Digits count
        digits_count = sum(c.isdigit() for c in cleaned_url)

        # 11. Shannon entropy (base 2)
        entropy = cls.calculate_shannon_entropy(cleaned_url)

        # -------------------------------------------------------------
        # Additional Structural & Heuristic Features (for RiskEngine & UI)
        # -------------------------------------------------------------
        domain_length = len(hostname)
        hyphen_count = hostname.count("-")
        at_count = cleaned_url.count("@")

        parts = hostname.split(".") if hostname else []
        subdomain_count = max(0, len(parts) - 2) if len(parts) >= 2 else 0

        try:
            port = parsed.port
        except (ValueError, Exception):
            port = None
        has_suspicious_port = port not in STANDARD_PORTS

        path = parsed.path or ""
        path_segments = [seg for seg in path.split("/") if seg]
        path_depth = len(path_segments)

        params = parse_qs(query)
        param_count = len(params)

        is_shortened = hostname in URL_SHORTENERS

        combined_text = f"{hostname} {path}".replace("-", " ").replace("_", " ").replace(".", " ").lower()
        found_keywords = [kw for kw in EXTENDED_SUSPICIOUS_KEYWORDS if kw in combined_text]

        found_brands = [
            b for b in SUSPICIOUS_BRANDS
            if b in combined_text and not (hostname == f"{b}.com" or hostname.endswith(f".{b}.com"))
        ]

        matched_tld = None
        for s_tld in SUSPICIOUS_TLDS:
            if hostname.endswith(s_tld):
                matched_tld = s_tld
                break

        return {
            # Canonical ML Features
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

            # Heuristic & Backward-Compatible UI Fields
            "original_url": cleaned_url,
            "normalized_url": normalized_url,
            "hostname": hostname,
            "domain": domain,
            "domain_length": domain_length,
            "dot_count": num_dots,
            "hyphen_count": hyphen_count,
            "has_at_symbol": at_count > 0,
            "subdomain_count": subdomain_count,
            "url_entropy": entropy,
            "param_count": param_count,
            "path_depth": path_depth,
            "is_shortened": is_shortened,
            "has_suspicious_port": has_suspicious_port,
            "port": port,
            "suspicious_keywords": len(found_keywords) > 0,
            "suspicious_keywords_list": found_keywords,
            "suspicious_keywords_count": len(found_keywords),
            "brand_impersonation": len(found_brands) > 0,
            "impersonated_brands": found_brands,
            "suspicious_tld": matched_tld is not None,
            "matched_tld": matched_tld,
        }
