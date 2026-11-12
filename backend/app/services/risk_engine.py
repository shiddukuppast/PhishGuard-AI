from typing import Dict, Any, List, Tuple
from app.models.scan import SecurityIndicator


# Well-known benign domains to calibrate baseline
KNOWN_BENIGN_DOMAINS = {
    "google.com", "github.com", "microsoft.com", "stripe.com", "apple.com",
    "amazon.com", "netflix.com", "vercel.com", "linear.app", "cloudflare.com",
    "python.org", "fastapi.tiangolo.com", "mongodb.com", "recharts.org",
}


class RiskEngine:
    @classmethod
    def evaluate(
        cls,
        char: Dict[str, Any],
        ml_result: Dict[str, Any],
        threat_intel: Dict[str, Any],
    ) -> Tuple[int, str, str, List[SecurityIndicator], str, List[str]]:
        """
        Synthesize heuristic signals, machine learning output, and threat intelligence.
        Returns:
            (risk_score, classification, risk_level, indicators, explanation, recommendations)
        """
        score = 5  # Base minimal score for any web address
        flag_reasons: List[str] = []

        hostname = char.get("hostname", "")
        domain = char.get("domain", "")
        url_length = char.get("url_length", 0)
        has_https = char.get("has_https", False)
        has_ip = char.get("has_ip", False)
        has_at_symbol = char.get("has_at_symbol", False)
        subdomain_count = char.get("subdomain_count", 0)
        hyphen_count = char.get("hyphen_count", 0)
        special_char_count = char.get("special_char_count", 0)
        suspicious_keywords_list = char.get("suspicious_keywords_list", [])
        impersonated_brands = char.get("impersonated_brands", [])
        matched_tld = char.get("matched_tld")
        is_shortened = char.get("is_shortened", False)
        has_suspicious_port = char.get("has_suspicious_port", False)

        # -------------------------------------------------------------
        # 1. Threat Intelligence Overrides (Highest Priority Ground Truth)
        # -------------------------------------------------------------
        ti_phish_found = threat_intel.get("has_threat_intel_match", False)
        if ti_phish_found:
            score = max(score, 95)
            flag_reasons.append("Target matched active malicious signature in connected Threat Intelligence feeds.")

        # -------------------------------------------------------------
        # 2. Heuristic Structural Penalties
        # -------------------------------------------------------------
        # Protocol
        if not has_https:
            score += 20
            flag_reasons.append("Insecure plaintext HTTP protocol without TLS encryption.")

        # Direct IP hostname
        if has_ip:
            score += 45
            flag_reasons.append("Destination uses a raw numerical IP address host bypassing domain reputation.")

        # Brand impersonation
        if impersonated_brands:
            score += 35
            brands_str = ", ".join(b.upper() for b in impersonated_brands[:2])
            flag_reasons.append(f"Probable brand impersonation targeting [{brands_str}].")

        # Suspicious keywords
        if suspicious_keywords_list:
            kw_penalty = min(35, len(suspicious_keywords_list) * 12)
            score += kw_penalty
            kw_str = ", ".join(suspicious_keywords_list[:4])
            flag_reasons.append(f"Found credential harvesting / urgent keywords: [{kw_str}].")

        # Disposable / Abused TLD
        if matched_tld:
            score += 25
            flag_reasons.append(f"Domain registered under high-abuse TLD ({matched_tld}).")

        # Deep subdomain nesting
        if subdomain_count >= 3:
            score += 18
            flag_reasons.append(f"Abnormally deep subdomain hierarchy ({subdomain_count} levels).")
        elif subdomain_count == 2:
            score += 8

        # Multiple hyphens
        if hyphen_count >= 2:
            score += 15
            flag_reasons.append(f"Excessive hyphen chaining ({hyphen_count} hyphens) suggesting typosquatting.")

        # @ symbol credential spoofing
        if has_at_symbol:
            score += 30
            flag_reasons.append("URL contains '@' delimiter, commonly utilized in HTTP authority obfuscation.")

        # URL length > 75 characters
        if url_length > 75:
            score += 12
            flag_reasons.append(f"Excessive URL length ({url_length} characters).")

        # Unusual port
        if has_suspicious_port and char.get("port") is not None:
            score += 15
            flag_reasons.append(f"Destination runs on atypical web port ({char.get('port')}).")

        # URL shortener masking
        if is_shortened:
            score += 15
            flag_reasons.append("Destination uses a URL shortening redirection service that masks destination host.")

        # -------------------------------------------------------------
        # 3. Machine Learning Adjustment (When Available)
        # -------------------------------------------------------------
        ml_available = ml_result.get("available", False)
        if ml_available:
            pred = ml_result.get("prediction", "")
            conf = ml_result.get("confidence") or 0.5
            if pred == "PHISHING":
                score = max(score, int(70 + conf * 25))
                flag_reasons.append(f"Machine learning classification model flagged URL as PHISHING (confidence: {conf:.1%}).")
            elif pred == "LEGITIMATE" and conf > 0.85:
                # Moderate score downward if ML is strongly confident legitimate AND no IP or threat intel hit
                if not has_ip and not ti_phish_found and not impersonated_brands:
                    score = min(score, 25)

        # -------------------------------------------------------------
        # 4. Benign Domain Calibration
        # -------------------------------------------------------------
        is_known_safe = any(hostname == d or hostname.endswith(f".{d}") for d in KNOWN_BENIGN_DOMAINS)
        if is_known_safe and not has_ip and not ti_phish_found and not suspicious_keywords_list:
            score = min(score, 12)
            flag_reasons = []

        # Clamp score between 0 and 100
        final_score = min(99, max(3, score))

        # -------------------------------------------------------------
        # 5. Risk Level and Classification
        # -------------------------------------------------------------
        if final_score >= 81:
            risk_level = "CRITICAL"
            classification = "PHISHING"
        elif final_score >= 61:
            risk_level = "HIGH"
            classification = "PHISHING"
        elif final_score >= 31:
            risk_level = "MEDIUM"
            classification = "SUSPICIOUS"
        else:
            risk_level = "LOW"
            classification = "LEGITIMATE"

        # -------------------------------------------------------------
        # 6. Structured Security Indicators
        # -------------------------------------------------------------
        indicators = [
            SecurityIndicator(
                id="url-length",
                name="URL Length",
                status="warning" if url_length > 75 else "safe",
                severity="Medium" if url_length > 75 else "Low",
                detected=url_length > 75,
                description=(
                    f"Length is {url_length} characters (threshold is 75 chars)"
                    if url_length > 75
                    else f"Normal URL length ({url_length} characters)"
                ),
                technical_detail=f"{url_length} characters total",
            ),
            SecurityIndicator(
                id="https-protocol",
                name="HTTPS Protocol",
                status="safe" if has_https else "danger",
                severity="Low" if has_https else "High",
                detected=not has_https,
                description=(
                    "TLS/SSL cryptographic session detected on target"
                    if has_https
                    else "Not detected — plaintext HTTP connection transmits without encryption"
                ),
                technical_detail="TLS Active" if has_https else "Cleartext HTTP",
            ),
            SecurityIndicator(
                id="ip-address",
                name="IP Address Usage",
                status="danger" if has_ip else "safe",
                severity="Critical" if has_ip else "Low",
                detected=has_ip,
                description=(
                    "Raw numerical IP host detected bypassing standard public DNS names"
                    if has_ip
                    else "Not detected — valid standard domain name hierarchy utilized"
                ),
                technical_detail=f"Host: {hostname}" if has_ip else "Standard FQDN",
            ),
            SecurityIndicator(
                id="suspicious-keywords",
                name="Suspicious Keywords",
                status="danger" if suspicious_keywords_list else "safe",
                severity="High" if len(suspicious_keywords_list) > 1 else ("Medium" if suspicious_keywords_list else "Low"),
                detected=len(suspicious_keywords_list) > 0,
                description=(
                    f"Detected urgency/credential markers: [{', '.join(suspicious_keywords_list[:4])}]"
                    if suspicious_keywords_list
                    else "Not detected — no deceptive authentication or urgency tokens found"
                ),
                technical_detail=", ".join(suspicious_keywords_list) if suspicious_keywords_list else "None",
            ),
            SecurityIndicator(
                id="domain-structure",
                name="Domain Structure",
                status="danger" if (subdomain_count >= 2 or hyphen_count >= 2 or matched_tld) else "safe",
                severity="High" if (subdomain_count >= 2 or hyphen_count >= 2) else "Low",
                detected=bool(subdomain_count >= 2 or hyphen_count >= 2 or matched_tld),
                description=(
                    f"Suspicious ({subdomain_count} subdomains, {hyphen_count} hyphens{f', TLD: {matched_tld}' if matched_tld else ''})"
                    if (subdomain_count >= 2 or hyphen_count >= 2 or matched_tld)
                    else "Standard second-level domain structure and hierarchy"
                ),
                technical_detail=f"{subdomain_count} subdomains, {hyphen_count} hyphens",
            ),
            SecurityIndicator(
                id="special-characters",
                name="Special Characters",
                status="danger" if (has_at_symbol or special_char_count > 2) else "safe",
                severity="Critical" if has_at_symbol else ("Medium" if special_char_count > 2 else "Low"),
                detected=bool(has_at_symbol or special_char_count > 2),
                description=(
                    f"Detected ({'@ symbol present; ' if has_at_symbol else ''}{special_char_count} special characters)"
                    if (has_at_symbol or special_char_count > 2)
                    else "Not detected — standard RFC 3986 URL characters"
                ),
                technical_detail=f"@={has_at_symbol}, special={special_char_count}",
            ),
        ]

        # -------------------------------------------------------------
        # 7. Explanation & Recommendations
        # -------------------------------------------------------------
        if final_score >= 61:
            reasons_summary = "; ".join(flag_reasons[:2]) if flag_reasons else "anomalous characteristics"
            explanation = (
                f"The URL was classified as {classification} due to {reasons_summary}. "
                "These structural and heuristic anomalies indicate deceptive impersonation or credential harvesting."
            )
        elif final_score >= 31:
            explanation = (
                f"The URL exhibits moderate risk signals ({'; '.join(flag_reasons[:2]) if flag_reasons else 'minor anomalies'}). "
                "While not definitively confirmed as malicious, exercise elevated caution."
            )
        else:
            explanation = (
                "No critical phishing indicators or deceptive domain characteristics were identified. "
                "The destination conforms to standard web conventions."
            )

        # Explicit notice regarding ML status
        if not ml_available:
            explanation += " (Note: Machine learning inference was unavailable; assessment computed via rule-based heuristic checks.)"

        recommendations = []
        if final_score >= 61:
            recommendations.append("Do not enter login credentials, passwords, or personal identity details on this website.")
            recommendations.append("Do not download or execute attachments from this destination.")
            recommendations.append("Verify the official organization domain independently through bookmarks or corporate directories.")
            recommendations.append("Report the URL to your enterprise Security Operations Center (SOC) or IT security team.")
        elif final_score >= 31:
            recommendations.append("Inspect the destination SSL/TLS certificate details before interacting.")
            recommendations.append("Confirm the authenticity of the link with the originating sender.")
            recommendations.append("Avoid providing two-factor codes or financial payment methods.")
        else:
            recommendations.append("Standard web browsing security hygiene applies.")
            recommendations.append("Keep your browser software and endpoint security extensions updated.")

        return final_score, classification, risk_level, indicators, explanation, recommendations

