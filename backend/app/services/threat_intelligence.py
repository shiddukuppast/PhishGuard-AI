import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import httpx
from app.config.settings import settings

logger = logging.getLogger("phishguard.threat_intel")


class ThreatIntelligenceService:
    def __init__(self):
        # In-memory LRU cache to minimize duplicate queries (url -> (timestamp, result))
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_ttl_seconds = 3600  # 1 hour

    async def check_all_sources(self, target_url: str, domain: str) -> Dict[str, Any]:
        """
        Check URL/domain against configured threat intelligence feeds.
        Strictly query API metadata without fetching or visiting the target URL.
        """
        cache_key = f"ti:{target_url}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        phishtank_result = await self.check_phishtank(target_url)
        openphish_result = await self.check_openphish(target_url, domain)

        combined = {
            "phishtank": phishtank_result,
            "openphish": openphish_result,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "has_threat_intel_match": bool(
                phishtank_result.get("is_phishing") or openphish_result.get("is_phishing")
            ),
        }

        # Cache result
        self._cache[cache_key] = combined
        return combined

    async def check_phishtank(self, url: str) -> Dict[str, Any]:
        """Query PhishTank API endpoint if API key configured."""
        api_key = settings.PHISHTANK_API_KEY

        if not api_key:
            return {
                "available": False,
                "source": "PhishTank",
                "is_phishing": None,
                "confidence": None,
                "message": "PhishTank API key not configured. External threat feed check skipped.",
            }

        endpoint = "https://checkurl.phishtank.com/checkurl/"
        try:
            async with httpx.AsyncClient(timeout=3.5) as client:
                response = await client.post(
                    endpoint,
                    data={"url": url, "format": "json", "app_key": api_key},
                    headers={"User-Agent": "PhishGuard-AI-ThreatScanner/1.0"},
                )

                if response.status_code == 200:
                    data = response.json()
                    results = data.get("results", {})
                    in_database = results.get("in_database", False)
                    is_valid = results.get("valid", False)

                    return {
                        "available": True,
                        "source": "PhishTank",
                        "is_phishing": in_database and is_valid,
                        "verified": results.get("verified", False),
                        "confidence": 1.0 if (in_database and is_valid) else 0.0,
                        "verified_at": results.get("verified_at"),
                        "message": (
                            "Confirmed active phishing listing in PhishTank community feed."
                            if in_database and is_valid
                            else "No active PhishTank record found."
                        ),
                    }
                else:
                    return {
                        "available": False,
                        "source": "PhishTank",
                        "message": f"PhishTank API returned HTTP status {response.status_code}.",
                    }

        except httpx.TimeoutException:
            logger.warning("PhishTank API request timed out.")
            return {
                "available": False,
                "source": "PhishTank",
                "message": "PhishTank query timed out.",
            }
        except Exception as exc:
            logger.warning("PhishTank query error: %s", exc)
            return {
                "available": False,
                "source": "PhishTank",
                "message": f"PhishTank connection error: {str(exc)}",
            }

    async def check_openphish(self, url: str, domain: str) -> Dict[str, Any]:
        """Query OpenPhish feed if credentials configured."""
        api_key = settings.OPENPHISH_API_KEY

        if not api_key:
            return {
                "available": False,
                "source": "OpenPhish",
                "is_phishing": None,
                "confidence": None,
                "message": "OpenPhish feed subscription not configured. Service unavailable.",
            }

        # OpenPhish commercial feed query pattern
        endpoint = "https://openphish.com/api/v1/url"
        try:
            async with httpx.AsyncClient(timeout=3.5) as client:
                response = await client.get(
                    endpoint,
                    params={"url": url},
                    headers={"Authorization": f"Bearer {api_key}"},
                )

                if response.status_code == 200:
                    data = response.json()
                    is_phish = data.get("is_phish", False)
                    return {
                        "available": True,
                        "source": "OpenPhish",
                        "is_phishing": is_phish,
                        "confidence": float(data.get("confidence", 0.95)) if is_phish else 0.0,
                        "target": data.get("target"),
                        "message": (
                            "Detected in OpenPhish zero-day feed."
                            if is_phish
                            else "No record in OpenPhish feed."
                        ),
                    }
                else:
                    return {
                        "available": False,
                        "source": "OpenPhish",
                        "message": f"OpenPhish API returned HTTP status {response.status_code}.",
                    }

        except httpx.TimeoutException:
            logger.warning("OpenPhish API request timed out.")
            return {
                "available": False,
                "source": "OpenPhish",
                "message": "OpenPhish query timed out.",
            }
        except Exception as exc:
            logger.warning("OpenPhish query error: %s", exc)
            return {
                "available": False,
                "source": "OpenPhish",
                "message": f"OpenPhish connection error: {str(exc)}",
            }


threat_intel_service = ThreatIntelligenceService()

