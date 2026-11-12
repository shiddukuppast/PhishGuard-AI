import pytest
from app.services.threat_intelligence import ThreatIntelligenceService


@pytest.mark.asyncio
async def test_threat_intel_unconfigured_keys():
    service = ThreatIntelligenceService()

    # Query with unset keys
    result = await service.check_all_sources("https://example.com", "example.com")

    assert "phishtank" in result
    assert "openphish" in result
    assert result["phishtank"]["available"] is False
    assert result["openphish"]["available"] is False
    assert result["has_threat_intel_match"] is False
    assert "not configured" in result["phishtank"]["message"].lower()

    # Query again to verify caching
    cached_result = await service.check_all_sources("https://example.com", "example.com")
    assert cached_result == result

