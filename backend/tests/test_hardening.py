from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from app.services.threat_intelligence import ThreatIntelligenceService
from app.services.url_analyzer import URLAnalyzer


@pytest.mark.asyncio
@pytest.mark.parametrize('url', [
    'https://', 'http:///path', 'ftp://example.com', 'javascript:alert(1)',
    'https://example.com:bad', 'https://example.com:99999',
    'https://example.com/\nlogin', 'https://bad host.com',
    'https://example.com\\@evil.test', 'https://[broken', '%%%%%',
])
@pytest.mark.parametrize('endpoint', ['/scanner/scan', '/intelligence/check'])
async def test_invalid_urls_rejected(client, url, endpoint):
    response = await client.post('/api/v1' + endpoint, json={'url': url})
    assert response.status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize('url', [
    'example.com/path', 'HTTPS://EXAMPLE.COM/login', 'localhost:8000/path',
    'example.com/path?next=https://other.example', 'localhost:8000?query=1',
    'https://[::1]:8080/path', 'http://trusted.com@evil.test/login',
])
async def test_valid_and_suspicious_urls_remain_scannable(client, url):
    response = await client.post('/api/v1/scanner/scan', json={'url': url})
    assert response.status_code == 200


def test_https_requires_actual_scheme():
    assert URLAnalyzer.extract_features('HTTPS://EXAMPLE.COM')['has_https'] is True
    assert URLAnalyzer.extract_features('https-pretender.example')['has_https'] is False


@pytest.mark.asyncio
async def test_invalid_session_does_not_create_guest_scan(client, mock_db):
    response = await client.post('/api/v1/scanner/scan', json={'url': 'https://example.com'},
                                 headers={'Authorization': 'Bearer invalid'})
    assert response.status_code == 401
    assert mock_db.scans.docs == []


@pytest.mark.asyncio
async def test_public_feed_requires_explicit_publication(client, mock_db):
    for owner, published, name in [('private-user', True, 'private'), (None, False, 'guest'),
                                   (None, True, 'published')]:
        await mock_db.scans.insert_one({
            'user_id': owner, 'public_feed': published,
            'classification': 'PHISHING', 'original_url': f'https://{name}.example',
            'domain': f'{name}.example', 'risk_score': 90,
            'created_at': datetime.now(timezone.utc),
            'threat_intelligence': {'phishtank': {'is_phishing': True}},
            'url_characteristics': {'suspicious_keywords': True, 'suspicious_keywords_list': ['login']},
        })
    data = (await client.get('/api/v1/intelligence/overview')).json()
    assert [item['domain'] for item in data['active_threats_sample']] == ['published.example']
    assert data['metrics']['tracked_campaigns'] == 1
    assert data['metrics']['heuristic_accuracy_pct'] is None
    assert data['metrics']['avg_lure_lifespan_hours'] is None


@pytest.mark.asyncio
async def test_threat_cache_expiration_eviction_and_copy(monkeypatch):
    service = ThreatIntelligenceService()
    service._cache_max_entries = 2
    service.check_phishtank = AsyncMock(return_value={'available': True, 'is_phishing': False})
    service.check_openphish = AsyncMock(return_value={'available': True, 'is_phishing': False})
    clock = [100.0]
    monkeypatch.setattr('app.services.threat_intelligence.time.monotonic', lambda: clock[0])
    result = await service.check_all_sources('a', 'a')
    result['phishtank']['is_phishing'] = True
    assert not (await service.check_all_sources('a', 'a'))['phishtank']['is_phishing']
    assert service.check_phishtank.await_count == 1
    await service.check_all_sources('b', 'b')
    await service.check_all_sources('a', 'a')
    await service.check_all_sources('c', 'c')
    assert 'ti:b' not in service._cache
    clock[0] += 3601
    await service.check_all_sources('a', 'a')
    assert service.check_phishtank.await_count == 4


@pytest.mark.asyncio
async def test_history_search_is_literal(client):
    await client.post('/api/v1/auth/signup', json={
        'full_name': 'Test Analyst', 'email': 'analyst@example.com', 'password': 'Password123!',
    })
    await client.post('/api/v1/scanner/scan', json={'url': 'https://example.com/path'})
    for search in ['.*', '[', '(a+)+$']:
        response = await client.get('/api/v1/history/', params={'search': search})
        assert response.status_code == 200
        assert response.json()['total'] == 0
    response = await client.get('/api/v1/history/', params={'search': 'example.com'})
    assert response.json()['total'] == 1


def test_pdf_treats_submitted_markup_as_text():
    from app.services.report_service import ReportService
    pdf = ReportService.generate_pdf_report({
        'original_url': 'https://example.com/<img src="file:///missing">?a=1&b=2',
        'domain': 'example.com', 'explanation': '<broken> & explanation',
        'recommendations': ['<broken> & recommendation'],
        'security_indicators': [{'name': '<broken>', 'description': '<img src="missing">'}],
    })
    assert pdf.getvalue().startswith(b'%PDF')
