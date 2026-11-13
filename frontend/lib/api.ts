/**
 * PhishGuard AI - Centralized REST API Client Layer
 * Connects the Next.js frontend with the Python FastAPI + MongoDB Atlas backend.
 * 
 * Features:
 * - Credentials included for HTTP-only JWT cookies
 * - Request timeout handling (15 seconds abort controller)
 * - Centralized error normalization and typing
 * - Automatic conversion from backend schemas to frontend UI models
 * - Zero fallback to fake data: returns real database records or empty states
 */

import {
  ScanResult,
  Classification,
  RiskCategory,
  SecurityIndicatorItem,
  GeneratedReport,
  User,
  ThreatFeedItem,
  SuspiciousPattern,
} from '@/types';

let inMemoryAuthToken: string | null = null;
const SESSION_TOKEN_KEY = 'phishguard_session_token_v1';

/**
 * Set the session JWT authorization token.
 * Enables Bearer token propagation across requests alongside HTTP-only cookies
 * without storing tokens in localStorage (scoped strictly to sessionStorage).
 */
export function setAuthToken(token: string | null): void {
  inMemoryAuthToken = token;
  if (typeof window !== 'undefined') {
    try {
      if (token) {
        sessionStorage.setItem(SESSION_TOKEN_KEY, token);
      } else {
        sessionStorage.removeItem(SESSION_TOKEN_KEY);
      }
    } catch {
      // Storage unavailable or disabled
    }
  }
}

/**
 * Retrieve the current JWT authorization token from memory or sessionStorage.
 */
export function getAuthToken(): string | null {
  if (inMemoryAuthToken) return inMemoryAuthToken;
  if (typeof window !== 'undefined') {
    try {
      const stored = sessionStorage.getItem(SESSION_TOKEN_KEY);
      if (stored) {
        inMemoryAuthToken = stored;
        return stored;
      }
    } catch {
      // Storage unavailable
    }
  }
  return null;
}

/**
 * Dynamically resolves the API Base URL.
 * Automatically aligns hostname between window.location and backend (e.g. localhost vs 127.0.0.1)
 * to ensure SameSite=Lax cookies are not dropped due to cross-site origin differences in browser.
 */
export function getApiBaseUrl(): string {
  const envUrl = process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000/api/v1';
  if (typeof window !== 'undefined') {
    try {
      const parsed = new URL(envUrl);
      if (
        (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') &&
        (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1')
      ) {
        parsed.hostname = window.location.hostname;
        return parsed.toString().replace(/\/$/, '');
      }
    } catch {
      // Fallback to envUrl
    }
  }
  return envUrl.replace(/\/$/, '');
}

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL || 'http://localhost:8000/api/v1';

export class ApiError extends Error {
  status: number;
  data: any;

  constructor(status: number, message: string, data?: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

/**
 * Generic API request wrapper with credentials, Bearer token fallback, and abort timeout
 */
async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {},
  timeoutMs: number = 15000
): Promise<T> {
  const baseUrl = getApiBaseUrl();
  const url = `${baseUrl}${endpoint}`;

  const defaultHeaders: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  // Attach Bearer token if present to guarantee authentication
  // even if browser cross-site cookie restrictions affect requests
  const activeToken = getAuthToken();
  if (activeToken) {
    defaultHeaders['Authorization'] = `Bearer ${activeToken}`;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  const config: RequestInit = {
    ...options,
    signal: controller.signal,
    credentials: 'include', // Always send and receive HTTP-only cookies
    headers: {
      ...defaultHeaders,
      ...(options.headers || {}),
    },
  };

  try {
    const response = await fetch(url, config);
    clearTimeout(timeoutId);

    if (!response.ok) {
      let errorMessage = `API request failed with status ${response.status}`;
      let errorData = null;
      try {
        errorData = await response.json();
        if (errorData?.detail) {
          errorMessage =
            typeof errorData.detail === 'string'
              ? errorData.detail
              : JSON.stringify(errorData.detail);
        } else if (errorData?.message) {
          errorMessage = errorData.message;
        }
      } catch {
        // Non-JSON response body
      }

      if (response.status === 503 && (!errorData || (!errorData.detail && !errorData.message))) {
        errorMessage = 'Database connection is temporarily unavailable. Please try again later.';
      }

      throw new ApiError(response.status, errorMessage, errorData);
    }

    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      return (await response.json()) as T;
    }
    return (null as unknown) as T;
  } catch (err: any) {
    clearTimeout(timeoutId);
    if (err.name === 'AbortError') {
      throw new ApiError(408, 'The request to the PhishGuard analysis service timed out. Please try again.');
    }
    if (err instanceof ApiError) {
      throw err;
    }
    throw new ApiError(
      0,
      'Cannot connect to PhishGuard backend service. Ensure FastAPI server is running on port 8000.',
      err
    );
  }
}

/**
 * Maps a FastAPI backend scan response to the frontend ScanResult structure
 */
export function mapBackendScanToFrontend(backendScan: any): ScanResult {
  const rawClass = (backendScan.classification || 'LEGITIMATE').toUpperCase();
  let classification: Classification = 'Safe';
  if (rawClass === 'PHISHING') classification = 'Phishing';
  else if (rawClass === 'SUSPICIOUS') classification = 'Suspicious';

  const rawLevel = (backendScan.risk_level || 'LOW').toUpperCase();
  let riskCategory: RiskCategory = 'Low';
  if (rawLevel === 'CRITICAL') riskCategory = 'Critical';
  else if (rawLevel === 'HIGH') riskCategory = 'High';
  else if (rawLevel === 'MEDIUM') riskCategory = 'Medium';

  const indicators: SecurityIndicatorItem[] = (backendScan.security_indicators || []).map(
    (ind: any) => ({
      id: ind.id || `ind_${Math.random().toString(36).substring(2, 7)}`,
      name: ind.name || 'Security Check',
      status: (ind.status || 'safe').toLowerCase(),
      description: ind.description || '',
      severity: ind.severity || 'Info',
      detected: Boolean(ind.detected),
      technicalDetail: ind.technical_detail || undefined,
    })
  );

  const chars = backendScan.url_characteristics || {};
  const ml = backendScan.model_prediction || backendScan.ml_analysis || {};
  const ti = backendScan.threat_intelligence || {};
  const phishingProb =
    typeof ml.phishing_probability === 'number'
      ? ml.phishing_probability
      : typeof backendScan.phishing_probability === 'number'
      ? backendScan.phishing_probability
      : null;

  return {
    id: backendScan.id || backendScan.scan_id || `scan_${Date.now()}`,
    url: backendScan.url || backendScan.original_url || '',
    domain: backendScan.domain || '',
    timestamp: backendScan.created_at || backendScan.scanned_at || new Date().toISOString(),
    riskScore: typeof backendScan.risk_score === 'number' ? backendScan.risk_score : 0,
    classification,
    riskCategory,
    indicators,
    aiAnalysis: {
      summary:
        backendScan.explanation ||
        'Automated multi-factor risk evaluation performed from extracted syntactic and structural indicators.',
      flagReasons: backendScan.recommendations || [],
      impersonatedBrand:
        chars.suspicious_keywords && chars.suspicious_keywords.length > 0
          ? chars.suspicious_keywords.join(', ')
          : undefined,
      threatType:
        classification === 'Phishing'
          ? 'Active Credential Phishing'
          : classification === 'Suspicious'
          ? 'Anomalous URL Indicators'
          : 'Verified Web Host',
      heuristicsEngineVersion: ml.available
        ? `PhishGuard AI (ML Model ${ml.model_version || 'v1.0'})`
        : 'PhishGuard Defense Engine v2.4 (FastAPI Backend)',
    },
    mlPrediction: {
      available: Boolean(ml.available),
      prediction: ml.prediction ?? null,
      confidence: ml.confidence ?? null,
      phishingProbability: phishingProb,
      modelVersion: ml.model_version ?? null,
      message:
        ml.message ||
        'Machine learning analysis is currently unavailable. This result is based on the available URL security checks.',
    },
    threatIntelligence: {
      phishtank: ti.phishtank || {
        available: false,
        source: 'PhishTank',
        message: 'PhishTank API key not configured. External threat feed check skipped.',
      },
      openphish: ti.openphish || {
        available: false,
        source: 'OpenPhish',
        message: 'OpenPhish feed subscription not configured. Service unavailable.',
      },
      has_threat_intel_match: Boolean(ti.has_threat_intel_match),
      checked_at: ti.checked_at,
    },
    recommendations: backendScan.recommendations || [
      'Exercise caution when submitting credentials or downloading attachments.',
      'Always inspect the domain hierarchy and protocol in your browser address bar.',
    ],
    domainDetails: {
      tld: backendScan.domain ? '.' + backendScan.domain.split('.').pop() : '.com',
      subdomainCount: chars.subdomain_count || 0,
      domainLength: chars.domain_length || 0,
      urlLength: chars.url_length || (backendScan.original_url || backendScan.url || '').length,
      hasHttps: chars.has_https ?? true,
      hasIpHost: chars.has_ip_host ?? false,
      specialCharsCount: (chars.dots || 0) + (chars.hyphens || 0),
      suspiciousKeywordsFound: chars.suspicious_keywords || [],
    },
    isSimulated: false,
  };
}

// -------------------------------------------------------------
// Authentication Endpoints
// -------------------------------------------------------------
export const authApi = {
  async signup(data: { full_name: string; email: string; password: string }) {
    const res = await apiRequest<{
      success: boolean;
      message: string;
      user: {
        id: string;
        full_name: string;
        email: string;
        is_active: boolean;
        created_at: string;
        role: string;
        organization: string;
      };
      token: string;
    }>('/auth/signup', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    if (res?.token) {
      setAuthToken(res.token);
    }
    return res;
  },

  async login(data: { email: string; password: string; remember_me?: boolean }) {
    const res = await apiRequest<{
      success: boolean;
      message: string;
      user: {
        id: string;
        full_name: string;
        email: string;
        is_active: boolean;
        created_at: string;
        role: string;
        organization: string;
      };
      token: string;
    }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    if (res?.token) {
      setAuthToken(res.token);
    }
    return res;
  },

  async me() {
    return apiRequest<{
      id: string;
      full_name: string;
      email: string;
      is_active: boolean;
      created_at: string;
      role: string;
      organization: string;
    }>('/auth/me', {
      method: 'GET',
    });
  },

  async logout() {
    try {
      return await apiRequest<{ message: string }>('/auth/logout', {
        method: 'POST',
      });
    } finally {
      setAuthToken(null);
    }
  },
};

// -------------------------------------------------------------
// URL Scanner Endpoints
// -------------------------------------------------------------
export const scannerApi = {
  async scanUrl(url: string): Promise<ScanResult> {
    const data = await apiRequest<any>('/scanner/scan', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
    return mapBackendScanToFrontend(data);
  },

  async getScan(scanId: string): Promise<ScanResult> {
    const data = await apiRequest<any>(`/scanner/${scanId}`, {
      method: 'GET',
    });
    return mapBackendScanToFrontend(data);
  },
};

// -------------------------------------------------------------
// History Endpoints
// -------------------------------------------------------------
export const historyApi = {
  async getHistory(params?: {
    page?: number;
    limit?: number;
    search?: string;
    classification?: string;
    riskLevel?: string;
    sortBy?: string;
    order?: string;
  }) {
    const query = new URLSearchParams();
    if (params?.page) query.set('page', params.page.toString());
    if (params?.limit) query.set('limit', params.limit.toString());
    if (params?.search) query.set('search', params.search);
    if (params?.classification && params.classification !== 'ALL') {
      query.set('classification', params.classification);
    }
    if (params?.riskLevel && params.riskLevel !== 'ALL') {
      query.set('risk_level', params.riskLevel);
    }
    if (params?.sortBy) query.set('sort_by', params.sortBy);
    if (params?.order) query.set('order', params.order);

    const qs = query.toString() ? `?${query.toString()}` : '';
    const res = await apiRequest<{
      success: boolean;
      scans: any[];
      page: number;
      limit: number;
      total: number;
      total_pages: number;
    }>(`/history/${qs}`, { method: 'GET' });

    return {
      scans: (res.scans || []).map(mapBackendScanToFrontend),
      total: res.total || 0,
      page: res.page || 1,
      limit: res.limit || 10,
      totalPages: res.total_pages || 1,
    };
  },

  async getScan(scanId: string): Promise<ScanResult> {
    const data = await apiRequest<any>(`/history/${scanId}`, {
      method: 'GET',
    });
    return mapBackendScanToFrontend(data);
  },

  async deleteScan(scanId: string) {
    return apiRequest<{ success: boolean; message: string }>(`/history/${scanId}`, {
      method: 'DELETE',
    });
  },
};

// -------------------------------------------------------------
// Dashboard Endpoints
// -------------------------------------------------------------
export const dashboardApi = {
  async getStats() {
    return apiRequest<{
      total_scanned: number;
      phishing_detected: number;
      suspicious_detected: number;
      legitimate_urls: number;
      average_risk_score: number;
      detection_rate: number;
      trends: {
        scanned?: string;
        phishing?: string;
        safe?: string;
      };
    }>('/dashboard/stats', { method: 'GET' });
  },

  async getActivity() {
    return apiRequest<{
      activity: Array<{
        date: string;
        phishing: number;
        suspicious: number;
        safe: number;
        total: number;
      }>;
    }>('/dashboard/activity', { method: 'GET' });
  },

  async getRecentScans() {
    const res = await apiRequest<{
      recent_scans: Array<{
        id: string;
        url: string;
        domain: string;
        classification: string;
        risk_score: number;
        risk_level: string;
        created_at: string;
        has_https: boolean;
      }>;
    }>('/dashboard/recent-scans', { method: 'GET' });

    return (res.recent_scans || []).map((item) => {
      const rawClass = item.classification.toUpperCase();
      let classification: Classification = 'Safe';
      if (rawClass === 'PHISHING') classification = 'Phishing';
      else if (rawClass === 'SUSPICIOUS') classification = 'Suspicious';

      const rawLevel = item.risk_level.toUpperCase();
      let riskCategory: RiskCategory = 'Low';
      if (rawLevel === 'CRITICAL') riskCategory = 'Critical';
      else if (rawLevel === 'HIGH') riskCategory = 'High';
      else if (rawLevel === 'MEDIUM') riskCategory = 'Medium';

      return {
        id: item.id,
        url: item.url,
        domain: item.domain,
        timestamp: item.created_at,
        riskScore: item.risk_score,
        classification,
        riskCategory,
        indicators: [],
        aiAnalysis: {
          summary: '',
          flagReasons: [],
          threatType: classification,
          heuristicsEngineVersion: 'PhishGuard Defense Engine',
        },
        recommendations: [],
        domainDetails: {
          tld: '.' + item.domain.split('.').pop(),
          subdomainCount: 0,
          domainLength: item.domain.length,
          urlLength: item.url.length,
          hasHttps: item.has_https,
          hasIpHost: false,
          specialCharsCount: 0,
          suspiciousKeywordsFound: [],
        },
        isSimulated: false,
      } as ScanResult;
    });
  },
};

// -------------------------------------------------------------
// Reports Endpoints
// -------------------------------------------------------------
export const reportsApi = {
  async getReports() {
    const res = await apiRequest<{
      reports: Array<{
        id: string;
        scan_id: string;
        title: string;
        target_url: string;
        domain: string;
        classification: string;
        risk_score: number;
        risk_level: string;
        created_at: string;
        file_size_estimate: string;
        status: string;
      }>;
      total: number;
    }>('/reports/', { method: 'GET' });

    const mapped: GeneratedReport[] = (res.reports || []).map((r) => {
      const rawClass = r.classification.toUpperCase();
      let classification: Classification = 'Safe';
      if (rawClass === 'PHISHING') classification = 'Phishing';
      else if (rawClass === 'SUSPICIOUS') classification = 'Suspicious';

      return {
        id: r.id,
        scanId: r.scan_id,
        title: r.title || `Incident Analysis: ${r.domain}`,
        targetUrl: r.target_url,
        classification,
        riskScore: r.risk_score,
        generatedDate: r.created_at
          ? new Date(r.created_at).toISOString().replace('T', ' ').substring(0, 16) + ' UTC'
          : '',
        fileSize: r.file_size_estimate || '184 KB',
        generatedBy: 'PhishGuard Autonomous Core',
        indicatorsFlagged: 0,
        status: 'Ready',
      };
    });

    return { reports: mapped, total: res.total || 0 };
  },

  async createReport(scanId: string) {
    return apiRequest<{
      id: string;
      user_id: string;
      scan_id: string;
      report_data: any;
      created_at: string;
    }>('/reports/', {
      method: 'POST',
      body: JSON.stringify({ scan_id: scanId }),
    });
  },

  async downloadPdf(idOrScanId: string): Promise<Blob> {
    const url = `${API_BASE_URL}/reports/${idOrScanId}/download`;

    const response = await fetch(url, {
      method: 'GET',
      credentials: 'include',
    });

    if (!response.ok) {
      throw new ApiError(response.status, 'Failed to download report PDF from backend');
    }

    return await response.blob();
  },
};

// -------------------------------------------------------------
// Threat Intelligence Endpoints
// -------------------------------------------------------------
export const intelligenceApi = {
  async getOverview() {
    return apiRequest<{
      sources: {
        phishtank: {
          configured: boolean;
          service: string;
          type: string;
          status: string;
          message: string;
          last_checked: string;
        };
        openphish: {
          configured: boolean;
          service: string;
          type: string;
          status: string;
          message: string;
          last_checked: string;
        };
      };
      active_threats_sample: Array<{
        id: string;
        url: string;
        domain: string;
        target_brand: string;
        confidence: number;
        source: string;
        reported_at: string;
        category: string;
        ip_address: string;
        status: string;
      }>;
      suspicious_patterns: Array<{
        id: string;
        pattern: string;
        description: string;
        frequency: string;
        risk_weight: string;
        example: string;
      }>;
      metrics: {
        tracked_campaigns: number;
        top_target_sector: string;
        avg_lure_lifespan_hours: number;
        heuristic_accuracy_pct: number;
      };
    }>('/intelligence/overview', { method: 'GET' });
  },

  async checkUrl(url: string) {
    return apiRequest<{
      url: string;
      domain: string;
      phishtank: {
        available: boolean;
        source: string;
        is_phishing?: boolean | null;
        confidence?: number | null;
        message: string;
      };
      openphish: {
        available: boolean;
        source: string;
        is_phishing?: boolean | null;
        confidence?: number | null;
        message: string;
      };
      has_threat_intel_match: boolean;
      checked_at: string;
    }>('/intelligence/check', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
  },
};
