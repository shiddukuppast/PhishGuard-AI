import { ScanResult, UserSettings, GeneratedReport } from '@/types';
import { INITIAL_MOCK_SCANS, DEFAULT_USER_SETTINGS, MOCK_REPORTS } from './mock-data';

const SCANS_STORAGE_KEY = 'phishguard_scans_v1';
const SETTINGS_STORAGE_KEY = 'phishguard_settings_v1';
const REPORTS_STORAGE_KEY = 'phishguard_reports_v1';

export function getStoredScans(): ScanResult[] {
  if (typeof window === 'undefined') return INITIAL_MOCK_SCANS;
  try {
    const raw = localStorage.getItem(SCANS_STORAGE_KEY);
    if (!raw) {
      localStorage.setItem(SCANS_STORAGE_KEY, JSON.stringify(INITIAL_MOCK_SCANS));
      return INITIAL_MOCK_SCANS;
    }
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) && parsed.length > 0 ? parsed : INITIAL_MOCK_SCANS;
  } catch (err) {
    console.error('Failed reading scans from storage', err);
    return INITIAL_MOCK_SCANS;
  }
}

export function saveScanToStorage(scan: ScanResult): ScanResult[] {
  if (typeof window === 'undefined') return [scan, ...INITIAL_MOCK_SCANS];
  try {
    const existing = getStoredScans();
    // Prepend new scan, remove duplicate id if any
    const updated = [scan, ...existing.filter((s) => s.id !== scan.id)];
    localStorage.setItem(SCANS_STORAGE_KEY, JSON.stringify(updated));

    // Also auto-generate an entry in reports for this scan
    const newReport: GeneratedReport = {
      id: `REP-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`,
      scanId: scan.id,
      title: `Analysis: ${scan.domain}`,
      targetUrl: scan.url,
      classification: scan.classification,
      riskScore: scan.riskScore,
      generatedDate: new Date().toISOString().replace('T', ' ').substring(0, 16) + ' UTC',
      fileSize: `${Math.floor(140 + Math.random() * 80)} KB`,
      generatedBy: 'On-Demand Heuristics Engine',
      indicatorsFlagged: scan.indicators.filter((i) => i.detected).length,
      status: 'Ready',
    };
    saveReportToStorage(newReport);

    return updated;
  } catch (err) {
    console.error('Failed writing scan to storage', err);
    return [scan, ...INITIAL_MOCK_SCANS];
  }
}

export function deleteScanFromStorage(scanId: string): ScanResult[] {
  if (typeof window === 'undefined') return INITIAL_MOCK_SCANS;
  try {
    const existing = getStoredScans();
    const updated = existing.filter((s) => s.id !== scanId);
    localStorage.setItem(SCANS_STORAGE_KEY, JSON.stringify(updated));
    return updated;
  } catch (err) {
    console.error('Failed deleting scan', err);
    return INITIAL_MOCK_SCANS;
  }
}

export function resetScansToDefault(): ScanResult[] {
  if (typeof window !== 'undefined') {
    localStorage.setItem(SCANS_STORAGE_KEY, JSON.stringify(INITIAL_MOCK_SCANS));
  }
  return INITIAL_MOCK_SCANS;
}

export function getStoredSettings(): UserSettings {
  if (typeof window === 'undefined') return DEFAULT_USER_SETTINGS;
  try {
    const raw = localStorage.getItem(SETTINGS_STORAGE_KEY);
    if (!raw) {
      localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(DEFAULT_USER_SETTINGS));
      return DEFAULT_USER_SETTINGS;
    }
    return { ...DEFAULT_USER_SETTINGS, ...JSON.parse(raw) };
  } catch (err) {
    console.error('Failed reading settings', err);
    return DEFAULT_USER_SETTINGS;
  }
}

export function saveSettingsToStorage(settings: UserSettings): void {
  if (typeof window === 'undefined') return;
  try {
    localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(settings));
  } catch (err) {
    console.error('Failed saving settings', err);
  }
}

export function getStoredReports(): GeneratedReport[] {
  if (typeof window === 'undefined') return MOCK_REPORTS;
  try {
    const raw = localStorage.getItem(REPORTS_STORAGE_KEY);
    if (!raw) {
      localStorage.setItem(REPORTS_STORAGE_KEY, JSON.stringify(MOCK_REPORTS));
      return MOCK_REPORTS;
    }
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : MOCK_REPORTS;
  } catch (err) {
    console.error('Failed reading reports', err);
    return MOCK_REPORTS;
  }
}

export function saveReportToStorage(report: GeneratedReport): GeneratedReport[] {
  if (typeof window === 'undefined') return [report, ...MOCK_REPORTS];
  try {
    const existing = getStoredReports();
    const updated = [report, ...existing.filter((r) => r.id !== report.id)];
    localStorage.setItem(REPORTS_STORAGE_KEY, JSON.stringify(updated));
    return updated;
  } catch (err) {
    console.error('Failed saving report', err);
    return [report, ...MOCK_REPORTS];
  }
}

export function downloadReportAsFile(scan: ScanResult, format: 'json' | 'txt' | 'md' = 'md') {
  if (typeof window === 'undefined') return;

  let content = '';
  let mimeType = 'text/plain';
  let extension = 'txt';

  if (format === 'json') {
    content = JSON.stringify(scan, null, 2);
    mimeType = 'application/json';
    extension = 'json';
  } else if (format === 'md') {
    extension = 'md';
    mimeType = 'text/markdown';
    content = `# PhishGuard AI - Security Analysis Report
**Generated on:** ${new Date(scan.timestamp).toUTCString()}
**Report ID:** ${scan.id}
**Engine:** ${scan.aiAnalysis.heuristicsEngineVersion} (Simulated Frontend Heuristics)

---

## 1. Executive Summary
- **Target URL:** \`${scan.url}\`
- **Domain:** \`${scan.domain}\`
- **Classification:** **${scan.classification.toUpperCase()}**
- **Risk Score:** **${scan.riskScore}/100** (${scan.riskCategory} Risk)
${scan.aiAnalysis.impersonatedBrand ? `- **Impersonated Target:** ${scan.aiAnalysis.impersonatedBrand}` : ''}
- **Threat Category:** ${scan.aiAnalysis.threatType}

### Analysis Summary
> ${scan.aiAnalysis.summary}

---

## 2. Security Indicator Evaluation
| Indicator | Status | Severity | Details |
| :--- | :--- | :--- | :--- |
${scan.indicators.map((i) => `| ${i.name} | ${i.detected ? 'FLAGGED' : 'PASSED'} | ${i.severity} | ${i.description} |`).join('\n')}

---

## 3. Flag Reasons & Detection Logic
${scan.aiAnalysis.flagReasons.map((r, idx) => `${idx + 1}. ${r}`).join('\n')}

---

## 4. Technical Domain Telemetry
- **IP Address:** ${scan.domainDetails.ipAddress || 'N/A'}
- **Country:** ${scan.domainDetails.country || 'N/A'}
- **Top Level Domain:** ${scan.domainDetails.tld}
- **HTTPS Enforced:** ${scan.domainDetails.hasHttps ? 'Yes' : 'No (Insecure HTTP)'}
- **Subdomain Count:** ${scan.domainDetails.subdomainCount}
- **Total URL Length:** ${scan.domainDetails.urlLength} characters
- **Registrar:** ${scan.domainDetails.registrar || 'Protected / N/A'}
- **Estimated Domain Age:** ${scan.domainDetails.createdAgeDays ?? 'Unknown'} days

---

## 5. Security Recommendations
${scan.recommendations.map((rec, i) => `${i + 1}. ${rec}`).join('\n')}

---
*Notice: This report was compiled by PhishGuard AI frontend heuristic evaluation. Final production verification will query live FastAPI ML models and integrated threat feeds.*
`;
  }

  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `PhishGuard-Report-${scan.domain.replace(/[^a-zA-Z0-9.-]/g, '_')}-${scan.id}.${extension}`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

