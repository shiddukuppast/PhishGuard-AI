import { ScanResult, UserSettings, GeneratedReport } from '@/types';

const SCANS_STORAGE_KEY = 'phishguard_scans_v1';
const SETTINGS_STORAGE_KEY = 'phishguard_settings_v1';
const REPORTS_STORAGE_KEY = 'phishguard_reports_v1';

export const CLEAN_USER_SETTINGS: UserSettings = {
  profile: {
    name: 'Security Analyst',
    email: 'analyst@phishguard.ai',
    role: 'Analyst',
    organization: 'PhishGuard AI Operations',
    apiKey: 'pg_live_' + Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join(''),
  },
  appearance: {
    compactMode: false,
    highContrastRisk: false,
    showAnimationStage: true,
    soundAlerts: false,
  },
  notifications: {
    emailOnCriticalThreat: true,
    dailyDigest: false,
    browserAlerts: true,
    weeklySecurityReport: true,
  },
  security: {
    deepUrlHeuristics: true,
    autoFlagSuspiciousTlds: true,
    strictHttpsEnforcement: true,
    simulateSandboxedExecution: false,
    shareAnonymizedTelemetry: false,
  },
};

/**
 * Returns stored scans from local cache (if any), otherwise empty array.
 * Never populates fake/demo scans.
 */
export function getStoredScans(): ScanResult[] {
  if (typeof window === 'undefined') return [];
  try {
    const raw = localStorage.getItem(SCANS_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.error('Failed reading scans from storage', err);
    return [];
  }
}

export function saveScanToStorage(scan: ScanResult): ScanResult[] {
  if (typeof window === 'undefined') return [scan];
  try {
    const existing = getStoredScans();
    const updated = [scan, ...existing.filter((s) => s.id !== scan.id)];
    localStorage.setItem(SCANS_STORAGE_KEY, JSON.stringify(updated));
    return updated;
  } catch (err) {
    console.error('Failed writing scan to storage', err);
    return [scan];
  }
}

export function deleteScanFromStorage(scanId: string): ScanResult[] {
  if (typeof window === 'undefined') return [];
  try {
    const existing = getStoredScans();
    const updated = existing.filter((s) => s.id !== scanId);
    localStorage.setItem(SCANS_STORAGE_KEY, JSON.stringify(updated));
    return updated;
  } catch (err) {
    console.error('Failed deleting scan', err);
    return [];
  }
}

export function getStoredSettings(): UserSettings {
  if (typeof window === 'undefined') return CLEAN_USER_SETTINGS;
  try {
    const raw = localStorage.getItem(SETTINGS_STORAGE_KEY);
    if (!raw) {
      localStorage.setItem(SETTINGS_STORAGE_KEY, JSON.stringify(CLEAN_USER_SETTINGS));
      return CLEAN_USER_SETTINGS;
    }
    return { ...CLEAN_USER_SETTINGS, ...JSON.parse(raw) };
  } catch (err) {
    console.error('Failed reading settings', err);
    return CLEAN_USER_SETTINGS;
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
  if (typeof window === 'undefined') return [];
  try {
    const raw = localStorage.getItem(REPORTS_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.error('Failed reading reports', err);
    return [];
  }
}

export function saveReportToStorage(report: GeneratedReport): GeneratedReport[] {
  if (typeof window === 'undefined') return [report];
  try {
    const existing = getStoredReports();
    const updated = [report, ...existing.filter((r) => r.id !== report.id)];
    localStorage.setItem(REPORTS_STORAGE_KEY, JSON.stringify(updated));
    return updated;
  } catch (err) {
    console.error('Failed saving report', err);
    return [report];
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
**Engine:** ${scan.aiAnalysis?.heuristicsEngineVersion || 'FastAPI Heuristics Engine'}

---

## 1. Executive Summary
- **Target URL:** \`${scan.url}\`
- **Domain:** \`${scan.domain}\`
- **Classification:** **${scan.classification.toUpperCase()}**
- **Risk Score:** **${scan.riskScore}/100** (${scan.riskCategory} Risk)
${scan.aiAnalysis?.impersonatedBrand ? `- **Impersonated Target:** ${scan.aiAnalysis.impersonatedBrand}` : ''}
- **Threat Category:** ${scan.aiAnalysis?.threatType || 'Suspicious URL'}

### Analysis Summary
> ${scan.aiAnalysis?.summary || 'Automated security analysis performed.'}

---

## 2. Security Indicator Evaluation
| Indicator | Status | Severity | Details |
| :--- | :--- | :--- | :--- |
${(scan.indicators || []).map((i) => `| ${i.name} | ${i.detected ? 'FLAGGED' : 'PASSED'} | ${i.severity} | ${i.description} |`).join('\n')}

---

## 3. Flag Reasons & Detection Logic
${(scan.aiAnalysis?.flagReasons || []).map((r, idx) => `${idx + 1}. ${r}`).join('\n')}

---

## 4. Technical Domain Telemetry
- **IP Address:** ${scan.domainDetails?.ipAddress || 'N/A'}
- **Country:** ${scan.domainDetails?.country || 'N/A'}
- **Top Level Domain:** ${scan.domainDetails?.tld || 'N/A'}
- **HTTPS Enforced:** ${scan.domainDetails?.hasHttps ? 'Yes' : 'No (Insecure HTTP)'}
- **Subdomain Count:** ${scan.domainDetails?.subdomainCount ?? 0}
- **Total URL Length:** ${scan.domainDetails?.urlLength ?? 0} characters
- **Registrar:** ${scan.domainDetails?.registrar || 'Protected / N/A'}
- **Estimated Domain Age:** ${scan.domainDetails?.createdAgeDays ?? 'Unknown'} days

---

## 5. Security Recommendations
${(scan.recommendations || []).map((rec, i) => `${i + 1}. ${rec}`).join('\n')}

---
*Generated by PhishGuard AI Security Platform.*
`;
  }

  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `PhishGuard-Report-${scan.domain ? scan.domain.replace(/[^a-zA-Z0-9.-]/g, '_') : 'scan'}-${scan.id}.${extension}`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
