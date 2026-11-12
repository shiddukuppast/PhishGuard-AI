export type RiskCategory = 'Low' | 'Medium' | 'High' | 'Critical';

export type Classification = 'Safe' | 'Suspicious' | 'Phishing';

export type IndicatorSeverity = 'Info' | 'Low' | 'Medium' | 'High' | 'Critical';

export type IndicatorStatus = 'safe' | 'warning' | 'danger' | 'neutral';

export interface SecurityIndicatorItem {
  id: string;
  name: string;
  status: IndicatorStatus;
  description: string;
  severity: IndicatorSeverity;
  detected: boolean;
  technicalDetail?: string;
}

export interface DomainMetadata {
  ipAddress?: string;
  country?: string;
  tld: string;
  subdomainCount: number;
  domainLength: number;
  urlLength: number;
  hasHttps: boolean;
  hasIpHost: boolean;
  specialCharsCount: number;
  suspiciousKeywordsFound: string[];
  sslIssuer?: string;
  createdAgeDays?: number;
  registrar?: string;
}

export interface ScanResult {
  id: string;
  url: string;
  domain: string;
  timestamp: string;
  riskScore: number; // 0 - 100
  classification: Classification;
  riskCategory: RiskCategory;
  indicators: SecurityIndicatorItem[];
  aiAnalysis: {
    summary: string;
    flagReasons: string[];
    impersonatedBrand?: string;
    threatType: string;
    heuristicsEngineVersion: string;
  };
  mlPrediction?: {
    available: boolean;
    prediction?: string | null;
    confidence?: number | null;
    modelVersion?: string | null;
    message: string;
  };
  threatIntelligence?: {
    phishtank?: {
      available: boolean;
      source?: string;
      is_phishing?: boolean | null;
      confidence?: number | null;
      message?: string;
      verified_at?: string | null;
    };
    openphish?: {
      available: boolean;
      source?: string;
      is_phishing?: boolean | null;
      confidence?: number | null;
      message?: string;
    };
    has_threat_intel_match: boolean;
    checked_at?: string;
  };
  recommendations: string[];
  domainDetails: DomainMetadata;
  isSimulated: boolean;
}

export interface ThreatFeedItem {
  id: string;
  url: string;
  domain: string;
  targetBrand: string;
  confidence: number;
  source: 'PhishTank' | 'OpenPhish' | 'Internal ML' | 'ThreatPulse';
  reportedAt: string;
  category: 'Credential Harvesting' | 'Financial Fraud' | 'Malware Delivery' | 'Brand Impersonation' | 'Crypto Scam';
  ipAddress: string;
  status: 'Active' | 'Mitigated' | 'Under Review';
}

export interface SuspiciousPattern {
  id: string;
  pattern: string;
  description: string;
  frequency: string;
  riskWeight: 'High' | 'Medium' | 'Critical';
  example: string;
}

export interface DashboardMetric {
  title: string;
  value: string | number;
  trend?: string;
  trendDirection?: 'up' | 'down' | 'neutral';
  description?: string;
  iconName: string;
}

export interface ActivityDataPoint {
  date: string;
  phishing: number;
  suspicious: number;
  safe: number;
  total: number;
}

export interface ThreatDistributionPoint {
  name: string;
  value: number;
  color: string;
}

export interface GeneratedReport {
  id: string;
  scanId: string;
  title: string;
  targetUrl: string;
  classification: Classification;
  riskScore: number;
  generatedDate: string;
  fileSize: string;
  generatedBy: string;
  indicatorsFlagged: number;
  status: 'Ready' | 'Archived';
}

export interface UserSettings {
  profile: {
    name: string;
    email: string;
    role: string;
    organization: string;
    apiKey: string;
  };
  appearance: {
    compactMode: boolean;
    highContrastRisk: boolean;
    showAnimationStage: boolean;
    soundAlerts: boolean;
  };
  notifications: {
    emailOnCriticalThreat: boolean;
    dailyDigest: boolean;
    browserAlerts: boolean;
    weeklySecurityReport: boolean;
  };
  security: {
    deepUrlHeuristics: boolean;
    autoFlagSuspiciousTlds: boolean;
    strictHttpsEnforcement: boolean;
    simulateSandboxedExecution: boolean;
    shareAnonymizedTelemetry: boolean;
  };
}

export interface User {
  id: string;
  name: string;
  email: string;
  role: string;
  organization: string;
  avatarInitials: string;
  apiKey: string;
  createdAt: string;
}

export interface AuthSession {
  token: string;
  user: User;
  expiresAt: number;
}

export interface LoginCredentials {
  email: string;
  password: string;
  rememberMe?: boolean;
}

export interface SignupCredentials {
  name: string;
  email: string;
  password: string;
  confirmPassword?: string;
  termsAccepted: boolean;
}

export interface AuthResponse {
  success: boolean;
  message?: string;
  session?: AuthSession;
}


