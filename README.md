# PhishGuard AI

> **Detect. Analyze. Protect.**  
> Next-Generation AI-Powered Phishing Detection & Threat Intelligence Platform.

PhishGuard AI is an enterprise-grade cybersecurity SaaS platform engineered to analyze URLs, detect suspicious structural anomalies, assign calibrated risk scores, and deliver actionable security recommendations for Security Operations Centers (SOC) and end users.

---

## 🛡️ Core Highlights

- **Linear / Vercel-Grade Cybersecurity UI**: Dark navy palette (`#0B1120`), elevated cards (`#111827`), subtle `#263244` borders, electric cyan (`#06B6D4`) and high-visibility status indicators.
- **Deep Heuristic Scanner Engine**: Client-side analysis evaluates 6 core indicators:
  - Protocol verification (TLS/HTTPS enforcement)
  - Raw numerical IP host masquerading
  - Brand typosquatting and impersonation (Apple, PayPal, Microsoft, Netflix, Chase, etc.)
  - URL length and entropy thresholds
  - Suspicious token and credential harvesting keywords
  - High-abuse Top-Level Domains (`.xyz`, `.top`, `.tk`, `.rest`, `.buzz`)
- **Realistic Heuristic Risk Scoring**: 0–100 scale dynamically mapped to Low (0–30), Medium (31–60), High (61–80), and Critical (81–100) risk categories.
- **5-Stage Animated Scanner Pipeline**: Visual progress bar tracking characteristic extraction, domain structure, security indicators, ML detection, and risk assessment.
- **Interactive Recharts Visualizations**: 7-day threat activity area charts and classification distribution donut charts.
- **Full Audit History & Offline Persistence**: Automatic localStorage sync, search, status filtering, risk score sorting, and pagination.
- **Exportable Incident Reports**: Instant Markdown and JSON dossier generation with downloadable file outputs.
- **Threat Intelligence Radar**: Tracked phishing domains, feed sync simulator (PhishTank, OpenPhish), and heuristic pattern library.
- **Configurable Settings**: Profile management, API bearer token generator, high-contrast risk gauges, and heuristic engine tuning with live toggle switches.

---

## 🚀 Quick Start

### Prerequisites
- Node.js (v18+ or v20+)
- npm

### 1. Run Development Server
```bash
# From repository root
npm run dev

# Or directly in frontend/
cd frontend
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### 2. Build for Production
```bash
npm run build
npm run start
```

---

## 📁 Project Architecture

```
PhishGuard-AI/
├── frontend/
│   ├── app/
│   │   ├── dashboard/page.tsx      # Overview, stats, Recharts area/donut, recent scans
│   │   ├── scanner/page.tsx        # URL scanner centerpiece
│   │   ├── history/page.tsx        # Filterable audit log with localStorage
│   │   ├── intelligence/page.tsx   # Threat feeds (PhishTank, OpenPhish)
│   │   ├── reports/page.tsx        # Report metrics & Markdown/JSON exports
│   │   ├── settings/page.tsx       # Profile, toggles, API key generation
│   │   ├── layout.tsx              # Root layout with persistent sidebar & toast
│   │   ├── globals.css             # Tailwind dark theme variables
│   │   └── page.tsx                # Automatic redirect to /dashboard
│   ├── components/
│   │   ├── layout/
│   │   │   ├── Sidebar.tsx         # Collapsible responsive sidebar & mobile drawer
│   │   │   └── Header.tsx          # Page title, live clock, notifications & avatar
│   │   ├── dashboard/
│   │   │   ├── StatisticsCard.tsx  # KPI cards with direction badges
│   │   │   └── ThreatChart.tsx     # Recharts Area & Donut components
│   │   ├── scanner/
│   │   │   ├── URLScanner.tsx      # Input, validation, 5-stage progress, presets
│   │   │   ├── RiskGauge.tsx       # SVG circular gauge (0-100)
│   │   │   ├── SecurityIndicator.tsx# Individual security check cards
│   │   │   └── ResultCard.tsx      # Comprehensive scan report & recommendations
│   │   ├── history/
│   │   │   └── ScanHistoryTable.tsx# Search, filter, risk sort, pagination, modals
│   │   └── shared/
│   │       ├── ScanDetailModal.tsx # Full forensics dossier (telemetry, JSON, etc.)
│   │       └── ToastContext.tsx    # Cyber-styled notifications system
│   ├── lib/
│   │   ├── scanner.ts              # Heuristics analysis engine
│   │   ├── storage.ts              # LocalStorage sync & report downloads
│   │   ├── mock-data.ts            # High-fidelity cybersecurity demo data
│   │   └── utils.ts                # Class merging & formatters
│   ├── types/
│   │   └── index.ts                # Strict TypeScript interfaces
│   └── package.json
└── package.json                    # Root workspace launcher
```

---

## 🔌 Future FastAPI Integration Guide

The frontend data structures in `types/index.ts` and `lib/scanner.ts` are strictly modeled after standard RESTful cybersecurity schemas:

```typescript
// POST /api/v1/scan
// Request payload:
{
  "url": "http://secure-account-verification.example.test"
}

// Expected response matches `ScanResult` interface:
{
  "id": "scan_...",
  "url": "http://...",
  "domain": "...",
  "riskScore": 92,
  "classification": "Phishing",
  "riskCategory": "Critical",
  "indicators": [...],
  "aiAnalysis": {
    "summary": "...",
    "flagReasons": [...],
    "impersonatedBrand": "...",
    "threatType": "..."
  },
  "recommendations": [...]
}
```

---

## 🎨 Design System

| Role | Color | Hex | Usage |
| :--- | :--- | :--- | :--- |
| **Dark Navy Background** | `bg-background` | `#0B1120` | Main canvas |
| **Lighter Cards** | `bg-surface` | `#111827` | Cards, panels, modals |
| **Subtle Borders** | `border` | `#263244` | Outlines, separators |
| **Electric Cyan** | `text-cyan-400` | `#06B6D4` | Primary brand accent |
| **Secondary Blue** | `text-blue-500` | `#3B82F6` | Secondary accent |
| **Danger (Red)** | `text-red-400` | `#EF4444` | Phishing, critical risk |
| **Warning (Amber)** | `text-amber-400` | `#F59E0B` | Suspicious anomalies |
| **Success (Emerald)**| `text-emerald-400` | `#10B981` | Safe, verified legitimate |

---
*PhishGuard AI — Autonomous Threat Detection Platform*

