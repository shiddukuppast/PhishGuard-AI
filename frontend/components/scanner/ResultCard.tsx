'use client';

import React, { useState } from 'react';
import {
  Download,
  RotateCcw,
  Maximize2,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  Copy,
  Check,
  ExternalLink,
  Sparkles,
  Info,
  Layers,
  Globe,
  Lock,
  Unlock,
  Cpu,
  Radio,
  Clock,
  CheckCircle2,
} from 'lucide-react';
import { ScanResult } from '@/types';
import { RiskGauge } from './RiskGauge';
import { SecurityIndicator } from './SecurityIndicator';
import { reportsApi } from '@/lib/api';
import { downloadReportAsFile } from '@/lib/storage';
import { useToast } from '../shared/ToastContext';
import { cn } from '@/lib/utils';
import { ScanDetailModal } from '../shared/ScanDetailModal';

interface ResultCardProps {
  result: ScanResult;
  onScanAnother: () => void;
}

export function ResultCard({ result, onScanAnother }: ResultCardProps) {
  const { success, error: toastError } = useToast();
  const [copied, setCopied] = useState(false);
  const [showFullModal, setShowFullModal] = useState(false);
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);

  const copyUrl = () => {
    navigator.clipboard.writeText(result.url);
    setCopied(true);
    success('URL copied to clipboard');
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadPdf = async () => {
    setIsDownloadingPdf(true);
    try {
      const blob = await reportsApi.downloadPdf(result.id);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `PhishGuard-Report-${result.domain}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      success('Dossier Downloaded', `PDF security report generated for ${result.domain}`);
    } catch {
      // Fallback to client markdown report if PDF stream fails
      downloadReportAsFile(result, 'md');
      success('Report Downloaded', `Markdown dossier exported for ${result.domain}`);
    } finally {
      setIsDownloadingPdf(false);
    }
  };

  const isPhishing = result.classification === 'Phishing';
  const isSuspicious = result.classification === 'Suspicious';
  const isSafe = result.classification === 'Safe';

  const formattedDate = result.timestamp
    ? new Date(result.timestamp).toUTCString()
    : new Date().toUTCString();

  return (
    <>
      <div className="bg-[#111827] border border-[#263244] rounded-2xl p-6 lg:p-8 shadow-xl space-y-6">
        {/* Top Header & Source Verification Banner */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-5 border-b border-[#263244]">
          <div className="flex flex-wrap items-center gap-2">
            <span
              className={cn(
                'text-xs font-mono font-semibold uppercase px-3 py-1 rounded-full border flex items-center gap-1.5',
                isPhishing && 'bg-red-500/10 text-red-400 border-red-500/30',
                isSuspicious && 'bg-amber-500/10 text-amber-300 border-amber-500/30',
                isSafe && 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
              )}
            >
              {isPhishing && <ShieldAlert className="w-3.5 h-3.5" />}
              {isSuspicious && <AlertTriangle className="w-3.5 h-3.5" />}
              {isSafe && <ShieldCheck className="w-3.5 h-3.5" />}
              {isPhishing ? 'POTENTIAL PHISHING' : result.classification.toUpperCase()}
            </span>

            <span className="text-xs font-mono px-2.5 py-1 rounded-full bg-[#162032] text-slate-300 border border-[#263244]">
              Risk Level: <strong className="text-slate-100">{result.riskCategory}</strong>
            </span>

            {result.aiAnalysis.impersonatedBrand && (
              <span className="text-xs font-mono px-2.5 py-1 rounded-full bg-red-950/40 text-red-300 border border-red-800/40">
                Impersonating: {result.aiAnalysis.impersonatedBrand}
              </span>
            )}
          </div>

          {/* Real Backend Verification Tag */}
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#0B1120] border border-[#263244] text-[11px] text-emerald-400">
              <ShieldCheck className="w-3 h-3 text-emerald-400 shrink-0" />
              <span>FastAPI Threat Engine</span>
            </div>
            <span className="text-slate-500 text-[11px] flex items-center gap-1">
              <Clock className="w-3 h-3" />
              {formattedDate}
            </span>
          </div>
        </div>

        {/* URL Identity Block */}
        <div className="p-4 rounded-xl bg-[#0B1120] border border-[#263244] flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400 font-mono mb-1">
              <div className="flex items-center gap-1">
                <Globe className="w-3.5 h-3.5 text-slate-500" />
                <span>Domain:</span>
                <span className="text-slate-200 font-bold">{result.domain}</span>
              </div>
              <span>•</span>
              <div>
                {result.domainDetails.hasHttps ? (
                  <span className="flex items-center gap-1 text-emerald-400 text-[11px]">
                    <Lock className="w-3 h-3" /> TLS / HTTPS Secured
                  </span>
                ) : (
                  <span className="flex items-center gap-1 text-red-400 text-[11px]">
                    <Unlock className="w-3 h-3" /> Insecure Plaintext HTTP
                  </span>
                )}
              </div>
            </div>
            <p className="text-sm md:text-base font-mono text-slate-100 font-medium break-all select-all">
              {result.url}
            </p>
          </div>

          <button
            onClick={copyUrl}
            className="self-start md:self-center flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#162032] hover:bg-[#1E293B] border border-[#263244] text-xs font-medium text-slate-300 hover:text-white transition-colors"
            title="Copy URL"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copied ? 'Copied' : 'Copy URL'}</span>
          </button>
        </div>

        {/* Multi-Layer Verification Breakdown (Rule-Based, ML Prediction, Threat Intel) */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {/* 1. Rule-Based Analysis */}
          <div className="p-4 rounded-xl bg-[#0B1120] border border-[#263244] space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Rule-Based Analysis</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
                ACTIVE
              </span>
            </div>
            <p className="text-xs text-slate-200 font-mono font-medium">13 Lexical & Structural Checks</p>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              {result.indicators.filter((i) => i.detected).length} of {result.indicators.length} threat indicators flagged during static evaluation.
            </p>
          </div>

          {/* 2. Machine Learning Prediction */}
          <div className="p-4 rounded-xl bg-[#0B1120] border border-[#263244] space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Machine Learning</span>
              <span
                className={cn(
                  'text-[10px] font-mono px-2 py-0.5 rounded border font-semibold',
                  result.mlPrediction?.available
                    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                    : 'bg-amber-500/10 text-amber-300 border-amber-500/20'
                )}
              >
                {result.mlPrediction?.available ? 'INFERENCE ACTIVE' : 'MODEL UNAVAILABLE'}
              </span>
            </div>
            <p className="text-xs text-slate-200 font-mono font-medium">
              {result.mlPrediction?.available
                ? `Prediction: ${result.mlPrediction.prediction}`
                : 'Scikit-learn Model Pending'}
            </p>
            <p className="text-[11px] text-amber-200/90 leading-relaxed">
              {result.mlPrediction?.message ||
                'Machine learning analysis is currently unavailable. This result is based on the available URL security checks.'}
            </p>
            {result.mlPrediction?.available && typeof result.mlPrediction.confidence === 'number' && (
              <span className="text-[11px] font-mono text-cyan-400 block pt-0.5">
                Model Confidence: {(result.mlPrediction.confidence * 100).toFixed(1)}%
              </span>
            )}
          </div>

          {/* 3. Threat Intelligence Verification */}
          <div className="p-4 rounded-xl bg-[#0B1120] border border-[#263244] space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Threat Intelligence</span>
              <span
                className={cn(
                  'text-[10px] font-mono px-2 py-0.5 rounded border font-semibold',
                  result.threatIntelligence?.has_threat_intel_match
                    ? 'bg-red-500/10 text-red-400 border-red-500/30'
                    : 'bg-slate-700/30 text-slate-300 border-slate-700'
                )}
              >
                {result.threatIntelligence?.has_threat_intel_match ? 'FEED MATCH' : 'FEEDS QUERIED'}
              </span>
            </div>
            <p className="text-xs text-slate-200 font-mono font-medium">PhishTank & OpenPhish</p>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              {result.threatIntelligence?.phishtank?.message || 'External threat feeds evaluated with zero SSRF lookup.'}
            </p>
          </div>
        </div>

        {/* Core Metric & Gauge Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
          {/* Circular Gauge */}
          <div className="lg:col-span-5 flex flex-col items-center justify-center p-6 rounded-xl bg-[#0B1120]/60 border border-[#263244]">
            <p className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-4">
              Calibrated Risk Score
            </p>
            <RiskGauge score={result.riskScore} size={190} strokeWidth={13} />
            <p className="mt-3 text-xs text-slate-500 font-mono text-center max-w-xs">
              Synthesized from static lexical tokens, host type, protocol, and reputation indicators.
            </p>
          </div>

          {/* Forensic Explanation Section */}
          <div className="lg:col-span-7 space-y-4">
            <div className="p-5 rounded-xl bg-[#0B1120]/80 border border-[#263244] space-y-3">
              <div className="flex items-center gap-2">
                <div className="w-6 h-6 rounded-md bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
                  <Sparkles className="w-3.5 h-3.5" />
                </div>
                <h3 className="text-sm font-semibold text-slate-100 tracking-tight">
                  Security Assessment Explanation
                </h3>
              </div>

              <p className="text-xs md:text-sm text-slate-300 leading-relaxed">
                {result.aiAnalysis.summary}
              </p>

              {result.aiAnalysis.flagReasons.length > 0 && (
                <div className="space-y-1.5 pt-2 border-t border-[#263244]/60">
                  <p className="text-[11px] font-mono uppercase tracking-wider text-slate-500">
                    Detection Findings:
                  </p>
                  <ul className="space-y-1">
                    {result.aiAnalysis.flagReasons.map((reason, idx) => (
                      <li key={idx} className="flex items-start gap-2 text-xs text-slate-400">
                        <span className="text-cyan-400 font-mono text-[11px] mt-0.5">•</span>
                        <span>{reason}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            {/* Recommendations */}
            <div className="p-5 rounded-xl bg-[#0B1120]/80 border border-[#263244] space-y-2.5">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-amber-400" />
                <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider font-mono">
                  Recommended Protective Actions
                </h4>
              </div>

              <ul className="space-y-1.5">
                {result.recommendations.map((rec, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-slate-300">
                    <span className="text-amber-400 font-mono text-[11px] mt-0.5">▸</span>
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>

        {/* Security Indicators Section */}
        <div className="space-y-3 pt-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-slate-100">
                Security Indicator Checks ({result.indicators.length} Features Evaluated)
              </h3>
            </div>
            <span className="text-xs font-mono text-slate-400">
              {result.indicators.filter((i) => i.detected).length} of {result.indicators.length} checks triggered
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {result.indicators.map((indicator) => (
              <SecurityIndicator key={indicator.id} indicator={indicator} />
            ))}
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-[#263244]">
          <button
            onClick={onScanAnother}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[#162032] hover:bg-[#1E293B] text-slate-200 border border-[#263244] text-xs font-medium transition-all"
          >
            <RotateCcw className="w-3.5 h-3.5 text-cyan-400" />
            <span>Scan Another URL</span>
          </button>

          <div className="flex items-center gap-2.5">
            <button
              onClick={handleDownloadPdf}
              disabled={isDownloadingPdf}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[#162032] hover:bg-[#1E293B] text-slate-200 border border-[#263244] text-xs font-medium transition-all disabled:opacity-50"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              <span>{isDownloadingPdf ? 'Generating PDF...' : 'Download PDF Dossier'}</span>
            </button>

            <button
              onClick={() => setShowFullModal(true)}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-[#041C24] font-semibold text-xs transition-all shadow-md shadow-cyan-500/20"
            >
              <Maximize2 className="w-3.5 h-3.5" />
              <span>View Full Forensics</span>
            </button>
          </div>
        </div>
      </div>

      {/* Full Analysis Modal */}
      {showFullModal && (
        <ScanDetailModal scan={result} onClose={() => setShowFullModal(false)} />
      )}
    </>
  );
}
