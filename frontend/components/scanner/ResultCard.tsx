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
} from 'lucide-react';
import { ScanResult } from '@/types';
import { RiskGauge } from './RiskGauge';
import { SecurityIndicator } from './SecurityIndicator';
import { downloadReportAsFile } from '@/lib/storage';
import { useToast } from '../shared/ToastContext';
import { cn } from '@/lib/utils';
import { ScanDetailModal } from '../shared/ScanDetailModal';

interface ResultCardProps {
  result: ScanResult;
  onScanAnother: () => void;
}

export function ResultCard({ result, onScanAnother }: ResultCardProps) {
  const { success } = useToast();
  const [copied, setCopied] = useState(false);
  const [showFullModal, setShowFullModal] = useState(false);

  const copyUrl = () => {
    navigator.clipboard.writeText(result.url);
    setCopied(true);
    success('URL copied to clipboard');
    setTimeout(() => setCopied(false), 2000);
  };

  const isPhishing = result.classification === 'Phishing';
  const isSuspicious = result.classification === 'Suspicious';
  const isSafe = result.classification === 'Safe';

  return (
    <>
      <div className="bg-[#111827] border border-[#263244] rounded-2xl p-6 lg:p-8 shadow-xl space-y-6">
        {/* Top Header & Simulation Notice Banner */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-5 border-b border-[#263244]">
          <div className="flex items-center gap-2">
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

            {result.aiAnalysis.impersonatedBrand && (
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-red-950/40 text-red-300 border border-red-800/40">
                Impersonating: {result.aiAnalysis.impersonatedBrand}
              </span>
            )}
          </div>

          {/* Simulated Tag Requirement */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#0B1120] border border-[#263244] text-[11px] font-mono text-cyan-400">
            <Sparkles className="w-3 h-3 text-cyan-400 shrink-0" />
            <span>Simulated Frontend Heuristics (Ready for FastAPI)</span>
          </div>
        </div>

        {/* URL Identity Block */}
        <div className="p-4 rounded-xl bg-[#0B1120] border border-[#263244] flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 text-xs text-slate-400 font-mono mb-1">
              <Globe className="w-3.5 h-3.5 text-slate-500" />
              <span>Target URL:</span>
              {result.domainDetails.hasHttps ? (
                <span className="flex items-center gap-1 text-emerald-400 text-[10px]">
                  <Lock className="w-3 h-3" /> HTTPS
                </span>
              ) : (
                <span className="flex items-center gap-1 text-red-400 text-[10px]">
                  <Unlock className="w-3 h-3" /> Plaintext HTTP
                </span>
              )}
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

        {/* Core Metric & Gauge Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-center">
          {/* Circular Gauge */}
          <div className="lg:col-span-5 flex flex-col items-center justify-center p-6 rounded-xl bg-[#0B1120]/60 border border-[#263244]">
            <p className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-4">
              Composite Risk Score
            </p>
            <RiskGauge score={result.riskScore} size={190} strokeWidth={13} />
            <p className="mt-3 text-xs text-slate-500 font-mono text-center max-w-xs">
              Calculated via syntactic, structural, protocol, and reputation signals.
            </p>
          </div>

          {/* AI Analysis Section */}
          <div className="lg:col-span-7 space-y-4">
            <div className="p-5 rounded-xl bg-[#0B1120]/80 border border-[#263244] space-y-3">
              <div className="flex items-center gap-2">
                <div className="w-6 h-6 rounded-md bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
                  <Sparkles className="w-3.5 h-3.5" />
                </div>
                <h3 className="text-sm font-semibold text-slate-100 tracking-tight">
                  Why was this URL flagged?
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
                  Recommended Actions
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
                Security Indicator Checks
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
              onClick={() => {
                downloadReportAsFile(result, 'md');
                success('Report downloaded', 'Saved security briefing to markdown file.');
              }}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[#162032] hover:bg-[#1E293B] text-slate-200 border border-[#263244] text-xs font-medium transition-all"
            >
              <Download className="w-3.5 h-3.5 text-slate-400" />
              <span>Download Report</span>
            </button>

            <button
              onClick={() => setShowFullModal(true)}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-[#041C24] font-semibold text-xs transition-all shadow-md shadow-cyan-500/20"
            >
              <Maximize2 className="w-3.5 h-3.5" />
              <span>View Full Analysis</span>
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

