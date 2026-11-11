'use client';

import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Download,
  Copy,
  Check,
  ExternalLink,
  Server,
  Globe,
  Lock,
  Unlock,
  Calendar,
  FileCode,
  Terminal,
} from 'lucide-react';
import { ScanResult } from '@/types';
import { RiskGauge } from '../scanner/RiskGauge';
import { downloadReportAsFile } from '@/lib/storage';
import { useToast } from './ToastContext';
import { cn } from '@/lib/utils';

interface ScanDetailModalProps {
  scan: ScanResult;
  onClose: () => void;
}

export function ScanDetailModal({ scan, onClose }: ScanDetailModalProps) {
  const { success } = useToast();
  const [activeTab, setActiveTab] = useState<'overview' | 'indicators' | 'telemetry' | 'json'>('overview');
  const [copied, setCopied] = useState(false);

  const copyUrl = () => {
    navigator.clipboard.writeText(scan.url);
    setCopied(true);
    success('URL copied to clipboard');
    setTimeout(() => setCopied(false), 2000);
  };

  const isPhishing = scan.classification === 'Phishing';
  const isSuspicious = scan.classification === 'Suspicious';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div
        className="w-full max-w-4xl max-h-[90vh] bg-[#111827] border border-[#263244] rounded-2xl shadow-2xl flex flex-col overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Top Header */}
        <div className="px-6 py-4 border-b border-[#263244] flex items-center justify-between bg-[#0E1526]">
          <div className="flex items-center gap-3">
            <div
              className={cn(
                'w-9 h-9 rounded-lg flex items-center justify-center border',
                isPhishing
                  ? 'bg-red-500/10 text-red-400 border-red-500/30'
                  : isSuspicious
                  ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                  : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
              )}
            >
              {isPhishing ? (
                <ShieldAlert className="w-5 h-5" />
              ) : isSuspicious ? (
                <AlertTriangle className="w-5 h-5" />
              ) : (
                <ShieldCheck className="w-5 h-5" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-bold text-slate-100 tracking-tight">
                  Security Forensics Dossier
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#162032] text-cyan-400 border border-[#263244]">
                  {scan.id}
                </span>
              </div>
              <p className="text-xs text-slate-400 truncate max-w-md font-mono mt-0.5">
                {scan.domain}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                downloadReportAsFile(scan, 'md');
                success('Markdown report downloaded');
              }}
              className="p-2 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-[#162032] border border-transparent hover:border-[#263244] transition-colors"
              title="Download report"
            >
              <Download className="w-4 h-4" />
            </button>
            <button
              onClick={onClose}
              className="p-2 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-[#162032] border border-transparent hover:border-[#263244] transition-colors"
              title="Close modal"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="px-6 border-b border-[#263244] flex items-center gap-6 bg-[#0E1526]/50">
          {(['overview', 'indicators', 'telemetry', 'json'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={cn(
                'py-3 text-xs font-medium uppercase tracking-wider font-mono border-b-2 transition-colors',
                activeTab === tab
                  ? 'border-cyan-400 text-cyan-300 font-semibold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              )}
            >
              {tab}
            </button>
          ))}
        </div>

        {/* Modal Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* URL Banner */}
              <div className="p-4 rounded-xl bg-[#0B1120] border border-[#263244] flex items-center justify-between gap-3">
                <div className="min-w-0 flex-1">
                  <p className="text-[11px] font-mono text-slate-500 uppercase">Analyzed URL</p>
                  <p className="text-sm font-mono text-slate-200 break-all select-all mt-0.5">
                    {scan.url}
                  </p>
                </div>
                <button
                  onClick={copyUrl}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#162032] hover:bg-[#1E293B] border border-[#263244] text-xs font-mono text-slate-300"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
              </div>

              {/* Gauge & Key Findings */}
              <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
                <div className="md:col-span-5 flex flex-col items-center justify-center p-4 rounded-xl bg-[#0B1120] border border-[#263244]">
                  <RiskGauge score={scan.riskScore} size={160} strokeWidth={11} />
                </div>
                <div className="md:col-span-7 space-y-3">
                  <div className="p-4 rounded-xl bg-[#0B1120] border border-[#263244] space-y-2">
                    <h4 className="text-xs font-semibold text-slate-200 uppercase font-mono">
                      Heuristic Classification
                    </h4>
                    <p className="text-xs text-slate-300 leading-relaxed">
                      {scan.aiAnalysis.summary}
                    </p>
                  </div>

                  <div className="p-4 rounded-xl bg-[#0B1120] border border-[#263244] space-y-2">
                    <h4 className="text-xs font-semibold text-slate-200 uppercase font-mono">
                      Threat Persona
                    </h4>
                    <div className="flex flex-wrap gap-2 text-xs">
                      <span className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 font-mono">
                        {scan.aiAnalysis.threatType}
                      </span>
                      {scan.aiAnalysis.impersonatedBrand && (
                        <span className="px-2 py-0.5 rounded bg-red-500/10 text-red-300 border border-red-500/20 font-mono">
                          Target: {scan.aiAnalysis.impersonatedBrand}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {/* Recommendations */}
              <div className="p-4 rounded-xl bg-[#0B1120] border border-[#263244] space-y-2">
                <h4 className="text-xs font-semibold text-slate-200 uppercase font-mono">
                  Prescribed Containment Steps
                </h4>
                <ul className="space-y-1.5">
                  {scan.recommendations.map((rec, i) => (
                    <li key={i} className="flex items-start gap-2 text-xs text-slate-300">
                      <span className="text-cyan-400 font-mono">[{i + 1}]</span>
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}

          {activeTab === 'indicators' && (
            <div className="space-y-3">
              <p className="text-xs text-slate-400 font-mono">
                Granular indicator verification matrix ({scan.indicators.length} security checks executed)
              </p>
              <div className="divide-y divide-[#263244] rounded-xl border border-[#263244] bg-[#0B1120] overflow-hidden">
                {scan.indicators.map((ind) => (
                  <div key={ind.id} className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-slate-200">{ind.name}</span>
                        <span
                          className={cn(
                            'text-[10px] font-mono uppercase px-1.5 py-0.5 rounded border',
                            ind.detected
                              ? 'bg-red-500/10 text-red-400 border-red-500/20'
                              : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                          )}
                        >
                          {ind.detected ? 'Triggered' : 'Passed'}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 mt-1">{ind.description}</p>
                    </div>
                    {ind.technicalDetail && (
                      <span className="text-xs font-mono text-slate-500 bg-[#162032] px-2 py-1 rounded border border-[#263244] self-start sm:self-center">
                        {ind.technicalDetail}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'telemetry' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 rounded-xl bg-[#0B1120] border border-[#263244] space-y-3">
                <div className="flex items-center gap-2 text-cyan-400">
                  <Server className="w-4 h-4" />
                  <h4 className="text-xs font-mono font-semibold uppercase text-slate-200">
                    Host & Network
                  </h4>
                </div>
                <div className="space-y-2 text-xs font-mono">
                  <div className="flex justify-between py-1 border-b border-[#263244]/50">
                    <span className="text-slate-500">Destination IP:</span>
                    <span className="text-slate-200">{scan.domainDetails.ipAddress || 'Dynamic Edge'}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-[#263244]/50">
                    <span className="text-slate-500">Host Type:</span>
                    <span className="text-slate-200">{scan.domainDetails.hasIpHost ? 'Direct IP Host' : 'DNS Hostname'}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-[#263244]/50">
                    <span className="text-slate-500">Geo Location:</span>
                    <span className="text-slate-200">{scan.domainDetails.country || 'Unknown'}</span>
                  </div>
                  <div className="flex justify-between py-1">
                    <span className="text-slate-500">Estimated Domain Age:</span>
                    <span className="text-slate-200">{scan.domainDetails.createdAgeDays ?? 'N/A'} days</span>
                  </div>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-[#0B1120] border border-[#263244] space-y-3">
                <div className="flex items-center gap-2 text-cyan-400">
                  <Globe className="w-4 h-4" />
                  <h4 className="text-xs font-mono font-semibold uppercase text-slate-200">
                    Domain & TLS Structure
                  </h4>
                </div>
                <div className="space-y-2 text-xs font-mono">
                  <div className="flex justify-between py-1 border-b border-[#263244]/50">
                    <span className="text-slate-500">TLD Extension:</span>
                    <span className="text-slate-200">{scan.domainDetails.tld}</span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-[#263244]/50">
                    <span className="text-slate-500">HTTPS Transport:</span>
                    <span className={scan.domainDetails.hasHttps ? 'text-emerald-400' : 'text-red-400'}>
                      {scan.domainDetails.hasHttps ? 'TLS Enabled' : 'Plaintext HTTP'}
                    </span>
                  </div>
                  <div className="flex justify-between py-1 border-b border-[#263244]/50">
                    <span className="text-slate-500">Subdomain Count:</span>
                    <span className="text-slate-200">{scan.domainDetails.subdomainCount}</span>
                  </div>
                  <div className="flex justify-between py-1">
                    <span className="text-slate-500">Registrar:</span>
                    <span className="text-slate-200 truncate max-w-[180px]">{scan.domainDetails.registrar || 'Hidden WHOIS'}</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'json' && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-400">Raw JSON Payload (FastAPI Schema Ready)</span>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(JSON.stringify(scan, null, 2));
                    success('JSON payload copied');
                  }}
                  className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                >
                  <Copy className="w-3 h-3" />
                  <span>Copy JSON</span>
                </button>
              </div>
              <pre className="p-4 rounded-xl bg-[#0B1120] border border-[#263244] text-[11px] font-mono text-cyan-300/90 overflow-x-auto max-h-96">
                {JSON.stringify(scan, null, 2)}
              </pre>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-[#263244] bg-[#0E1526] flex items-center justify-between text-xs">
          <span className="text-slate-500 font-mono">
            Scanned: {new Date(scan.timestamp).toLocaleString()}
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                downloadReportAsFile(scan, 'json');
                success('JSON report downloaded');
              }}
              className="px-3 py-1.5 rounded-lg bg-[#162032] hover:bg-[#1E293B] border border-[#263244] text-slate-300 font-mono text-xs transition-colors"
            >
              Export JSON
            </button>
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-[#041C24] font-semibold text-xs transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

