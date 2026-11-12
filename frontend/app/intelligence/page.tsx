'use client';

import React, { useState, useEffect, useCallback } from 'react';
import { Header } from '@/components/layout/Header';
import {
  Radio,
  ShieldAlert,
  Globe,
  Database,
  ExternalLink,
  Layers,
  AlertTriangle,
  Info,
  CheckCircle2,
  RefreshCw,
  Search,
  Server,
  FileCode,
  Sparkles,
  Send,
  XCircle,
} from 'lucide-react';
import { intelligenceApi } from '@/lib/api';
import { useToast } from '@/components/shared/ToastContext';
import { cn } from '@/lib/utils';

interface ThreatFeedItem {
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
}

interface SuspiciousPattern {
  id: string;
  pattern: string;
  description: string;
  frequency: string;
  risk_weight: string;
  example: string;
}

interface SourceStatus {
  configured: boolean;
  service: string;
  type: string;
  status: string;
  message: string;
  last_checked: string;
}

export default function ThreatIntelligencePage() {
  const { success, error: toastError, info: showInfo } = useToast();
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSource, setSelectedSource] = useState<'All' | 'PhishTank' | 'OpenPhish' | 'Internal Heuristics'>('All');
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Live data states
  const [sources, setSources] = useState<{ [key: string]: SourceStatus }>({});
  const [activeThreats, setActiveThreats] = useState<ThreatFeedItem[]>([]);
  const [patterns, setPatterns] = useState<SuspiciousPattern[]>([]);
  const [metrics, setMetrics] = useState({
    tracked_campaigns: 0,
    top_target_sector: 'None',
    avg_lure_lifespan_hours: 0,
    heuristic_accuracy_pct: 0,
  });

  // On-demand URL check state
  const [checkUrlInput, setCheckUrlInput] = useState('');
  const [isChecking, setIsChecking] = useState(false);
  const [checkResult, setCheckResult] = useState<any | null>(null);

  const fetchOverview = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const data = await intelligenceApi.getOverview();
      if (data) {
        setSources(data.sources || {});
        setActiveThreats(data.active_threats_sample || []);
        setPatterns(data.suspicious_patterns || []);
        if (data.metrics) {
          setMetrics(data.metrics);
        }
      }
    } catch (err: any) {
      console.error('Failed fetching intelligence overview:', err);
    } finally {
      setIsRefreshing(false);
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchOverview();
  }, [fetchOverview]);

  const handleRefreshFeed = async () => {
    await fetchOverview();
    success('Threat Telemetry Synced', 'Updated live feeds and indicators from FastAPI gateway.');
  };

  const handleCheckUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!checkUrlInput.trim()) return;

    setIsChecking(true);
    setCheckResult(null);
    try {
      const res = await intelligenceApi.checkUrl(checkUrlInput.trim());
      setCheckResult(res);
      success('Verification Completed', `Evaluated threat feeds for ${res.domain || 'target'}`);
    } catch (err: any) {
      toastError('Verification Failed', err.message || 'Unable to check URL with backend.');
    } finally {
      setIsChecking(false);
    }
  };

  const ptConfigured = sources.phishtank?.configured ?? false;
  const opConfigured = sources.openphish?.configured ?? false;

  const filteredFeed = activeThreats.filter((item) => {
    const matchesSearch =
      item.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.domain.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.target_brand.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSource = selectedSource === 'All' || item.source === selectedSource;

    return matchesSearch && matchesSource;
  });

  return (
    <div className="flex flex-col min-h-screen">
      <Header
        title="Threat Intelligence Radar"
        subtitle="Global phishing telemetry, zero-day threat feeds, and domain pattern heuristics."
      />

      <div className="p-6 lg:p-8 space-y-8 max-w-7xl mx-auto w-full">
        {/* Honest Feed Status Banner */}
        <div className="p-4 rounded-xl bg-[#111827] border border-cyan-500/30 flex items-start gap-3">
          <Info className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <h4 className="text-xs font-semibold text-slate-100 font-mono uppercase tracking-wide">
              Threat Intelligence Feed Gateway Status
            </h4>
            <p className="text-xs text-slate-300 leading-relaxed">
              {!ptConfigured && !opConfigured ? (
                <>
                  External feed integration (PhishTank & OpenPhish) is currently running in local inspection mode.
                  To enable commercial real-time polling, configure <code className="text-cyan-400 bg-slate-900 px-1 py-0.5 rounded">PHISHTANK_API_KEY</code> and{' '}
                  <code className="text-cyan-400 bg-slate-900 px-1 py-0.5 rounded">OPENPHISH_API_KEY</code> in <code className="text-slate-300">backend/.env</code>.
                  Verified phishing detections below are retrieved from real MongoDB scan records.
                </>
              ) : (
                <>
                  External threat intelligence feeds are active and integrated with the FastAPI threat intelligence engine.
                </>
              )}
            </p>
          </div>
        </div>

        {/* Real Intelligence Stats Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-[#111827] border border-[#263244] space-y-1">
            <span className="text-[11px] font-mono text-slate-400 uppercase">Tracked Malicious Scans</span>
            <p className="text-2xl font-bold text-slate-100 font-sans">{metrics.tracked_campaigns}</p>
            <span className="text-[10px] font-mono text-cyan-400 block">Verified in database</span>
          </div>
          <div className="p-4 rounded-xl bg-[#111827] border border-[#263244] space-y-1">
            <span className="text-[11px] font-mono text-slate-400 uppercase">Dominant Threat Vector</span>
            <p className="text-2xl font-bold text-cyan-400 font-sans">{metrics.top_target_sector}</p>
            <span className="text-[10px] font-mono text-slate-500 block">Identified by risk engine</span>
          </div>
          <div className="p-4 rounded-xl bg-[#111827] border border-[#263244] space-y-1">
            <span className="text-[11px] font-mono text-slate-400 uppercase">Avg Lure Lifespan</span>
            <p className="text-2xl font-bold text-amber-400 font-sans">
              {metrics.avg_lure_lifespan_hours > 0 ? `${metrics.avg_lure_lifespan_hours}h` : 'N/A'}
            </p>
            <span className="text-[10px] font-mono text-slate-500 block">Bulletproof rotation cycle</span>
          </div>
          <div className="p-4 rounded-xl bg-[#111827] border border-[#263244] space-y-1">
            <span className="text-[11px] font-mono text-slate-400 uppercase">Heuristic Accuracy</span>
            <p className="text-2xl font-bold text-emerald-400 font-sans">
              {metrics.heuristic_accuracy_pct > 0 ? `${metrics.heuristic_accuracy_pct}%` : 'N/A'}
            </p>
            <span className="text-[10px] font-mono text-slate-500 block">Multi-layer verification</span>
          </div>
        </div>

        {/* On-Demand URL Threat Feed Check Tool */}
        <div className="p-5 rounded-xl bg-[#111827] border border-[#263244] space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-100 tracking-tight flex items-center gap-2">
              <Search className="w-4 h-4 text-cyan-400" />
              On-Demand Threat Feed Verification
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Query the FastAPI threat intelligence engine directly to verify whether a URL is listed in known threat databases.
            </p>
          </div>

          <form onSubmit={handleCheckUrl} className="flex flex-col sm:flex-row gap-2">
            <input
              type="text"
              value={checkUrlInput}
              onChange={(e) => setCheckUrlInput(e.target.value)}
              placeholder="Enter URL to check (e.g. http://suspicious-login.example.com)..."
              className="flex-1 px-3 py-2 rounded-lg bg-[#0B1120] border border-[#263244] text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
            />
            <button
              type="submit"
              disabled={isChecking || !checkUrlInput.trim()}
              className="flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 text-xs font-semibold font-mono transition-colors"
            >
              <Send className={`w-3.5 h-3.5 ${isChecking ? 'animate-spin' : ''}`} />
              <span>{isChecking ? 'Checking...' : 'Check Feeds'}</span>
            </button>
          </form>

          {checkResult && (
            <div className="p-4 rounded-lg bg-[#0B1120] border border-[#263244] space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-[#263244] pb-2">
                <span className="text-slate-400">Target: <strong className="text-slate-100">{checkResult.url}</strong></span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${checkResult.has_threat_intel_match ? 'bg-red-500/20 text-red-400 border border-red-500/30' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'}`}>
                  {checkResult.has_threat_intel_match ? 'THREAT MATCH DETECTED' : 'NO KNOWN LISTINGS'}
                </span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-[11px]">
                <div className="p-2.5 rounded bg-[#111827] border border-[#263244] space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200">PhishTank</span>
                    <span className="text-slate-400">{checkResult.phishtank?.status || 'Checked'}</span>
                  </div>
                  <p className="text-slate-400 text-[10px]">{checkResult.phishtank?.message || 'No active listing reported.'}</p>
                </div>
                <div className="p-2.5 rounded bg-[#111827] border border-[#263244] space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-slate-200">OpenPhish</span>
                    <span className="text-slate-400">{checkResult.openphish?.status || 'Checked'}</span>
                  </div>
                  <p className="text-slate-400 text-[10px]">{checkResult.openphish?.message || 'No active listing reported.'}</p>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Section: Known Phishing Domains from MongoDB */}
        <div className="bg-[#111827] border border-[#263244] rounded-xl overflow-hidden shadow-lg space-y-4 p-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Radio className="w-4 h-4 text-red-400 animate-pulse" />
                <h3 className="text-sm font-semibold text-slate-100 tracking-tight">
                  Verified Phishing Signatures (Database Ingest)
                </h3>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Malicious URLs recorded and confirmed by security scans in your MongoDB database
              </p>
            </div>

            <button
              onClick={handleRefreshFeed}
              disabled={isRefreshing}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0B1120] hover:bg-[#162032] border border-[#263244] text-xs font-mono text-slate-300 transition-colors self-start sm:self-center disabled:opacity-50"
            >
              <RefreshCw className={cn('w-3.5 h-3.5 text-cyan-400', isRefreshing && 'animate-spin')} />
              <span>{isRefreshing ? 'Syncing...' : 'Sync Radar'}</span>
            </button>
          </div>

          {/* Search & Source Filter */}
          <div className="flex flex-col sm:flex-row gap-3 pt-2">
            <div className="relative flex-1">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search domain, target brand, or category..."
                className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-[#0B1120] border border-[#263244] text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center gap-1 bg-[#0B1120] p-1 rounded-lg border border-[#263244]">
              {(['All', 'PhishTank', 'OpenPhish', 'Internal Heuristics'] as const).map((source) => (
                <button
                  key={source}
                  onClick={() => setSelectedSource(source)}
                  className={`px-3 py-1 text-[11px] font-mono rounded transition-colors ${
                    selectedSource === source
                      ? 'bg-[#162032] text-cyan-400 font-semibold border border-[#263244]'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {source}
                </button>
              ))}
            </div>
          </div>

          {/* Threat List Table or Empty State */}
          <div className="overflow-x-auto pt-2">
            {filteredFeed.length === 0 ? (
              <div className="py-12 px-4 text-center space-y-2">
                <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto" />
                <h4 className="text-sm font-semibold text-slate-200 font-mono">No Active Phishing Records in Database</h4>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  When the scanner flags malicious URLs or confirms phishing signatures, they will be indexed here in real-time.
                </p>
              </div>
            ) : (
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-[#263244] bg-[#0E1526]/80 text-[11px] font-mono uppercase tracking-wider text-slate-400">
                    <th className="py-2.5 px-3">Target & URL</th>
                    <th className="py-2.5 px-3">Category</th>
                    <th className="py-2.5 px-3">Risk Score</th>
                    <th className="py-2.5 px-3">Detection Source</th>
                    <th className="py-2.5 px-3">Domain</th>
                    <th className="py-2.5 px-3 text-right">Recorded At</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#263244]/60">
                  {filteredFeed.map((threat) => (
                    <tr key={threat.id} className="hover:bg-[#162032]/40 transition-colors">
                      <td className="py-3 px-3 max-w-xs md:max-w-sm">
                        <div className="flex flex-col min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="font-semibold text-slate-100">{threat.target_brand}</span>
                            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-red-500/10 text-red-400 border border-red-500/20">
                              {threat.status}
                            </span>
                          </div>
                          <span className="font-mono text-[11px] text-slate-400 truncate mt-0.5">
                            {threat.url}
                          </span>
                        </div>
                      </td>

                      <td className="py-3 px-3 whitespace-nowrap">
                        <span className="text-slate-300 font-mono text-xs">{threat.category}</span>
                      </td>

                      <td className="py-3 px-3 whitespace-nowrap">
                        <div className="flex items-center gap-1.5 font-mono text-xs">
                          <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                          <span className="text-red-400 font-semibold">{threat.confidence}</span>
                          <span className="text-[10px] text-slate-500">/100</span>
                        </div>
                      </td>

                      <td className="py-3 px-3 whitespace-nowrap font-mono text-xs text-cyan-400">
                        {threat.source}
                      </td>

                      <td className="py-3 px-3 whitespace-nowrap font-mono text-xs text-slate-400 truncate max-w-[150px]">
                        {threat.domain}
                      </td>

                      <td className="py-3 px-3 whitespace-nowrap font-mono text-xs text-slate-500 text-right">
                        {threat.reported_at}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* Section: Suspicious URL Patterns */}
        <div className="space-y-4">
          <div>
            <h3 className="text-base font-semibold text-slate-100 tracking-tight">
              Suspicious URL Heuristic Patterns
            </h3>
            <p className="text-xs text-slate-400">
              Structural evasion signatures evaluated by the PhishGuard AI heuristics engine
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {patterns.map((item) => (
              <div
                key={item.id}
                className="p-5 rounded-xl bg-[#111827] border border-[#263244] space-y-3 hover:border-[#334155] transition-colors"
              >
                <div className="flex items-start justify-between gap-2">
                  <h4 className="text-sm font-semibold text-slate-100 tracking-tight">
                    {item.pattern}
                  </h4>
                  <span
                    className={cn(
                      'text-[10px] font-mono uppercase px-2 py-0.5 rounded border',
                      item.risk_weight === 'Critical'
                        ? 'bg-red-500/10 text-red-400 border-red-500/30'
                        : 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                    )}
                  >
                    {item.risk_weight} Weight
                  </span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">
                  {item.description}
                </p>

                <div className="pt-2 border-t border-[#263244] flex flex-col gap-1.5 text-xs font-mono">
                  <div className="flex justify-between text-slate-400 text-[11px]">
                    <span>Observed Frequency:</span>
                    <span className="text-cyan-400 font-semibold">{item.frequency}</span>
                  </div>
                  <div className="p-2 rounded bg-[#0B1120] border border-[#263244] text-[11px] text-slate-400 truncate">
                    <span className="text-slate-500 mr-2">Example:</span>
                    <span className="text-red-300">{item.example}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Threat Intelligence Source Telemetry Section */}
        <div className="p-6 rounded-2xl bg-[#0E1526] border border-[#263244] space-y-4">
          <div className="flex items-center gap-2.5">
            <Database className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-100 tracking-tight">
              Threat Intelligence Sources & Gateway Integrations
            </h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            {/* PhishTank Card */}
            <div className="p-4 rounded-xl bg-[#111827] border border-[#263244] space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-100 text-sm">PhishTank</span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                  sources.phishtank?.configured
                    ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30'
                    : 'text-amber-400 bg-amber-500/10 border-amber-500/30'
                }`}>
                  {sources.phishtank?.status || 'Checking...'}
                </span>
              </div>
              <p className="text-slate-300 leading-relaxed text-xs">
                Community-driven clearing house for verified phishing destinations. Integrates verified submission IDs and analyst validation votes.
              </p>
              <div className="pt-2 text-[11px] font-mono text-slate-400">
                {sources.phishtank?.message || 'Connector initialized.'}
              </div>
            </div>

            {/* OpenPhish Card */}
            <div className="p-4 rounded-xl bg-[#111827] border border-[#263244] space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-100 text-sm">OpenPhish</span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                  sources.openphish?.configured
                    ? 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30'
                    : 'text-amber-400 bg-amber-500/10 border-amber-500/30'
                }`}>
                  {sources.openphish?.status || 'Checking...'}
                </span>
              </div>
              <p className="text-slate-300 leading-relaxed text-xs">
                Autonomous zero-day phishing detection feed utilizing proprietary heuristic algorithms for rapid URL discovery and classification.
              </p>
              <div className="pt-2 text-[11px] font-mono text-slate-400">
                {sources.openphish?.message || 'Connector initialized.'}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
