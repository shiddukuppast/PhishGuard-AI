'use client';

import React, { useState } from 'react';
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
} from 'lucide-react';
import { MOCK_THREAT_FEED, MOCK_SUSPICIOUS_PATTERNS } from '@/lib/mock-data';
import { useToast } from '@/components/shared/ToastContext';
import { cn } from '@/lib/utils';

export default function ThreatIntelligencePage() {
  const { success, info: showInfo } = useToast();
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedSource, setSelectedSource] = useState<'All' | 'PhishTank' | 'OpenPhish' | 'Internal ML'>('All');
  const [feedItems, setFeedItems] = useState(MOCK_THREAT_FEED);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const handleRefreshFeed = () => {
    setIsRefreshing(true);
    setTimeout(() => {
      setIsRefreshing(false);
      success('Threat Feed Refreshed', 'Synced simulated signatures from OpenPhish and PhishTank.');
    }, 1000);
  };

  const filteredFeed = feedItems.filter((item) => {
    const matchesSearch =
      item.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.domain.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.targetBrand.toLowerCase().includes(searchTerm.toLowerCase());

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
        {/* Mock Notice Warning Banner - Explicit user requirement */}
        <div className="p-4 rounded-xl bg-[#111827] border border-amber-500/30 flex items-start gap-3">
          <Info className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <h4 className="text-xs font-semibold text-slate-100 font-mono uppercase tracking-wide">
              Simulated Threat Intelligence Feeds
            </h4>
            <p className="text-xs text-slate-300 leading-relaxed">
              External threat telemetry from <span className="font-semibold text-cyan-400">PhishTank</span> and{' '}
              <span className="font-semibold text-cyan-400">OpenPhish</span> is currently rendered using synthetic demonstration datasets. Production API credentials will integrate with the Python FastAPI backend gateway in subsequent releases.
            </p>
          </div>
        </div>

        {/* Top Intelligence Stats Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-[#111827] border border-[#263244] space-y-1">
            <span className="text-[11px] font-mono text-slate-400 uppercase">Tracked Active Campaigns</span>
            <p className="text-2xl font-bold text-slate-100 font-sans">4,129</p>
            <span className="text-[10px] font-mono text-red-400 block">+142 discovered today</span>
          </div>
          <div className="p-4 rounded-xl bg-[#111827] border border-[#263244] space-y-1">
            <span className="text-[11px] font-mono text-slate-400 uppercase">Top Target Sector</span>
            <p className="text-2xl font-bold text-cyan-400 font-sans">Fintech / Banking</p>
            <span className="text-[10px] font-mono text-slate-500 block">41.8% of active lures</span>
          </div>
          <div className="p-4 rounded-xl bg-[#111827] border border-[#263244] space-y-1">
            <span className="text-[11px] font-mono text-slate-400 uppercase">Avg Lure Lifespan</span>
            <p className="text-2xl font-bold text-amber-400 font-sans">18.4 Hours</p>
            <span className="text-[10px] font-mono text-slate-500 block">Fast bulletproof rotation</span>
          </div>
          <div className="p-4 rounded-xl bg-[#111827] border border-[#263244] space-y-1">
            <span className="text-[11px] font-mono text-slate-400 uppercase">Detection Accuracy</span>
            <p className="text-2xl font-bold text-emerald-400 font-sans">98.4%</p>
            <span className="text-[10px] font-mono text-slate-500 block">Validated against ground truth</span>
          </div>
        </div>

        {/* Section: Known Phishing Domains & Recent Identified Threats */}
        <div className="bg-[#111827] border border-[#263244] rounded-xl overflow-hidden shadow-lg space-y-4 p-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <Radio className="w-4 h-4 text-red-400 animate-pulse" />
                <h3 className="text-sm font-semibold text-slate-100 tracking-tight">
                  Live Phishing Stream (Simulated Ingest)
                </h3>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Continuously verified malicious URLs harvested from global honeypots and reporting feeds
              </p>
            </div>

            <button
              onClick={handleRefreshFeed}
              disabled={isRefreshing}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0B1120] hover:bg-[#162032] border border-[#263244] text-xs font-mono text-slate-300 transition-colors self-start sm:self-center"
            >
              <RefreshCw className={cn('w-3.5 h-3.5 text-cyan-400', isRefreshing && 'animate-spin')} />
              <span>{isRefreshing ? 'Syncing...' : 'Sync Feed'}</span>
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
              {(['All', 'PhishTank', 'OpenPhish', 'Internal ML'] as const).map((source) => (
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

          {/* Threat List Table */}
          <div className="overflow-x-auto pt-2">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#263244] bg-[#0E1526]/80 text-[11px] font-mono uppercase tracking-wider text-slate-400">
                  <th className="py-2.5 px-3">Target & URL</th>
                  <th className="py-2.5 px-3">Category</th>
                  <th className="py-2.5 px-3">Confidence</th>
                  <th className="py-2.5 px-3">Source Feed</th>
                  <th className="py-2.5 px-3">Host IP</th>
                  <th className="py-2.5 px-3 text-right">Reported</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#263244]/60">
                {filteredFeed.map((threat) => (
                  <tr key={threat.id} className="hover:bg-[#162032]/40 transition-colors">
                    <td className="py-3 px-3 max-w-xs md:max-w-sm">
                      <div className="flex flex-col min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-slate-100">{threat.targetBrand}</span>
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
                        <span className="text-red-400 font-semibold">{threat.confidence}%</span>
                      </div>
                    </td>

                    <td className="py-3 px-3 whitespace-nowrap font-mono text-xs text-cyan-400">
                      {threat.source}
                    </td>

                    <td className="py-3 px-3 whitespace-nowrap font-mono text-xs text-slate-400">
                      {threat.ipAddress}
                    </td>

                    <td className="py-3 px-3 whitespace-nowrap font-mono text-xs text-slate-500 text-right">
                      {threat.reportedAt}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Section: Suspicious URL Patterns */}
        <div className="space-y-4">
          <div>
            <h3 className="text-base font-semibold text-slate-100 tracking-tight">
              Suspicious URL Heuristic Patterns
            </h3>
            <p className="text-xs text-slate-400">
              Structural indicators leveraged by PhishGuard AI ML models to detect zero-day evasion
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {MOCK_SUSPICIOUS_PATTERNS.map((item) => (
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
                      item.riskWeight === 'Critical'
                        ? 'bg-red-500/10 text-red-400 border-red-500/30'
                        : 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                    )}
                  >
                    {item.riskWeight} Weight
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

        {/* Threat Intelligence Source Documentation Section */}
        <div className="p-6 rounded-2xl bg-[#0E1526] border border-[#263244] space-y-4">
          <div className="flex items-center gap-2.5">
            <Database className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-100 tracking-tight">
              Threat Intelligence Sources & Upstream Telemetry
            </h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
            {/* PhishTank Card */}
            <div className="p-4 rounded-xl bg-[#111827] border border-[#263244] space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-100 text-sm">PhishTank</span>
                <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                  Open Community Feed
                </span>
              </div>
              <p className="text-slate-300 leading-relaxed text-xs">
                Community-driven clearing house for phishing data. Validated votes from global cybersecurity analysts verify active malicious operations.
              </p>
              <div className="pt-2 text-[11px] font-mono text-slate-500">
                Status: <span className="text-amber-400">Simulated Adapter (API connector ready)</span>
              </div>
            </div>

            {/* OpenPhish Card */}
            <div className="p-4 rounded-xl bg-[#111827] border border-[#263244] space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-bold text-slate-100 text-sm">OpenPhish</span>
                <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                  Autonomous AI Crawler
                </span>
              </div>
              <p className="text-slate-300 leading-relaxed text-xs">
                Automated platform that detects zero-day phishing through heuristic proprietary algorithms and real-time algorithmic inspection of newly active web hosts.
              </p>
              <div className="pt-2 text-[11px] font-mono text-slate-500">
                Status: <span className="text-amber-400">Simulated Adapter (FastAPI Webhook ready)</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

