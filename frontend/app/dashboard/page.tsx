'use client';

import React, { useState, useEffect } from 'react';
import { Header } from '@/components/layout/Header';
import { StatisticsCard } from '@/components/dashboard/StatisticsCard';
import { ThreatActivityChart, ThreatDistributionChart } from '@/components/dashboard/ThreatChart';
import { ScanHistoryTable } from '@/components/history/ScanHistoryTable';
import { getStoredScans, deleteScanFromStorage } from '@/lib/storage';
import { MOCK_ACTIVITY_DATA, MOCK_THREAT_DISTRIBUTION } from '@/lib/mock-data';
import { ScanResult } from '@/types';
import Link from 'next/link';
import { ShieldCheck, Sparkles, ArrowRight, Activity, Terminal } from 'lucide-react';

export default function DashboardPage() {
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setScans(getStoredScans());
    setMounted(true);
  }, []);

  const handleDeleteScan = (id: string) => {
    const updated = deleteScanFromStorage(id);
    setScans(updated);
  };

  return (
    <div className="flex flex-col min-h-screen">
      {/* Top Header */}
      <Header
        title="Security Overview"
        subtitle="Monitor phishing threats and protect your digital environment."
      />

      <div className="p-6 lg:p-8 space-y-8 max-w-7xl mx-auto w-full">
        {/* Banner with Quick Action */}
        <div className="relative rounded-2xl bg-gradient-to-r from-[#111827] via-[#142033] to-[#111827] border border-[#263244] p-6 overflow-hidden flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="absolute right-0 top-0 bottom-0 w-1/3 bg-cyan-500/5 blur-3xl pointer-events-none" />

          <div className="space-y-1.5 z-10">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-xs font-mono font-medium text-emerald-400 uppercase tracking-wider">
                Threat Intelligence Engines Active
              </span>
            </div>
            <h2 className="text-lg lg:text-xl font-bold text-slate-100 tracking-tight">
              PhishGuard Autonomous Threat Defense
            </h2>
            <p className="text-xs text-slate-400 max-w-xl">
              Real-time heuristic evaluation inspects URL structure, lexical tokens, domain age, and SSL authenticity to prevent credential harvesting.
            </p>
          </div>

          <Link
            href="/scanner"
            className="z-10 px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-[#041C24] font-bold text-xs tracking-wide transition-all shadow-lg shadow-cyan-500/20 flex items-center gap-2 shrink-0 group"
          >
            <Sparkles className="w-4 h-4" />
            <span>Launch URL Scanner</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
          </Link>
        </div>

        {/* Statistics Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatisticsCard
            title="Total URLs Scanned"
            value="12,845"
            trend="+12.5%"
            trendDirection="up"
            iconName="scanned"
          />
          <StatisticsCard
            title="Phishing Detected"
            value="1,284"
            trend="+8.2%"
            trendDirection="up"
            iconName="phishing"
          />
          <StatisticsCard
            title="Safe Websites"
            value="10,932"
            trend="+5.4%"
            trendDirection="up"
            iconName="safe"
          />
          <StatisticsCard
            title="Threat Detection Rate"
            value="96.8%"
            trendDirection="up"
            iconName="rate"
          />
        </div>

        {/* Charts Grid: Section A (Activity) + Section B (Distribution) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-8">
            <ThreatActivityChart data={MOCK_ACTIVITY_DATA} />
          </div>
          <div className="lg:col-span-4">
            <ThreatDistributionChart data={MOCK_THREAT_DISTRIBUTION} />
          </div>
        </div>

        {/* Section C: Recent Scans */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-base font-semibold text-slate-100 tracking-tight">
                Recent Scans
              </h2>
              <p className="text-xs text-slate-400">
                Latest analyzed URLs with heuristic scores. Click any row for complete forensic detail.
              </p>
            </div>
            <Link
              href="/history"
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
            >
              <span>View Full History</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>

          <ScanHistoryTable
            scans={scans}
            onDeleteScan={handleDeleteScan}
            itemsPerPage={5}
            showFilters={false}
            title="Real-Time Inspection Log"
          />
        </div>
      </div>
    </div>
  );
}

