'use client';

import React, { useState, useEffect } from 'react';
import { Header } from '@/components/layout/Header';
import { StatisticsCard } from '@/components/dashboard/StatisticsCard';
import { ThreatActivityChart, ThreatDistributionChart } from '@/components/dashboard/ThreatChart';
import { ScanHistoryTable } from '@/components/history/ScanHistoryTable';
import { dashboardApi, historyApi } from '@/lib/api';
import { ScanResult, ActivityDataPoint } from '@/types';
import Link from 'next/link';
import { ShieldCheck, Sparkles, ArrowRight, ShieldAlert, AlertCircle, Loader2 } from 'lucide-react';
import { useToast } from '@/components/shared/ToastContext';

export default function DashboardPage() {
  const { success, error: toastError } = useToast();
  const [recentScans, setRecentScans] = useState<ScanResult[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [stats, setStats] = useState({
    totalScans: 0,
    phishingDetected: 0,
    suspiciousDetected: 0,
    safeWebsites: 0,
    averageRiskScore: 0.0,
    detectionRate: 0.0,
    trends: {
      scanned: '0',
      phishing: '0',
      safe: '0',
    },
  });
  const [activityData, setActivityData] = useState<ActivityDataPoint[]>([]);

  useEffect(() => {
    let isMounted = true;

    async function loadDashboardData() {
      setIsLoading(true);
      try {
        // Fetch stats, activity, and recent scans concurrently from FastAPI backend
        const [statsRes, activityRes, recentRes] = await Promise.allSettled([
          dashboardApi.getStats(),
          dashboardApi.getActivity(),
          dashboardApi.getRecentScans(),
        ]);

        if (!isMounted) return;

        if (statsRes.status === 'fulfilled' && statsRes.value) {
          const s = statsRes.value;
          setStats({
            totalScans: s.total_scanned,
            phishingDetected: s.phishing_detected,
            suspiciousDetected: s.suspicious_detected,
            safeWebsites: s.legitimate_urls,
            averageRiskScore: s.average_risk_score,
            detectionRate: s.detection_rate,
            trends: {
              scanned: s.trends?.scanned || '0',
              phishing: s.trends?.phishing || '0',
              safe: s.trends?.safe || '0',
            },
          });
        }

        if (activityRes.status === 'fulfilled' && activityRes.value?.activity) {
          setActivityData(activityRes.value.activity);
        } else {
          // If no activity yet, set clean empty 7-day baseline
          const today = new Date();
          const emptyDays: ActivityDataPoint[] = [];
          for (let i = 6; i >= 0; i--) {
            const d = new Date(today);
            d.setDate(d.getDate() - i);
            emptyDays.push({
              date: d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
              phishing: 0,
              suspicious: 0,
              safe: 0,
              total: 0,
            });
          }
          setActivityData(emptyDays);
        }

        if (recentRes.status === 'fulfilled' && Array.isArray(recentRes.value)) {
          setRecentScans(recentRes.value);
        }
      } catch (err) {
        console.error('Failed loading dashboard metrics:', err);
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    }

    loadDashboardData();

    return () => {
      isMounted = false;
    };
  }, []);

  const handleDeleteScan = async (id: string) => {
    try {
      await historyApi.deleteScan(id);
      setRecentScans((prev) => prev.filter((s) => s.id !== id));
      success('Record Deleted', 'The audit record has been removed.');
      // Refresh stats
      const updatedStats = await dashboardApi.getStats();
      if (updatedStats) {
        setStats({
          totalScans: updatedStats.total_scanned,
          phishingDetected: updatedStats.phishing_detected,
          suspiciousDetected: updatedStats.suspicious_detected,
          safeWebsites: updatedStats.legitimate_urls,
          averageRiskScore: updatedStats.average_risk_score,
          detectionRate: updatedStats.detection_rate,
          trends: {
            scanned: updatedStats.trends?.scanned || '0',
            phishing: updatedStats.trends?.phishing || '0',
            safe: updatedStats.trends?.safe || '0',
          },
        });
      }
    } catch (err: any) {
      console.error('Failed to delete scan record:', err);
      toastError('Delete Failed', err.message || 'Could not delete record from server.');
    }
  };

  // Threat distribution points calculated strictly from MongoDB counts
  const distributionData = [
    { name: 'Phishing', value: stats.phishingDetected, color: '#EF4444' },
    { name: 'Suspicious', value: stats.suspiciousDetected, color: '#F59E0B' },
    { name: 'Legitimate', value: stats.safeWebsites, color: '#10B981' },
  ];

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
                MongoDB Threat Store Connected
              </span>
            </div>
            <h2 className="text-lg lg:text-xl font-bold text-slate-100 tracking-tight">
              PhishGuard Autonomous Threat Defense
            </h2>
            <p className="text-xs text-slate-400 max-w-xl">
              Inspect suspicious URLs in real-time. Structural anomaly extraction, ML heuristics, and threat feeds protect your environment.
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

        {/* Statistics Cards - 5 Real Metrics from MongoDB */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          <StatisticsCard
            title="Total URLs Scanned"
            value={stats.totalScans}
            trend={stats.trends.scanned}
            trendDirection="neutral"
            trendSubtext="Total user scans"
            iconName="scanned"
          />
          <StatisticsCard
            title="Phishing Detected"
            value={stats.phishingDetected}
            trend={stats.trends.phishing}
            trendDirection="neutral"
            trendSubtext="Confirmed phishing"
            iconName="phishing"
          />
          <StatisticsCard
            title="Suspicious URLs"
            value={stats.suspiciousDetected}
            trend="0"
            trendDirection="neutral"
            trendSubtext="Anomalous heuristics"
            iconName="suspicious"
          />
          <StatisticsCard
            title="Legitimate URLs"
            value={stats.safeWebsites}
            trend={stats.trends.safe}
            trendDirection="neutral"
            trendSubtext="Benign web hosts"
            iconName="safe"
          />
          <StatisticsCard
            title="Average Risk Score"
            value={stats.totalScans > 0 ? `${stats.averageRiskScore}/100` : '0/100'}
            trend={`${stats.detectionRate}%`}
            trendDirection="neutral"
            trendSubtext="Detection rate"
            iconName="score"
          />
        </div>

        {/* Charts Grid: Section A (Activity) + Section B (Distribution) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-8">
            <ThreatActivityChart data={activityData} />
          </div>
          <div className="lg:col-span-4">
            <ThreatDistributionChart data={distributionData} />
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
                Latest analyzed URLs from MongoDB. Click any record for complete forensic breakdown.
              </p>
            </div>
            {recentScans.length > 0 && (
              <Link
                href="/history"
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
              >
                <span>View Full History</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            )}
          </div>

          {isLoading ? (
            <div className="p-12 rounded-xl bg-[#111827] border border-[#263244] flex flex-col items-center justify-center gap-3">
              <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
              <span className="text-xs font-mono text-slate-400">Loading audit records from database...</span>
            </div>
          ) : recentScans.length === 0 ? (
            <div className="p-12 rounded-xl bg-[#111827] border border-[#263244] flex flex-col items-center justify-center text-center space-y-4">
              <div className="w-12 h-12 rounded-full bg-[#0B1120] border border-[#263244] flex items-center justify-center text-slate-500">
                <ShieldCheck className="w-6 h-6 text-cyan-400" />
              </div>
              <div className="space-y-1">
                <h3 className="text-sm font-semibold text-slate-200">No Scans Recorded Yet</h3>
                <p className="text-xs text-slate-400 max-w-sm">
                  Your security overview is clear. Paste any website address into the URL Scanner to generate your first forensic report.
                </p>
              </div>
              <Link
                href="/scanner"
                className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-[#041C24] font-semibold text-xs tracking-wide transition-all shadow-md shadow-cyan-500/20 flex items-center gap-1.5"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>Scan a URL</span>
              </Link>
            </div>
          ) : (
            <ScanHistoryTable
              scans={recentScans}
              onDeleteScan={handleDeleteScan}
              itemsPerPage={5}
              showFilters={false}
              title="Recent Audit Log"
            />
          )}
        </div>
      </div>
    </div>
  );
}
