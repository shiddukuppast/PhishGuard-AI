'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import { Header } from '@/components/layout/Header';
import { ScanHistoryTable } from '@/components/history/ScanHistoryTable';
import { historyApi } from '@/lib/api';
import { ScanResult } from '@/types';
import { useToast } from '@/components/shared/ToastContext';
import {
  History,
  RotateCcw,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Search,
  Scan,
  RefreshCw,
} from 'lucide-react';

export default function HistoryPage() {
  const { success, error: toastError } = useToast();
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);

  const fetchHistory = useCallback(async () => {
    setIsLoading(true);
    setFetchError(null);
    try {
      const res = await historyApi.getHistory({ limit: 100 });
      setScans(res.scans || []);
    } catch (err: any) {
      console.error('Failed fetching scan history from backend:', err);
      setFetchError(err.message || 'Unable to connect to security database.');
      setScans([]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchHistory();
  }, [fetchHistory]);

  const handleDelete = async (id: string) => {
    try {
      await historyApi.deleteScan(id);
      setScans((prev) => prev.filter((s) => s.id !== id));
      success('Record Deleted', 'The audit record has been removed from MongoDB.');
    } catch (err: any) {
      toastError('Delete Failed', err.message || 'Could not delete record from server.');
    }
  };

  // Live summary counts computed directly from real MongoDB records
  const total = scans.length;
  const phishingCount = scans.filter((s) => s.classification === 'Phishing').length;
  const suspiciousCount = scans.filter((s) => s.classification === 'Suspicious').length;
  const safeCount = scans.filter((s) => s.classification === 'Safe').length;

  return (
    <div className="flex flex-col min-h-screen">
      <Header
        title="Scan History & Audit Log"
        subtitle="Historical repository of investigated URLs, classification tags, and forensic telemetry."
      />

      <div className="p-6 lg:p-8 space-y-6 max-w-7xl mx-auto w-full">
        {/* Top Summary Bar & Refresh Action */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#111827] border border-[#263244] text-xs font-mono">
              <span className="text-slate-400">Total Scans:</span>
              <span className="font-bold text-slate-100">{total}</span>
            </div>
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/20 text-xs font-mono text-red-400">
              <span>Phishing:</span>
              <span className="font-bold">{phishingCount}</span>
            </div>
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-xs font-mono text-amber-300">
              <span>Suspicious:</span>
              <span className="font-bold">{suspiciousCount}</span>
            </div>
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs font-mono text-emerald-400">
              <span>Safe:</span>
              <span className="font-bold">{safeCount}</span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={fetchHistory}
              disabled={isLoading}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#111827] hover:bg-[#162032] border border-[#263244] text-xs font-mono text-slate-300 hover:text-white transition-colors disabled:opacity-50"
              title="Refresh history from MongoDB"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${isLoading ? 'animate-spin' : ''}`} />
              <span>{isLoading ? 'Syncing...' : 'Refresh'}</span>
            </button>
          </div>
        </div>

        {/* Loading State */}
        {isLoading && scans.length === 0 ? (
          <div className="p-12 rounded-xl bg-[#111827] border border-[#263244] flex flex-col items-center justify-center text-center space-y-3">
            <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin" />
            <p className="text-sm font-mono text-slate-300">Loading audit history from MongoDB...</p>
          </div>
        ) : fetchError ? (
          /* Error State */
          <div className="p-8 rounded-xl bg-[#111827] border border-red-500/30 flex flex-col items-center justify-center text-center space-y-3">
            <AlertTriangle className="w-8 h-8 text-red-400" />
            <div className="space-y-1">
              <h4 className="text-sm font-semibold text-slate-100">Unable to Load Scan History</h4>
              <p className="text-xs text-slate-400 max-w-md">{fetchError}</p>
            </div>
            <button
              onClick={fetchHistory}
              className="px-4 py-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-xs font-mono text-cyan-300 hover:bg-cyan-500/20 transition-colors"
            >
              Retry Connection
            </button>
          </div>
        ) : scans.length === 0 ? (
          /* Honest Empty State */
          <div className="p-12 rounded-xl bg-[#111827] border border-[#263244] flex flex-col items-center justify-center text-center space-y-4">
            <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
              <History className="w-6 h-6" />
            </div>
            <div className="space-y-1 max-w-md">
              <h4 className="text-base font-semibold text-slate-100">No scans found</h4>
              <p className="text-xs text-slate-400">
                Start by scanning a URL to generate live forensic analysis, risk scoring, and audit telemetry.
              </p>
            </div>
            <Link
              href="/scanner"
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs transition-colors"
            >
              <Scan className="w-4 h-4" />
              <span>Launch URL Scanner</span>
            </Link>
          </div>
        ) : (
          /* Real Data Table */
          <ScanHistoryTable
            scans={scans}
            onDeleteScan={handleDelete}
            itemsPerPage={8}
            showFilters={true}
            title="Investigated URLs Database"
          />
        )}
      </div>
    </div>
  );
}
