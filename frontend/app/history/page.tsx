'use client';

import React, { useState, useEffect } from 'react';
import { Header } from '@/components/layout/Header';
import { ScanHistoryTable } from '@/components/history/ScanHistoryTable';
import { getStoredScans, deleteScanFromStorage, resetScansToDefault } from '@/lib/storage';
import { ScanResult } from '@/types';
import { useToast } from '@/components/shared/ToastContext';
import { History, RotateCcw, Download, ShieldCheck, ShieldAlert, Sparkles } from 'lucide-react';

export default function HistoryPage() {
  const { success } = useToast();
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setScans(getStoredScans());
    setMounted(true);
  }, []);

  const handleDelete = (id: string) => {
    const updated = deleteScanFromStorage(id);
    setScans(updated);
  };

  const handleResetDefaults = () => {
    const defaults = resetScansToDefault();
    setScans(defaults);
    success('History Reset', 'Restored default security audit baseline records.');
  };

  // Quick summary counts
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
        {/* Top Summary Bar & Reset Action */}
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
              onClick={handleResetDefaults}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#111827] hover:bg-[#162032] border border-[#263244] text-xs font-mono text-slate-300 hover:text-white transition-colors"
              title="Reset history to sample dataset"
            >
              <RotateCcw className="w-3.5 h-3.5 text-cyan-400" />
              <span>Reset Samples</span>
            </button>
          </div>
        </div>

        {/* Scan History Table with Search, Classification Filter, Risk Sorting & Pagination */}
        <ScanHistoryTable
          scans={scans}
          onDeleteScan={handleDelete}
          itemsPerPage={8}
          showFilters={true}
          title="Investigated URLs Database"
        />
      </div>
    </div>
  );
}

