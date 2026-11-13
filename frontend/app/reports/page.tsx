'use client';

import React, { useState, useEffect, useCallback } from 'react';
import Link from 'next/link';
import { Header } from '@/components/layout/Header';
import {
  FileText,
  Download,
  Search,
  Eye,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileCheck,
  RefreshCw,
  PlusCircle,
  Scan,
} from 'lucide-react';
import { GeneratedReport, ScanResult } from '@/types';
import { reportsApi, historyApi } from '@/lib/api';
import { useToast } from '@/components/shared/ToastContext';
import { useAuth } from '@/context/AuthContext';
import { ScanDetailModal } from '@/components/shared/ScanDetailModal';
import { cn } from '@/lib/utils';

export default function ReportsPage() {
  const { user, isAuthenticated, isLoading: isAuthLoading } = useAuth();
  const { success, error: toastError, info } = useToast();
  const [reports, setReports] = useState<GeneratedReport[]>([]);
  const [recentScans, setRecentScans] = useState<ScanResult[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [isGenerating, setIsGenerating] = useState(false);
  const [selectedScanForModal, setSelectedScanForModal] = useState<ScanResult | null>(null);

  const fetchReportsAndScans = useCallback(async () => {
    if (isAuthLoading) return;
    if (!isAuthenticated || !user) {
      setReports([]);
      setRecentScans([]);
      setIsLoading(false);
      return;
    }

    setIsLoading(true);
    try {
      const [reportsRes, historyRes] = await Promise.allSettled([
        reportsApi.getReports(),
        historyApi.getHistory({ limit: 50 }),
      ]);

      if (reportsRes.status === 'fulfilled') {
        setReports(reportsRes.value.reports || []);
      } else {
        setReports([]);
      }
      if (historyRes.status === 'fulfilled') {
        setRecentScans(historyRes.value.scans || []);
      } else {
        setRecentScans([]);
      }
    } catch (err: any) {
      console.error('Failed loading reports:', err);
    } finally {
      setIsLoading(false);
    }
  }, [isAuthLoading, isAuthenticated, user]);

  useEffect(() => {
    fetchReportsAndScans();
  }, [fetchReportsAndScans, user?.id, isAuthenticated, isAuthLoading]);

  const handleGenerateReport = async (scanId: string) => {
    setIsGenerating(true);
    try {
      await reportsApi.createReport(scanId);
      success('Dossier Generated', 'A new executive incident report was saved to MongoDB.');
      await fetchReportsAndScans();
    } catch (err: any) {
      toastError('Generation Failed', err.message || 'Unable to generate report from scan.');
    } finally {
      setIsGenerating(false);
    }
  };

  const totalReports = reports.length;
  const phishingReports = reports.filter((r) => r.classification === 'Phishing').length;
  const safeReports = reports.filter((r) => r.classification === 'Safe').length;
  const suspiciousReports = reports.filter((r) => r.classification === 'Suspicious').length;

  const filteredReports = reports.filter((r) => {
    return (
      r.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.targetUrl.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.id.toLowerCase().includes(searchTerm.toLowerCase())
    );
  });

  const handleDownload = async (report: GeneratedReport) => {
    try {
      info('Downloading Dossier...', 'Generating streaming binary from ReportLab engine.');
      const targetId = report.id || report.scanId;
      const blob = await reportsApi.downloadPdf(targetId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `PhishGuard-Report-${report.id || 'dossier'}.pdf`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      success('PDF Export Complete', `Report ${report.id} saved to your system.`);
    } catch (err: any) {
      console.error('Download error:', err);
      toastError('Download Failed', err.message || 'Unable to stream PDF report from backend.');
    }
  };

  const handleViewDetails = (report: GeneratedReport) => {
    const match = recentScans.find((s) => s.id === report.scanId || s.url === report.targetUrl);
    if (match) {
      setSelectedScanForModal(match);
    } else {
      info('Scan Telemetry', `Report target: ${report.targetUrl}`);
    }
  };

  return (
    <div className="flex flex-col min-h-screen">
      <Header
        title="Security Reports Management"
        subtitle="Exportable threat assessments, compliance audits, and ReportLab PDF executive summaries."
      />

      <div className="p-6 lg:p-8 space-y-8 max-w-7xl mx-auto w-full">
        {/* Metric Cards - Real counts only */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-5 rounded-xl bg-[#111827] border border-[#263244] space-y-1">
            <span className="text-xs font-mono text-slate-400 uppercase">Total Generated Reports</span>
            <p className="text-2xl lg:text-3xl font-bold text-slate-100 font-sans">{totalReports}</p>
            <span className="text-[11px] font-mono text-cyan-400 block">Available in MongoDB</span>
          </div>

          <div className="p-5 rounded-xl bg-[#111827] border border-[#263244] space-y-1">
            <span className="text-xs font-mono text-slate-400 uppercase">Phishing Reports</span>
            <p className="text-2xl lg:text-3xl font-bold text-red-400 font-sans">{phishingReports}</p>
            <span className="text-[11px] font-mono text-red-400/80 block">Critical risk level</span>
          </div>

          <div className="p-5 rounded-xl bg-[#111827] border border-[#263244] space-y-1">
            <span className="text-xs font-mono text-slate-400 uppercase">Safe URL Reports</span>
            <p className="text-2xl lg:text-3xl font-bold text-emerald-400 font-sans">{safeReports}</p>
            <span className="text-[11px] font-mono text-emerald-400/80 block">Zero indicators flagged</span>
          </div>

          <div className="p-5 rounded-xl bg-[#111827] border border-[#263244] space-y-1">
            <span className="text-xs font-mono text-slate-400 uppercase">Suspicious Reports</span>
            <p className="text-2xl lg:text-3xl font-bold text-amber-400 font-sans">{suspiciousReports}</p>
            <span className="text-[11px] font-mono text-amber-400/80 block">Medium risk level</span>
          </div>
        </div>

        {/* Reports Management Table */}
        <div className="bg-[#111827] border border-[#263244] rounded-xl overflow-hidden shadow-lg space-y-4 p-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-slate-100 tracking-tight">
                  Generated Security Dossiers
                </h3>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Official ReportLab forensic documents stored in MongoDB with full technical domain breakdown
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={fetchReportsAndScans}
                disabled={isLoading}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0B1120] hover:bg-[#162032] border border-[#263244] text-xs font-mono text-slate-300 transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${isLoading ? 'animate-spin' : ''}`} />
                <span>{isLoading ? 'Syncing...' : 'Refresh'}</span>
              </button>

              {/* Search */}
              <div className="relative w-full sm:w-64">
                <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  placeholder="Search report ID, title, URL..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-[#0B1120] border border-[#263244] text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>
          </div>

          {/* Table or Empty State */}
          <div className="overflow-x-auto pt-2">
            {isLoading && reports.length === 0 ? (
              <div className="py-12 text-center space-y-2">
                <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin mx-auto" />
                <p className="text-xs font-mono text-slate-400">Loading reports from database...</p>
              </div>
            ) : filteredReports.length === 0 ? (
              <div className="py-12 px-4 text-center space-y-4">
                <div className="w-12 h-12 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 mx-auto">
                  <FileText className="w-6 h-6" />
                </div>
                <div className="space-y-1 max-w-md mx-auto">
                  <h4 className="text-base font-semibold text-slate-100">No security reports generated yet</h4>
                  <p className="text-xs text-slate-400">
                    Run a scan to generate an incident report, or convert an existing scan into a downloadable PDF dossier.
                  </p>
                </div>
                <div className="flex flex-wrap items-center justify-center gap-3">
                  <Link
                    href="/scanner"
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs font-mono transition-colors"
                  >
                    <Scan className="w-4 h-4" />
                    <span>Run a Scan</span>
                  </Link>

                  {recentScans.length > 0 && (
                    <button
                      onClick={() => handleGenerateReport(recentScans[0].id)}
                      disabled={isGenerating}
                      className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[#162032] hover:bg-[#1e2d44] border border-cyan-500/30 text-cyan-300 text-xs font-mono transition-colors disabled:opacity-50"
                    >
                      <PlusCircle className="w-4 h-4" />
                      <span>Generate from Latest Scan ({recentScans[0].domain})</span>
                    </button>
                  )}
                </div>
              </div>
            ) : (
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-[#263244] bg-[#0E1526]/80 text-[11px] font-mono uppercase tracking-wider text-slate-400">
                    <th className="py-3 px-3">Report Title & Target</th>
                    <th className="py-3 px-3">Classification</th>
                    <th className="py-3 px-3">Risk Score</th>
                    <th className="py-3 px-3">Generated Date</th>
                    <th className="py-3 px-3">Format</th>
                    <th className="py-3 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#263244]/60">
                  {filteredReports.map((report) => (
                    <tr key={report.id} className="hover:bg-[#162032]/40 transition-colors">
                      <td className="py-3 px-3 max-w-xs md:max-w-sm">
                        <div className="flex flex-col min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="font-semibold text-slate-100">{report.title}</span>
                            <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#162032] text-slate-400 border border-[#263244]">
                              {report.id.substring(0, 10)}...
                            </span>
                          </div>
                          <span className="font-mono text-[11px] text-slate-500 truncate mt-0.5">
                            {report.targetUrl}
                          </span>
                        </div>
                      </td>

                      <td className="py-3 px-3 whitespace-nowrap">
                        <span
                          className={cn(
                            'inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-medium border',
                            report.classification === 'Phishing' && 'bg-red-500/10 text-red-400 border-red-500/30',
                            report.classification === 'Suspicious' && 'bg-amber-500/10 text-amber-300 border-amber-500/30',
                            report.classification === 'Safe' && 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          )}
                        >
                          {report.classification === 'Phishing' && <ShieldAlert className="w-3 h-3 text-red-400" />}
                          {report.classification === 'Suspicious' && <AlertTriangle className="w-3 h-3 text-amber-400" />}
                          {report.classification === 'Safe' && <ShieldCheck className="w-3 h-3 text-emerald-400" />}
                          {report.classification}
                        </span>
                      </td>

                      <td className="py-3 px-3 whitespace-nowrap font-mono">
                        <span className="font-bold text-slate-100">{report.riskScore}</span>
                        <span className="text-slate-500 text-[10px]">/100</span>
                      </td>

                      <td className="py-3 px-3 whitespace-nowrap font-mono text-slate-400 text-[11px]">
                        {report.generatedDate}
                      </td>

                      <td className="py-3 px-3 whitespace-nowrap font-mono text-cyan-400 text-[11px]">
                        ReportLab PDF
                      </td>

                      <td className="py-3 px-3 whitespace-nowrap text-right">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() => handleViewDetails(report)}
                            className="p-1.5 rounded text-slate-400 hover:text-cyan-400 hover:bg-[#0B1120] transition-colors"
                            title="Inspect scan telemetry"
                          >
                            <Eye className="w-4 h-4" />
                          </button>

                          <button
                            onClick={() => handleDownload(report)}
                            className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#0B1120] hover:bg-[#162032] border border-[#263244] text-xs font-mono text-cyan-400 hover:text-cyan-300 transition-colors"
                            title="Download Official PDF Report"
                          >
                            <Download className="w-3.5 h-3.5" />
                            <span>Export PDF</span>
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>

      {selectedScanForModal && (
        <ScanDetailModal
          scan={selectedScanForModal}
          onClose={() => setSelectedScanForModal(null)}
        />
      )}
    </div>
  );
}
