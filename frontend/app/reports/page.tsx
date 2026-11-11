'use client';

import React, { useState, useEffect } from 'react';
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
  Share2,
  Calendar,
  Sparkles,
} from 'lucide-react';
import { GeneratedReport, ScanResult } from '@/types';
import { getStoredReports, getStoredScans, downloadReportAsFile } from '@/lib/storage';
import { useToast } from '@/components/shared/ToastContext';
import { ScanDetailModal } from '@/components/shared/ScanDetailModal';
import { cn } from '@/lib/utils';

export default function ReportsPage() {
  const { success } = useToast();
  const [reports, setReports] = useState<GeneratedReport[]>([]);
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedScanForModal, setSelectedScanForModal] = useState<ScanResult | null>(null);

  useEffect(() => {
    setReports(getStoredReports());
    setScans(getStoredScans());
  }, []);

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

  const handleDownload = (report: GeneratedReport) => {
    // Find matching scan or build a lightweight representation
    const match = scans.find((s) => s.id === report.scanId || s.url === report.targetUrl);
    if (match) {
      downloadReportAsFile(match, 'md');
    } else {
      // Fallback download
      const content = `# PhishGuard AI Security Dossier\nReport ID: ${report.id}\nTarget: ${report.targetUrl}\nClassification: ${report.classification}\nRisk Score: ${report.riskScore}/100\nDate: ${report.generatedDate}\n`;
      const blob = new Blob([content], { type: 'text/markdown' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${report.id}.md`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }
    success('Dossier Downloaded', `Saved report ${report.id} to your local device.`);
  };

  const handleViewDetails = (report: GeneratedReport) => {
    const match = scans.find((s) => s.id === report.scanId || s.url === report.targetUrl);
    if (match) {
      setSelectedScanForModal(match);
    } else if (scans.length > 0) {
      setSelectedScanForModal(scans[0]);
    }
  };

  return (
    <div className="flex flex-col min-h-screen">
      <Header
        title="Security Reports Management"
        subtitle="Exportable threat assessments, compliance audits, and executive summaries."
      />

      <div className="p-6 lg:p-8 space-y-8 max-w-7xl mx-auto w-full">
        {/* Metric Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-5 rounded-xl bg-[#111827] border border-[#263244] space-y-1">
            <span className="text-xs font-mono text-slate-400 uppercase">Total Generated Reports</span>
            <p className="text-2xl lg:text-3xl font-bold text-slate-100 font-sans">{totalReports}</p>
            <span className="text-[11px] font-mono text-cyan-400 block">Available for instant download</span>
          </div>

          <div className="p-5 rounded-xl bg-[#111827] border border-[#263244] space-y-1">
            <span className="text-xs font-mono text-slate-400 uppercase">Phishing Detection Reports</span>
            <p className="text-2xl lg:text-3xl font-bold text-red-400 font-sans">{phishingReports}</p>
            <span className="text-[11px] font-mono text-red-400/80 block">Malicious indicators confirmed</span>
          </div>

          <div className="p-5 rounded-xl bg-[#111827] border border-[#263244] space-y-1">
            <span className="text-xs font-mono text-slate-400 uppercase">Safe URL Reports</span>
            <p className="text-2xl lg:text-3xl font-bold text-emerald-400 font-sans">{safeReports}</p>
            <span className="text-[11px] font-mono text-emerald-400/80 block">Standard security clean bill</span>
          </div>

          <div className="p-5 rounded-xl bg-[#111827] border border-[#263244] space-y-1">
            <span className="text-xs font-mono text-slate-400 uppercase">Suspicious / Under Review</span>
            <p className="text-2xl lg:text-3xl font-bold text-amber-400 font-sans">{suspiciousReports}</p>
            <span className="text-[11px] font-mono text-amber-400/80 block">Anomalous score tags</span>
          </div>
        </div>

        {/* Reports Management Table */}
        <div className="bg-[#111827] border border-[#263244] rounded-xl overflow-hidden shadow-lg space-y-4 p-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-slate-100 tracking-tight">
                  Recent Generated Reports
                </h3>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                On-demand forensics compilations with technical domain breakdown and mitigation steps
              </p>
            </div>

            {/* Search */}
            <div className="relative w-full sm:w-72">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search report ID, title, or URL..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-[#0B1120] border border-[#263244] text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {/* Table */}
          <div className="overflow-x-auto pt-2">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-[#263244] bg-[#0E1526]/80 text-[11px] font-mono uppercase tracking-wider text-slate-400">
                  <th className="py-3 px-3">Report Title & Target</th>
                  <th className="py-3 px-3">Classification</th>
                  <th className="py-3 px-3">Risk Score</th>
                  <th className="py-3 px-3">Generated Date</th>
                  <th className="py-3 px-3">File Size</th>
                  <th className="py-3 px-3 text-right">Download</th>
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
                            {report.id}
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

                    <td className="py-3 px-3 whitespace-nowrap font-mono text-slate-500 text-[11px]">
                      {report.fileSize}
                    </td>

                    <td className="py-3 px-3 whitespace-nowrap text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => handleViewDetails(report)}
                          className="p-1.5 rounded text-slate-400 hover:text-cyan-400 hover:bg-[#0B1120] transition-colors"
                          title="Preview full report modal"
                        >
                          <Eye className="w-4 h-4" />
                        </button>

                        <button
                          onClick={() => handleDownload(report)}
                          className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[#0B1120] hover:bg-[#162032] border border-[#263244] text-xs font-mono text-cyan-400 hover:text-cyan-300 transition-colors"
                          title="Download Report (Markdown/Text)"
                        >
                          <Download className="w-3.5 h-3.5" />
                          <span>Export</span>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
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

