'use client';

import React, { useState, useMemo } from 'react';
import {
  Search,
  Filter,
  ArrowUpDown,
  Download,
  Trash2,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Eye,
  Calendar,
} from 'lucide-react';
import { ScanResult, Classification } from '@/types';
import { getClassificationBadge, formatRiskScore, formatDateRelative } from '@/lib/utils';
import { downloadReportAsFile } from '@/lib/storage';
import { useToast } from '../shared/ToastContext';
import { ScanDetailModal } from '../shared/ScanDetailModal';

interface ScanHistoryTableProps {
  scans: ScanResult[];
  onDeleteScan?: (scanId: string) => void;
  itemsPerPage?: number;
  showFilters?: boolean;
  title?: string;
}

export function ScanHistoryTable({
  scans,
  onDeleteScan,
  itemsPerPage = 8,
  showFilters = true,
  title = 'Recent URL Scans',
}: ScanHistoryTableProps) {
  const { success } = useToast();
  const [searchTerm, setSearchTerm] = useState('');
  const [classificationFilter, setClassificationFilter] = useState<'All' | Classification>('All');
  const [sortOrder, setSortOrder] = useState<'desc' | 'asc'>('desc');
  const [currentPage, setCurrentPage] = useState(1);
  const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);

  // Filter and sort logic
  const filteredScans = useMemo(() => {
    return scans
      .filter((scan) => {
        const matchesSearch =
          scan.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
          scan.domain.toLowerCase().includes(searchTerm.toLowerCase());

        const matchesClass =
          classificationFilter === 'All' || scan.classification === classificationFilter;

        return matchesSearch && matchesClass;
      })
      .sort((a, b) => {
        if (sortOrder === 'desc') {
          return b.riskScore - a.riskScore;
        } else {
          return a.riskScore - b.riskScore;
        }
      });
  }, [scans, searchTerm, classificationFilter, sortOrder]);

  // Pagination calculation
  const totalPages = Math.max(1, Math.ceil(filteredScans.length / itemsPerPage));
  const paginatedScans = useMemo(() => {
    const start = (currentPage - 1) * itemsPerPage;
    return filteredScans.slice(start, start + itemsPerPage);
  }, [filteredScans, currentPage, itemsPerPage]);

  const toggleSort = () => {
    setSortOrder((prev) => (prev === 'desc' ? 'asc' : 'desc'));
    setCurrentPage(1);
  };

  return (
    <div className="bg-[#111827] border border-[#263244] rounded-xl overflow-hidden shadow-lg flex flex-col">
      {/* Table Header / Controls */}
      <div className="p-4 sm:p-5 border-b border-[#263244] space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-100 tracking-tight">{title}</h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Inspected destinations and historical risk evaluations
            </p>
          </div>

          <span className="text-xs font-mono text-cyan-400 bg-cyan-500/10 px-2.5 py-1 rounded border border-cyan-500/20 self-start sm:self-center">
            {filteredScans.length} records matching
          </span>
        </div>

        {/* Filters and search row */}
        {showFilters && (
          <div className="grid grid-cols-1 sm:grid-cols-12 gap-3 pt-2">
            {/* Search Input */}
            <div className="sm:col-span-6 relative">
              <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                placeholder="Search URL, domain or protocol..."
                value={searchTerm}
                onChange={(e) => {
                  setSearchTerm(e.target.value);
                  setCurrentPage(1);
                }}
                className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-[#0B1120] border border-[#263244] text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            {/* Classification Filter */}
            <div className="sm:col-span-4 flex items-center gap-1.5">
              <span className="text-[11px] font-mono text-slate-500 shrink-0">Filter:</span>
              <div className="flex items-center gap-1 bg-[#0B1120] p-1 rounded-lg border border-[#263244] w-full">
                {(['All', 'Phishing', 'Suspicious', 'Safe'] as const).map((filter) => (
                  <button
                    key={filter}
                    onClick={() => {
                      setClassificationFilter(filter);
                      setCurrentPage(1);
                    }}
                    className={`flex-1 py-1 text-[11px] font-mono rounded transition-colors ${
                      classificationFilter === filter
                        ? 'bg-[#162032] text-cyan-400 font-semibold border border-[#263244]'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {filter}
                  </button>
                ))}
              </div>
            </div>

            {/* Sort Toggle */}
            <div className="sm:col-span-2 flex justify-end">
              <button
                onClick={toggleSort}
                className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0B1120] hover:bg-[#162032] border border-[#263244] text-xs font-mono text-slate-300 transition-colors"
                title="Toggle Risk Score Sort"
              >
                <ArrowUpDown className="w-3.5 h-3.5 text-cyan-400" />
                <span>Risk: {sortOrder === 'desc' ? 'High→Low' : 'Low→High'}</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Table Data */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs border-collapse">
          <thead>
            <tr className="border-b border-[#263244] bg-[#0E1526]/80 text-[11px] font-mono uppercase tracking-wider text-slate-400">
              <th className="py-3 px-4">URL & Domain</th>
              <th className="py-3 px-4">Classification</th>
              <th className="py-3 px-4">Risk Score</th>
              <th className="py-3 px-4">Scan Date</th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#263244]/60">
            {paginatedScans.length === 0 ? (
              <tr>
                <td colSpan={5} className="py-12 text-center text-slate-500 font-mono text-xs">
                  No scan records matching current search or filters.
                </td>
              </tr>
            ) : (
              paginatedScans.map((scan) => {
                const { badgeClass } = getClassificationBadge(scan.classification);
                const { textColor, category } = formatRiskScore(scan.riskScore);

                return (
                  <tr
                    key={scan.id}
                    onClick={() => setSelectedScan(scan)}
                    className="hover:bg-[#162032]/60 cursor-pointer transition-colors group"
                  >
                    {/* URL & Domain */}
                    <td className="py-3 px-4 max-w-xs md:max-w-md">
                      <div className="flex flex-col min-w-0">
                        <span className="font-mono text-xs text-slate-200 group-hover:text-cyan-300 transition-colors truncate">
                          {scan.domain}
                        </span>
                        <span className="text-[11px] font-mono text-slate-500 truncate mt-0.5">
                          {scan.url}
                        </span>
                      </div>
                    </td>

                    {/* Classification Badge */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-medium ${badgeClass}`}>
                        {scan.classification === 'Phishing' && <ShieldAlert className="w-3 h-3 text-red-400" />}
                        {scan.classification === 'Suspicious' && <AlertTriangle className="w-3 h-3 text-amber-400" />}
                        {scan.classification === 'Safe' && <ShieldCheck className="w-3 h-3 text-emerald-400" />}
                        {scan.classification}
                      </span>
                    </td>

                    {/* Risk Score */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      <div className="flex items-baseline gap-1.5">
                        <span className={`text-sm font-bold font-mono ${textColor}`}>
                          {scan.riskScore}
                        </span>
                        <span className="text-[10px] text-slate-500 font-mono">/100</span>
                        <span className="text-[10px] text-slate-400 font-mono hidden md:inline">
                          ({category})
                        </span>
                      </div>
                    </td>

                    {/* Date */}
                    <td className="py-3 px-4 whitespace-nowrap text-slate-400 font-mono text-[11px]">
                      {formatDateRelative(scan.timestamp)}
                    </td>

                    {/* Actions */}
                    <td className="py-3 px-4 whitespace-nowrap text-right">
                      <div
                        className="flex items-center justify-end gap-1"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <button
                          onClick={() => setSelectedScan(scan)}
                          className="p-1.5 rounded text-slate-400 hover:text-cyan-400 hover:bg-[#0B1120] transition-colors"
                          title="View analysis modal"
                        >
                          <Eye className="w-4 h-4" />
                        </button>

                        <button
                          onClick={() => {
                            downloadReportAsFile(scan, 'md');
                            success('Report downloaded');
                          }}
                          className="p-1.5 rounded text-slate-400 hover:text-slate-100 hover:bg-[#0B1120] transition-colors"
                          title="Download report"
                        >
                          <Download className="w-4 h-4" />
                        </button>

                        {onDeleteScan && (
                          <button
                            onClick={() => {
                              onDeleteScan(scan.id);
                              success('Record removed');
                            }}
                            className="p-1.5 rounded text-slate-400 hover:text-red-400 hover:bg-[#0B1120] transition-colors"
                            title="Remove record"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      {totalPages > 1 && (
        <div className="p-3 border-t border-[#263244] bg-[#0E1526]/50 flex items-center justify-between text-xs font-mono text-slate-400">
          <span>
            Page {currentPage} of {totalPages}
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="p-1.5 rounded bg-[#111827] border border-[#263244] disabled:opacity-40 disabled:cursor-not-allowed hover:bg-[#162032] transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <button
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="p-1.5 rounded bg-[#111827] border border-[#263244] disabled:opacity-40 disabled:cursor-not-allowed hover:bg-[#162032] transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}

      {/* Detailed Modal Triggered from Row Click */}
      {selectedScan && (
        <ScanDetailModal scan={selectedScan} onClose={() => setSelectedScan(null)} />
      )}
    </div>
  );
}

