'use client';

import React, { useState } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Legend,
} from 'recharts';
import { ShieldAlert, TrendingUp, PieChart as PieIcon, Activity } from 'lucide-react';
import { ActivityDataPoint, ThreatDistributionPoint } from '@/types';

interface ThreatChartProps {
  activityData: ActivityDataPoint[];
  distributionData: ThreatDistributionPoint[];
}

export function ThreatActivityChart({ data }: { data: ActivityDataPoint[] }) {
  const [metricFilter, setMetricFilter] = useState<'all' | 'phishing' | 'safe'>('all');

  return (
    <div className="bg-[#111827] border border-[#263244] rounded-xl p-5 flex flex-col justify-between">
      {/* Chart Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6">
        <div>
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-slate-100 tracking-tight">
              Threat Activity (Last 7 Days)
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Phishing detections, suspicious flags, and benign scans over time
          </p>
        </div>

        {/* Filter Pills */}
        <div className="flex items-center gap-1 bg-[#0B1120] p-1 rounded-lg border border-[#263244] self-start sm:self-center">
          <button
            onClick={() => setMetricFilter('all')}
            className={`px-2.5 py-1 text-xs font-mono rounded-md transition-colors ${
              metricFilter === 'all'
                ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All Trajectory
          </button>
          <button
            onClick={() => setMetricFilter('phishing')}
            className={`px-2.5 py-1 text-xs font-mono rounded-md transition-colors ${
              metricFilter === 'phishing'
                ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Phishing Only
          </button>
        </div>
      </div>

      {/* Recharts Area Chart */}
      <div className="h-64 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <defs>
              <linearGradient id="phishingGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#EF4444" stopOpacity={0.35} />
                <stop offset="95%" stopColor="#EF4444" stopOpacity={0.0} />
              </linearGradient>
              <linearGradient id="suspiciousGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#F59E0B" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#F59E0B" stopOpacity={0.0} />
              </linearGradient>
              <linearGradient id="safeGradient" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.2} />
                <stop offset="95%" stopColor="#06B6D4" stopOpacity={0.0} />
              </linearGradient>
            </defs>

            <XAxis
              dataKey="date"
              stroke="#64748B"
              fontSize={11}
              tickLine={false}
              axisLine={{ stroke: '#263244' }}
            />
            <YAxis
              stroke="#64748B"
              fontSize={11}
              tickLine={false}
              axisLine={{ stroke: '#263244' }}
              tickFormatter={(v) => (v >= 1000 ? `${(v / 1000).toFixed(1)}k` : v)}
            />
            <Tooltip
              content={({ active, payload, label }) => {
                if (active && payload && payload.length) {
                  return (
                    <div className="bg-[#0B1120] border border-[#263244] p-3 rounded-lg shadow-xl text-xs space-y-1.5 font-mono">
                      <p className="text-slate-300 font-semibold border-b border-[#263244] pb-1">
                        {label}
                      </p>
                      {payload.map((entry, index) => (
                        <div key={index} className="flex items-center justify-between gap-4">
                          <span className="flex items-center gap-1.5 text-slate-400 capitalize">
                            <span
                              className="w-2 h-2 rounded-full"
                              style={{ backgroundColor: entry.color }}
                            />
                            {entry.name}:
                          </span>
                          <span className="text-slate-100 font-bold">
                            {entry.value?.toLocaleString()}
                          </span>
                        </div>
                      ))}
                    </div>
                  );
                }
                return null;
              }}
            />

            {(metricFilter === 'all' || metricFilter === 'phishing') && (
              <Area
                type="monotone"
                dataKey="phishing"
                name="Phishing"
                stroke="#EF4444"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#phishingGradient)"
              />
            )}
            {metricFilter === 'all' && (
              <Area
                type="monotone"
                dataKey="suspicious"
                name="Suspicious"
                stroke="#F59E0B"
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#suspiciousGradient)"
              />
            )}
            {metricFilter === 'all' && (
              <Area
                type="monotone"
                dataKey="safe"
                name="Safe"
                stroke="#06B6D4"
                strokeWidth={1.5}
                strokeDasharray="4 4"
                fillOpacity={1}
                fill="url(#safeGradient)"
              />
            )}
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Legend footer */}
      <div className="mt-4 pt-3 border-t border-[#263244] flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400 font-mono">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#EF4444]" />
            <span>Phishing Threats</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#F59E0B]" />
            <span>Suspicious Anomalies</span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-[#06B6D4]" />
            <span>Benign Safe Traffic</span>
          </span>
        </div>
        <span className="text-slate-500 text-[11px]">Aggregated 7d rolling window</span>
      </div>
    </div>
  );
}

export function ThreatDistributionChart({ data }: { data: ThreatDistributionPoint[] }) {
  const total = data.reduce((acc, curr) => acc + curr.value, 0);

  return (
    <div className="bg-[#111827] border border-[#263244] rounded-xl p-5 flex flex-col justify-between">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <PieIcon className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-semibold text-slate-100 tracking-tight">
            Threat Distribution
          </h3>
        </div>
        <p className="text-xs text-slate-400 mt-0.5">
          Breakdown of analyzed destinations by threat classification
        </p>
      </div>

      {/* Donut Chart with Centered Total */}
      <div className="h-60 w-full relative my-2 flex items-center justify-center">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              innerRadius={65}
              outerRadius={88}
              paddingAngle={4}
              dataKey="value"
              stroke="#0B1120"
              strokeWidth={3}
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const entry = payload[0];
                  const percentage = ((Number(entry.value) / total) * 100).toFixed(1);
                  return (
                    <div className="bg-[#0B1120] border border-[#263244] p-2.5 rounded-lg shadow-xl text-xs font-mono space-y-1">
                      <p className="text-slate-200 font-bold flex items-center gap-1.5">
                        <span
                          className="w-2 h-2 rounded-full"
                          style={{ backgroundColor: entry.payload.color }}
                        />
                        {entry.name}
                      </p>
                      <p className="text-slate-400">
                        Count: <span className="text-slate-100">{entry.value?.toLocaleString()}</span>
                      </p>
                      <p className="text-slate-400">
                        Share: <span className="text-cyan-400">{percentage}%</span>
                      </p>
                    </div>
                  );
                }
                return null;
              }}
            />
          </PieChart>
        </ResponsiveContainer>

        {/* Center label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-xs font-mono uppercase tracking-wider text-slate-400">Total Scans</span>
          <span className="text-xl font-bold font-sans text-slate-100">
            {total.toLocaleString()}
          </span>
        </div>
      </div>

      {/* Legend Breakdown */}
      <div className="pt-3 border-t border-[#263244] space-y-2">
        {data.map((item) => {
          const pct = ((item.value / total) * 100).toFixed(1);
          return (
            <div key={item.name} className="flex items-center justify-between text-xs font-mono">
              <span className="flex items-center gap-2 text-slate-300">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                <span>{item.name}</span>
              </span>
              <div className="flex items-center gap-3">
                <span className="text-slate-400">{item.value.toLocaleString()}</span>
                <span className="text-slate-500 w-12 text-right">{pct}%</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

