'use client';

import React from 'react';
import { ArrowUpRight, ArrowDownRight, Shield, ShieldAlert, CheckCircle2, Target, AlertTriangle, Activity } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface StatCardProps {
  title: string;
  value: string | number;
  trend?: string;
  trendDirection?: 'up' | 'down' | 'neutral';
  trendSubtext?: string;
  iconName: 'scanned' | 'phishing' | 'safe' | 'rate' | 'suspicious' | 'score';
}

const ICON_MAP = {
  scanned: {
    icon: Target,
    bg: 'bg-cyan-500/10',
    border: 'border-cyan-500/20',
    color: 'text-cyan-400',
  },
  phishing: {
    icon: ShieldAlert,
    bg: 'bg-red-500/10',
    border: 'border-red-500/20',
    color: 'text-red-400',
  },
  suspicious: {
    icon: AlertTriangle,
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/20',
    color: 'text-amber-400',
  },
  safe: {
    icon: CheckCircle2,
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/20',
    color: 'text-emerald-400',
  },
  rate: {
    icon: Shield,
    bg: 'bg-blue-500/10',
    border: 'border-blue-500/20',
    color: 'text-blue-400',
  },
  score: {
    icon: Activity,
    bg: 'bg-purple-500/10',
    border: 'border-purple-500/20',
    color: 'text-purple-400',
  },
};

export function StatisticsCard({
  title,
  value,
  trend,
  trendDirection = 'up',
  trendSubtext = 'vs last 7 days',
  iconName,
}: StatCardProps) {
  const config = ICON_MAP[iconName] || ICON_MAP.scanned;
  const Icon = config.icon;

  return (
    <div className="bg-[#111827] border border-[#263244] hover:border-[#334155] rounded-xl p-5 transition-all duration-200 relative group overflow-hidden">
      {/* Subtle hover gradient glow */}
      <div className="absolute top-0 right-0 w-24 h-24 bg-gradient-to-bl from-white/[0.02] to-transparent pointer-events-none rounded-tr-xl" />

      <div className="flex items-start justify-between">
        <p className="text-xs font-medium text-slate-400 tracking-wide">{title}</p>
        <div className={cn('w-9 h-9 rounded-lg flex items-center justify-center border', config.bg, config.border)}>
          <Icon className={cn('w-4 h-4', config.color)} />
        </div>
      </div>

      <div className="mt-3 flex items-baseline gap-2">
        <span className="text-2xl lg:text-3xl font-bold text-slate-100 tracking-tight font-sans">
          {value}
        </span>
      </div>

      {trend ? (
        <div className="mt-3 flex items-center gap-1.5 text-xs">
          <span
            className={cn(
              'inline-flex items-center gap-0.5 font-medium px-1.5 py-0.5 rounded font-mono text-[11px]',
              iconName === 'phishing'
                ? 'text-red-400 bg-red-500/10'
                : 'text-emerald-400 bg-emerald-500/10'
            )}
          >
            {trendDirection === 'up' ? (
              <ArrowUpRight className="w-3 h-3" />
            ) : (
              <ArrowDownRight className="w-3 h-3" />
            )}
            {trend}
          </span>
          <span className="text-slate-500 text-[11px]">{trendSubtext}</span>
        </div>
      ) : (
        <div className="mt-3 flex items-center gap-1.5 text-xs text-slate-500">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          <span className="text-[11px]">Precision metric validated</span>
        </div>
      )}
    </div>
  );
}

