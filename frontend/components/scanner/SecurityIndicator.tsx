'use client';

import React from 'react';
import { CheckCircle2, AlertTriangle, AlertCircle, ShieldCheck, ShieldAlert, Info } from 'lucide-react';
import { SecurityIndicatorItem } from '@/types';
import { cn } from '@/lib/utils';

interface SecurityIndicatorProps {
  indicator: SecurityIndicatorItem;
}

export function SecurityIndicator({ indicator }: SecurityIndicatorProps) {
  const isFlagged = indicator.detected || indicator.status === 'danger' || indicator.status === 'warning';

  let statusIcon = <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />;
  let badgeColor = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';

  if (indicator.status === 'danger' || indicator.severity === 'Critical' || indicator.severity === 'High') {
    statusIcon = <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />;
    badgeColor = 'bg-red-500/10 text-red-400 border-red-500/25';
  } else if (indicator.status === 'warning' || indicator.severity === 'Medium') {
    statusIcon = <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />;
    badgeColor = 'bg-amber-500/10 text-amber-300 border-amber-500/25';
  }

  return (
    <div
      className={cn(
        'p-3.5 rounded-lg border transition-all duration-150 flex items-start gap-3',
        isFlagged
          ? 'bg-[#141C2E] border-[#263244] hover:border-[#384961]'
          : 'bg-[#101726]/60 border-[#1E293B] hover:border-[#263244]'
      )}
    >
      <div className="mt-0.5">{statusIcon}</div>

      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs font-semibold text-slate-200 tracking-tight">
            {indicator.name}
          </span>
          <span
            className={cn(
              'text-[10px] font-mono uppercase font-semibold px-2 py-0.5 rounded border shrink-0',
              badgeColor
            )}
          >
            {indicator.detected ? (indicator.severity || 'Detected') : 'Clean'}
          </span>
        </div>

        <p className="text-xs text-slate-400 mt-1 leading-relaxed">
          {indicator.description}
        </p>

        {indicator.technicalDetail && (
          <div className="mt-1.5 flex items-center gap-1.5 text-[11px] font-mono text-slate-500">
            <span className="text-slate-600">detail:</span>
            <span className="text-slate-400 truncate">{indicator.technicalDetail}</span>
          </div>
        )}
      </div>
    </div>
  );
}

