'use client';

import React from 'react';
import { formatRiskScore } from '@/lib/utils';
import { RiskCategory } from '@/types';

interface RiskGaugeProps {
  score: number;
  size?: number;
  strokeWidth?: number;
  showLabels?: boolean;
}

export function RiskGauge({
  score,
  size = 180,
  strokeWidth = 12,
  showLabels = true,
}: RiskGaugeProps) {
  const radius = (size - strokeWidth * 2) / 2;
  const circumference = 2 * Math.PI * radius;
  // Clamp score between 0 and 100
  const normalizedScore = Math.min(100, Math.max(0, score));
  const strokeDashoffset = circumference - (normalizedScore / 100) * circumference;

  const { color, category, textColor, bgColor, borderColor } = formatRiskScore(score);

  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
        {/* SVG Gauge */}
        <svg
          className="transform -rotate-90 origin-center"
          width={size}
          height={size}
        >
          {/* Background track circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="#1E293B"
            strokeWidth={strokeWidth}
            fill="transparent"
            className="transition-all duration-300"
          />

          {/* Value Progress circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={color}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center content */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center select-none">
          <div className="flex items-baseline">
            <span className="text-4xl lg:text-5xl font-black font-sans text-slate-100 tracking-tight">
              {score}
            </span>
            <span className="text-xs text-slate-500 font-mono font-medium ml-1">/100</span>
          </div>

          <span
            className={`mt-1 text-[11px] font-mono uppercase tracking-wider font-semibold px-2 py-0.5 rounded-full border ${bgColor} ${borderColor} ${textColor}`}
          >
            {category} Risk
          </span>
        </div>
      </div>

      {showLabels && (
        <div className="mt-3 grid grid-cols-4 gap-1 w-full max-w-xs text-[10px] font-mono text-center text-slate-500">
          <span className={score <= 30 ? 'text-emerald-400 font-semibold' : ''}>0–30 Low</span>
          <span className={score > 30 && score <= 60 ? 'text-amber-400 font-semibold' : ''}>31–60 Med</span>
          <span className={score > 60 && score <= 80 ? 'text-orange-400 font-semibold' : ''}>61–80 High</span>
          <span className={score > 80 ? 'text-red-400 font-semibold' : ''}>81–100 Crit</span>
        </div>
      )}
    </div>
  );
}

