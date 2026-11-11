import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';
import { Classification, RiskCategory } from '@/types';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatRiskScore(score: number): {
  color: string;
  bgColor: string;
  borderColor: string;
  textColor: string;
  category: RiskCategory;
} {
  if (score >= 81) {
    return {
      color: '#EF4444',
      bgColor: 'bg-red-500/10',
      borderColor: 'border-red-500/30',
      textColor: 'text-red-400',
      category: 'Critical',
    };
  } else if (score >= 61) {
    return {
      color: '#F97316',
      bgColor: 'bg-orange-500/10',
      borderColor: 'border-orange-500/30',
      textColor: 'text-orange-400',
      category: 'High',
    };
  } else if (score >= 31) {
    return {
      color: '#F59E0B',
      bgColor: 'bg-amber-500/10',
      borderColor: 'border-amber-500/30',
      textColor: 'text-amber-400',
      category: 'Medium',
    };
  } else {
    return {
      color: '#10B981',
      bgColor: 'bg-emerald-500/10',
      borderColor: 'border-emerald-500/30',
      textColor: 'text-emerald-400',
      category: 'Low',
    };
  }
}

export function getClassificationBadge(classification: Classification) {
  switch (classification) {
    case 'Phishing':
      return {
        label: 'Phishing',
        badgeClass: 'bg-red-500/15 text-red-400 border border-red-500/30',
        dotClass: 'bg-red-400',
      };
    case 'Suspicious':
      return {
        label: 'Suspicious',
        badgeClass: 'bg-amber-500/15 text-amber-300 border border-amber-500/30',
        dotClass: 'bg-amber-400',
      };
    case 'Safe':
    default:
      return {
        label: 'Safe',
        badgeClass: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30',
        dotClass: 'bg-emerald-400',
      };
  }
}

export function formatDateRelative(isoString: string): string {
  try {
    const date = new Date(isoString);
    const now = new Date();
    const diffSeconds = Math.floor((now.getTime() - date.getTime()) / 1000);

    if (diffSeconds < 60) return 'Just now';
    if (diffSeconds < 3600) return `${Math.floor(diffSeconds / 60)}m ago`;
    if (diffSeconds < 86400) return `${Math.floor(diffSeconds / 3600)}h ago`;
    if (diffSeconds < 604800) return `${Math.floor(diffSeconds / 86400)}d ago`;

    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  } catch {
    return isoString;
  }
}

