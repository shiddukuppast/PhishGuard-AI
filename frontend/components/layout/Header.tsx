'use client';

import React, { useState } from 'react';
import { Bell, ShieldCheck, CheckCircle2, AlertTriangle, ShieldAlert, Sparkles, ExternalLink } from 'lucide-react';
import Link from 'next/link';

interface HeaderProps {
  title?: string;
  subtitle?: string;
}

export function Header({
  title = 'Security Overview',
  subtitle = 'Monitor phishing threats and protect your digital environment.',
}: HeaderProps) {
  const [showNotifications, setShowNotifications] = useState(false);
  const [unreadCount, setUnreadCount] = useState(3);

  // Formatted current date
  const currentDate = new Date().toLocaleDateString('en-US', {
    weekday: 'short',
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });

  const notifications = [
    {
      id: 1,
      title: 'High Risk Phishing Flagged',
      desc: '192.168.1.104/paypal was sinkholed.',
      time: '12m ago',
      type: 'danger',
    },
    {
      id: 2,
      title: 'Heuristics Engine v2.4 Active',
      desc: 'ML token analyzer rules loaded successfully.',
      time: '1h ago',
      type: 'info',
    },
    {
      id: 3,
      title: 'Threat Intel Feed Synced',
      desc: 'OpenPhish 2,400+ domain definitions loaded.',
      time: '3h ago',
      type: 'success',
    },
  ];

  return (
    <header className="h-16 px-6 border-b border-[#263244] bg-[#0E1526]/80 backdrop-blur-md flex items-center justify-between sticky top-0 z-30">
      {/* Title & Subtitle */}
      <div className="flex flex-col">
        <h1 className="text-base font-semibold text-slate-100 tracking-tight leading-none">
          {title}
        </h1>
        {subtitle && (
          <p className="text-xs text-slate-400 mt-1 hidden sm:block">
            {subtitle}
          </p>
        )}
      </div>

      {/* Right Actions: Date, Notification, Quick Scan Shortcut & Avatar */}
      <div className="flex items-center gap-3">
        {/* Quick Scan Action */}
        <Link
          href="/scanner"
          className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-xs font-medium transition-all shadow-sm"
        >
          <Sparkles className="w-3.5 h-3.5" />
          <span>New Scan</span>
        </Link>

        {/* Current Date Badge */}
        <div className="hidden lg:flex items-center gap-1.5 px-3 py-1 rounded-md bg-[#111827] border border-[#263244] text-xs font-mono text-slate-300">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
          <span>{currentDate}</span>
        </div>

        {/* Notifications Dropdown */}
        <div className="relative">
          <button
            onClick={() => {
              setShowNotifications(!showNotifications);
              if (unreadCount > 0) setUnreadCount(0);
            }}
            className="relative p-2 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-[#162032] border border-transparent hover:border-[#263244] transition-colors"
            aria-label="View notifications"
          >
            <Bell className="w-4 h-4" />
            {unreadCount > 0 && (
              <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-cyan-400 ring-2 ring-[#0E1526] animate-pulse" />
            )}
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 bg-[#111827] border border-[#263244] rounded-xl shadow-2xl p-3 z-50 animate-in fade-in slide-in-from-top-2">
              <div className="flex items-center justify-between pb-2 border-b border-[#263244]">
                <span className="text-xs font-semibold text-slate-200">System Notifications</span>
                <span className="text-[10px] font-mono text-cyan-400">All Systems Normal</span>
              </div>
              <div className="divide-y divide-[#263244]/60 max-h-64 overflow-y-auto mt-2">
                {notifications.map((n) => (
                  <div key={n.id} className="py-2.5 first:pt-1 last:pb-1 flex items-start gap-2.5">
                    {n.type === 'danger' && <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />}
                    {n.type === 'info' && <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />}
                    {n.type === 'success' && <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />}
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-medium text-slate-200">{n.title}</p>
                      <p className="text-[11px] text-slate-400 mt-0.5">{n.desc}</p>
                      <span className="text-[10px] text-slate-500 font-mono mt-1 block">{n.time}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* User Avatar */}
        <Link href="/settings" className="flex items-center gap-2 pl-2 border-l border-[#263244]/80">
          <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center text-white text-xs font-semibold ring-1 ring-cyan-500/40 hover:ring-cyan-400 transition-all cursor-pointer">
            AV
          </div>
        </Link>
      </div>
    </header>
  );
}

