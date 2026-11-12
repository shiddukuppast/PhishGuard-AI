'use client';

import React, { useState, useRef, useEffect } from 'react';
import {
  Bell,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  Sparkles,
  User as UserIcon,
  Settings,
  LogOut,
  ChevronDown,
  Key,
} from 'lucide-react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/components/shared/ToastContext';

interface HeaderProps {
  title?: string;
  subtitle?: string;
}

export function Header({
  title = 'Security Overview',
  subtitle = 'Monitor phishing threats and protect your digital environment.',
}: HeaderProps) {
  const router = useRouter();
  const { user, logout } = useAuth();
  const { info } = useToast();

  const [showNotifications, setShowNotifications] = useState(false);
  const [showProfileMenu, setShowProfileMenu] = useState(false);
  const [unreadCount, setUnreadCount] = useState(3);

  const profileRef = useRef<HTMLDivElement>(null);
  const notifRef = useRef<HTMLDivElement>(null);

  // Close dropdowns when clicking outside
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (profileRef.current && !profileRef.current.contains(event.target as Node)) {
        setShowProfileMenu(false);
      }
      if (notifRef.current && !notifRef.current.contains(event.target as Node)) {
        setShowNotifications(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleLogout = () => {
    logout();
    info('Logged Out', 'Your security session has ended.');
    setShowProfileMenu(false);
    router.replace('/');
  };

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

  const displayName = user?.name || 'Security Analyst';
  const displayEmail = user?.email || 'analyst@phishguard.sec';
  const displayInitials = user?.avatarInitials || 'PG';
  const displayRole = user?.role || 'Threat Analyst';

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

      {/* Right Actions: Date, Notification, Quick Scan Shortcut & Avatar Profile */}
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
        <div className="relative" ref={notifRef}>
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

        {/* User Profile Dropdown Menu */}
        <div className="relative pl-2 border-l border-[#263244]/80" ref={profileRef}>
          <button
            onClick={() => setShowProfileMenu(!showProfileMenu)}
            className="flex items-center gap-2 p-1 rounded-lg hover:bg-[#162032] border border-transparent hover:border-[#263244] transition-all group"
            aria-label="User account menu"
          >
            <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center text-white text-xs font-bold ring-1 ring-cyan-500/40 group-hover:ring-cyan-400 transition-all">
              {displayInitials}
            </div>
            <div className="hidden sm:flex flex-col text-left">
              <span className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300 transition-colors leading-tight">
                {displayName}
              </span>
              <span className="text-[10px] font-mono text-slate-400 leading-tight">
                {displayRole}
              </span>
            </div>
            <ChevronDown className="w-3.5 h-3.5 text-slate-400 group-hover:text-slate-200 transition-colors hidden sm:block" />
          </button>

          {/* Dropdown Menu Modal */}
          {showProfileMenu && (
            <div className="absolute right-0 mt-2 w-64 bg-[#111827] border border-[#263244] rounded-xl shadow-2xl p-2 z-50 animate-in fade-in slide-in-from-top-2">
              {/* Profile summary */}
              <div className="p-2.5 border-b border-[#263244] bg-[#0E1526]/80 rounded-lg mb-1">
                <p className="text-xs font-semibold text-slate-100 truncate">{displayName}</p>
                <p className="text-[11px] text-slate-400 font-mono truncate mt-0.5">{displayEmail}</p>
                <div className="mt-2 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-[10px] font-mono uppercase font-semibold text-cyan-400 bg-cyan-500/10 px-1.5 py-0.5 rounded border border-cyan-500/20">
                    {displayRole}
                  </span>
                </div>
              </div>

              {/* Navigation Options */}
              <div className="space-y-0.5 py-1">
                <Link
                  href="/settings"
                  onClick={() => setShowProfileMenu(false)}
                  className="flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium text-slate-300 hover:text-slate-100 hover:bg-[#162032] transition-colors"
                >
                  <Settings className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Account Settings</span>
                </Link>

                <Link
                  href="/scanner"
                  onClick={() => setShowProfileMenu(false)}
                  className="flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium text-slate-300 hover:text-slate-100 hover:bg-[#162032] transition-colors"
                >
                  <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                  <span>URL Security Scanner</span>
                </Link>
              </div>

              {/* Logout Option */}
              <div className="pt-1 mt-1 border-t border-[#263244]">
                <button
                  onClick={handleLogout}
                  className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs font-medium text-red-400 hover:text-red-300 hover:bg-red-500/10 transition-colors"
                >
                  <LogOut className="w-3.5 h-3.5 text-red-400" />
                  <span>Sign Out</span>
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
