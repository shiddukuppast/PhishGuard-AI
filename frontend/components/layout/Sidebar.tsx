'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useAuth } from '@/context/AuthContext';
import {
  Shield,
  LayoutDashboard,
  Search,
  History,
  Radio,
  FileText,
  Settings,
  HelpCircle,
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  Menu,
  X,
  ExternalLink,
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface NavItem {
  label: string;
  href: string;
  icon: React.ElementType;
  badge?: string;
}

const NAV_ITEMS: NavItem[] = [
  { label: 'Overview', href: '/dashboard', icon: LayoutDashboard },
  { label: 'URL Scanner', href: '/scanner', icon: Search, badge: 'Active' },
  { label: 'Scan History', href: '/history', icon: History },
  { label: 'Threat Intelligence', href: '/intelligence', icon: Radio, badge: 'Live' },
  { label: 'Reports', href: '/reports', icon: FileText },
];

const BOTTOM_ITEMS: NavItem[] = [
  { label: 'Settings', href: '/settings', icon: Settings },
];

export function Sidebar() {
  const pathname = usePathname();
  const { user } = useAuth();
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [isMobileOpen, setIsMobileOpen] = useState(false);
  const [showHelpModal, setShowHelpModal] = useState(false);

  // Auto-close mobile drawer on route change
  const handleNavClick = () => {
    setIsMobileOpen(false);
  };

  const isActive = (href: string) => {
    if (href === '/dashboard' && (pathname === '/' || pathname === '/dashboard')) return true;
    return pathname.startsWith(href);
  };

  return (
    <>
      {/* Mobile Top Bar */}
      <div className="lg:hidden flex items-center justify-between px-4 py-3 bg-[#0B1120] border-b border-[#263244] sticky top-0 z-40">
        <Link href="/dashboard" className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Shield className="w-4 h-4 text-cyan-400" />
          </div>
          <div>
            <span className="font-semibold text-slate-100 text-sm tracking-tight">PhishGuard</span>
            <span className="text-cyan-400 text-xs font-mono ml-1 font-semibold">AI</span>
          </div>
        </Link>
        <button
          onClick={() => setIsMobileOpen(!isMobileOpen)}
          className="p-2 text-slate-400 hover:text-slate-100 rounded-lg hover:bg-[#162032] border border-transparent hover:border-[#263244] transition-colors"
          aria-label="Toggle navigation menu"
        >
          {isMobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>
      </div>

      {/* Mobile Backdrop */}
      {isMobileOpen && (
        <div
          className="lg:hidden fixed inset-0 bg-black/70 backdrop-blur-sm z-40 animate-fade-in"
          onClick={() => setIsMobileOpen(false)}
        />
      )}

      {/* Sidebar Container */}
      <aside
        className={cn(
          'fixed lg:sticky top-0 left-0 z-40 h-screen bg-[#0E1526] border-r border-[#263244] flex flex-col justify-between transition-all duration-300 ease-in-out',
          isCollapsed ? 'w-20' : 'w-64',
          isMobileOpen ? 'translate-x-0 w-64' : '-translate-x-full lg:translate-x-0'
        )}
      >
        {/* Top: Logo & Collapse Button */}
        <div>
          <div className="h-16 px-4 flex items-center justify-between border-b border-[#263244]">
            <Link
              href="/dashboard"
              className={cn(
                'flex items-center gap-3 transition-opacity duration-200 overflow-hidden',
                isCollapsed && 'justify-center w-full'
              )}
            >
              <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-sm shrink-0">
                <Shield className="w-5 h-5 text-cyan-400" />
              </div>
              {!isCollapsed && (
                <div className="flex flex-col">
                  <div className="flex items-center gap-1.5">
                    <span className="font-bold text-slate-100 text-base tracking-tight">PhishGuard</span>
                    <span className="text-xs font-mono font-semibold px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                      AI
                    </span>
                  </div>
                  <span className="text-[10px] text-slate-500 uppercase tracking-widest font-mono">
                    Detect • Analyze • Protect
                  </span>
                </div>
              )}
            </Link>

            {/* Desktop collapse toggle */}
            {!isCollapsed && (
              <button
                onClick={() => setIsCollapsed(true)}
                className="hidden lg:flex items-center justify-center w-7 h-7 rounded-md text-slate-400 hover:text-slate-100 hover:bg-[#162032] border border-transparent hover:border-[#263244] transition-colors"
                title="Collapse sidebar"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
            )}
          </div>

          {/* Collapsed Expand Toggle */}
          {isCollapsed && (
            <div className="hidden lg:flex justify-center py-2 border-b border-[#263244]">
              <button
                onClick={() => setIsCollapsed(false)}
                className="p-1.5 rounded-md text-slate-400 hover:text-cyan-400 hover:bg-[#162032] transition-colors"
                title="Expand sidebar"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* Navigation Section */}
          <div className="px-3 py-4">
            {!isCollapsed && (
              <p className="px-3 mb-2 text-[11px] font-mono uppercase tracking-wider text-slate-500">
                Navigation
              </p>
            )}
            <nav className="space-y-1">
              {NAV_ITEMS.map((item) => {
                const active = isActive(item.href);
                const Icon = item.icon;

                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={handleNavClick}
                    className={cn(
                      'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all group relative',
                      active
                        ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/25 shadow-sm'
                        : 'text-slate-400 hover:text-slate-100 hover:bg-[#162032]',
                      isCollapsed && 'justify-center px-2'
                    )}
                    title={isCollapsed ? item.label : undefined}
                  >
                    <Icon
                      className={cn(
                        'w-4 h-4 shrink-0 transition-colors',
                        active ? 'text-cyan-400' : 'text-slate-400 group-hover:text-slate-200'
                      )}
                    />
                    {!isCollapsed && <span className="truncate">{item.label}</span>}
                    {!isCollapsed && item.badge && (
                      <span
                        className={cn(
                          'ml-auto text-[10px] px-1.5 py-0.5 rounded font-mono font-medium',
                          item.badge === 'Live'
                            ? 'bg-red-500/10 text-red-400 border border-red-500/20 animate-pulse'
                            : 'bg-[#162032] text-slate-400 border border-[#263244]'
                        )}
                      >
                        {item.badge}
                      </span>
                    )}

                    {/* Active left indicator pill */}
                    {active && (
                      <span className="absolute left-0 top-1.5 bottom-1.5 w-1 bg-cyan-400 rounded-r" />
                    )}
                  </Link>
                );
              })}
            </nav>
          </div>
        </div>

        {/* Bottom Section */}
        <div className="p-3 border-t border-[#263244] space-y-1">
          {!isCollapsed && (
            <p className="px-3 mb-1 text-[11px] font-mono uppercase tracking-wider text-slate-500">
              System
            </p>
          )}

          {BOTTOM_ITEMS.map((item) => {
            const active = isActive(item.href);
            const Icon = item.icon;
            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={handleNavClick}
                className={cn(
                  'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors group',
                  active
                    ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/25'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-[#162032]',
                  isCollapsed && 'justify-center px-2'
                )}
                title={isCollapsed ? item.label : undefined}
              >
                <Icon className="w-4 h-4 shrink-0 text-slate-400 group-hover:text-slate-200" />
                {!isCollapsed && <span>{item.label}</span>}
              </Link>
            );
          })}

          {/* Help & Support Button */}
          <button
            onClick={() => setShowHelpModal(true)}
            className={cn(
              'w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-slate-400 hover:text-slate-100 hover:bg-[#162032] transition-colors group',
              isCollapsed && 'justify-center px-2'
            )}
            title={isCollapsed ? 'Help & Support' : undefined}
          >
            <HelpCircle className="w-4 h-4 shrink-0 text-slate-400 group-hover:text-slate-200" />
            {!isCollapsed && <span>Help & Support</span>}
          </button>

          {/* User Profile Card */}
          <Link
            href="/settings"
            className={cn(
              'mt-2 pt-2 border-t border-[#263244]/60 flex items-center gap-3 px-2 py-1.5 rounded-lg bg-[#111827]/60 hover:bg-[#162032] transition-colors group',
              isCollapsed && 'justify-center px-0'
            )}
            title={user?.name || 'Account Settings'}
          >
            <div className="w-8 h-8 rounded-full bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center text-white font-semibold text-xs shrink-0 ring-1 ring-cyan-500/30 group-hover:ring-cyan-400">
              {user?.avatarInitials || 'PG'}
            </div>
            {!isCollapsed && (
              <div className="flex-1 min-w-0">
                <p className="text-xs font-semibold text-slate-200 truncate group-hover:text-cyan-300 transition-colors">
                  {user?.name || 'Security Analyst'}
                </p>
                <div className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-[10px] text-slate-400 font-mono truncate">
                    {user?.role || 'Threat Analyst'}
                  </span>
                </div>
              </div>
            )}
          </Link>
        </div>
      </aside>

      {/* Help & Support Modal */}
      {showHelpModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-lg bg-[#111827] border border-[#263244] rounded-xl p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-[#263244] pb-4">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                  <ShieldAlert className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-base font-semibold text-slate-100">PhishGuard AI Help & Support</h3>
                  <p className="text-xs text-slate-400">Documentation, ML architecture, and SOC contact</p>
                </div>
              </div>
              <button
                onClick={() => setShowHelpModal(false)}
                className="text-slate-400 hover:text-slate-200 p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-sm text-slate-300">
              <div className="p-3 rounded-lg bg-[#0B1120] border border-[#263244] space-y-1.5">
                <h4 className="text-xs font-mono font-semibold text-cyan-400 uppercase">Detection Pipeline</h4>
                <p className="text-xs text-slate-400 leading-relaxed">
                  PhishGuard AI evaluates URLs via multi-layered heuristic extraction, lexical token inspection, domain entropy analysis, and Python FastAPI risk assessment engine with Scikit-learn integration.
                </p>
              </div>

              <div className="p-3 rounded-lg bg-[#0B1120] border border-[#263244] space-y-1.5">
                <h4 className="text-xs font-mono font-semibold text-cyan-400 uppercase">Risk Scoring Scale</h4>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-emerald-400" />
                    <span>0–30: Low Risk (Safe)</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-amber-400" />
                    <span>31–60: Medium Risk (Suspicious)</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-orange-400" />
                    <span>61–80: High Risk (Phishing)</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-red-400" />
                    <span>81–100: Critical Risk (Active Phish)</span>
                  </div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-[#0B1120] border border-[#263244] space-y-1">
                <h4 className="text-xs font-mono font-semibold text-cyan-400 uppercase">FastAPI Integration</h4>
                <p className="text-xs text-slate-400">
                  Ready for endpoint connection: <code className="text-cyan-300 bg-[#162032] px-1 py-0.5 rounded text-[11px]">POST /api/v1/scan</code>. Currently running client-side heuristics.
                </p>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setShowHelpModal(false)}
                className="px-4 py-2 text-xs font-medium bg-[#162032] hover:bg-[#1E293B] text-slate-200 border border-[#263244] rounded-lg transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

