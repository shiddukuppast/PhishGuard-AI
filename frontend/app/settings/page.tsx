'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { Header } from '@/components/layout/Header';
import {
  Settings,
  User,
  Sliders,
  Bell,
  Shield,
  Key,
  Copy,
  Check,
  RotateCcw,
  CheckCircle2,
  Lock,
  Calendar,
  ShieldAlert,
} from 'lucide-react';
import { UserSettings } from '@/types';
import { getStoredSettings, saveSettingsToStorage } from '@/lib/storage';
import { useToast } from '@/components/shared/ToastContext';
import { useAuth } from '@/context/AuthContext';
import { cn } from '@/lib/utils';

export default function SettingsPage() {
  const { user, isAuthenticated } = useAuth();
  const { success, info } = useToast();
  const [settings, setSettings] = useState<UserSettings>(() => getStoredSettings());
  const [activeTab, setActiveTab] = useState<'profile' | 'appearance' | 'notifications' | 'security'>('profile');
  const [copiedKey, setCopiedKey] = useState(false);

  useEffect(() => {
    const stored = getStoredSettings();
    if (user) {
      stored.profile = {
        name: user.name || stored.profile.name,
        email: user.email || stored.profile.email,
        role: user.role || stored.profile.role,
        organization: user.organization || stored.profile.organization,
        apiKey: user.apiKey || stored.profile.apiKey,
      };
    }
    setSettings(stored);
  }, [user]);

  const handleToggle = (
    section: 'appearance' | 'notifications' | 'security',
    key: string
  ) => {
    setSettings((prev) => {
      const updated = {
        ...prev,
        [section]: {
          ...prev[section],
          // @ts-ignore
          [key]: !prev[section][key],
        },
      };
      saveSettingsToStorage(updated);
      return updated;
    });
    success('Preference Saved', 'Configuration saved to your client session.');
  };

  const copyApiKey = () => {
    navigator.clipboard.writeText(settings.profile.apiKey);
    setCopiedKey(true);
    info('API Key copied to clipboard');
    setTimeout(() => setCopiedKey(false), 2000);
  };

  const regenerateApiKey = () => {
    const newKey = 'pg_live_' + Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
    setSettings((prev) => {
      const updated = {
        ...prev,
        profile: {
          ...prev.profile,
          apiKey: newKey,
        },
      };
      saveSettingsToStorage(updated);
      return updated;
    });
    success('API Key Regenerated', 'Updated active client bearer key.');
  };

  return (
    <div className="flex flex-col min-h-screen">
      <Header
        title="Settings & System Configuration"
        subtitle="Manage analyst credentials, security thresholds, appearance, and notification rules."
      />

      <div className="p-6 lg:p-8 space-y-6 max-w-6xl mx-auto w-full">
        {/* Tab Header */}
        <div className="flex items-center gap-2 border-b border-[#263244] pb-2 overflow-x-auto">
          {[
            { id: 'profile', label: 'Analyst Profile', icon: User },
            { id: 'appearance', label: 'Appearance', icon: Sliders },
            { id: 'notifications', label: 'Notifications', icon: Bell },
            { id: 'security', label: 'Security & Heuristics', icon: Shield },
          ].map((tab) => {
            const Icon = tab.icon;
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={cn(
                  'flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium transition-all shrink-0',
                  active
                    ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#162032]'
                )}
              >
                <Icon className={cn('w-4 h-4', active ? 'text-cyan-400' : 'text-slate-400')} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Tab 1: Profile Settings */}
        {activeTab === 'profile' && (
          <div className="bg-[#111827] border border-[#263244] rounded-2xl p-6 lg:p-8 shadow-xl space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#263244] pb-4">
              <div>
                <h3 className="text-base font-semibold text-slate-100">Security Analyst Profile</h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Authenticated session information retrieved from Python FastAPI & MongoDB Atlas
                </p>
              </div>

              <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-xs font-mono text-cyan-300">
                <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                <span>{isAuthenticated ? 'Live Authenticated Session' : 'Guest Mode'}</span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              <div className="space-y-1.5">
                <label className="text-xs font-mono text-slate-400 uppercase">Full Name</label>
                <input
                  type="text"
                  readOnly
                  value={user?.name || settings.profile.name}
                  className="w-full px-3 py-2 rounded-lg bg-[#0B1120] border border-[#263244] text-xs text-slate-200 font-sans focus:outline-none cursor-default"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-mono text-slate-400 uppercase">Registered Email</label>
                <input
                  type="email"
                  readOnly
                  value={user?.email || settings.profile.email}
                  className="w-full px-3 py-2 rounded-lg bg-[#0B1120] border border-[#263244] text-xs text-slate-200 font-sans focus:outline-none cursor-default"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-mono text-slate-400 uppercase">Role / Clearance</label>
                <input
                  type="text"
                  readOnly
                  value={user?.role || 'Security Analyst'}
                  className="w-full px-3 py-2 rounded-lg bg-[#0B1120] border border-[#263244] text-xs text-slate-200 font-sans focus:outline-none cursor-default"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-mono text-slate-400 uppercase">Account Created Date</label>
                <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#0B1120] border border-[#263244] text-xs text-slate-300 font-mono">
                  <Calendar className="w-3.5 h-3.5 text-cyan-400" />
                  <span>
                    {user?.createdAt
                      ? new Date(user.createdAt).toLocaleDateString(undefined, {
                          year: 'numeric',
                          month: 'long',
                          day: 'numeric',
                        })
                      : 'Active Session'}
                  </span>
                </div>
              </div>
            </div>

            {user?.id && (
              <div className="p-3 rounded-lg bg-[#0B1120] border border-[#263244] flex items-center justify-between text-xs font-mono">
                <span className="text-slate-400">Database User ID:</span>
                <span className="text-cyan-400 select-all">{user.id}</span>
              </div>
            )}

            {/* API Key management */}
            <div className="pt-4 border-t border-[#263244] space-y-3">
              <div className="flex items-center gap-2">
                <Key className="w-4 h-4 text-cyan-400" />
                <h4 className="text-xs font-mono font-semibold uppercase text-slate-200">
                  Client API Access Key
                </h4>
              </div>

              <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
                <div className="flex-1 p-2.5 rounded-lg bg-[#0B1120] border border-[#263244] font-mono text-xs text-cyan-400 truncate select-all">
                  {settings.profile.apiKey}
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={copyApiKey}
                    className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#162032] hover:bg-[#1E293B] border border-[#263244] text-xs font-mono text-slate-300 transition-colors"
                  >
                    {copiedKey ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedKey ? 'Copied' : 'Copy Key'}</span>
                  </button>
                  <button
                    onClick={regenerateApiKey}
                    className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-[#162032] hover:bg-[#1E293B] border border-[#263244] text-xs font-mono text-slate-300 transition-colors"
                  >
                    <RotateCcw className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Regenerate</span>
                  </button>
                </div>
              </div>
              <p className="text-[11px] text-slate-500 font-mono">
                Bearer key used to authorize external queries to your PhishGuard AI instance.
              </p>
            </div>
          </div>
        )}

        {/* Tab 2: Appearance Preferences */}
        {activeTab === 'appearance' && (
          <div className="bg-[#111827] border border-[#263244] rounded-2xl p-6 lg:p-8 shadow-xl space-y-6">
            <div>
              <h3 className="text-base font-semibold text-slate-100">Appearance & Visual Interface</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Customize interface density, contrast, and animations
              </p>
            </div>

            <div className="divide-y divide-[#263244] rounded-xl border border-[#263244] bg-[#0B1120] overflow-hidden">
              <div className="p-4 flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-semibold text-slate-200">High Contrast Risk Visualization</h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Accentuate critical alerts with vivid high-contrast border and score markers
                  </p>
                </div>
                <button
                  onClick={() => handleToggle('appearance', 'highContrastRisk')}
                  className={cn(
                    'w-11 h-6 rounded-full transition-colors relative focus:outline-none',
                    (settings.appearance as any)?.highContrastRisk ? 'bg-cyan-500' : 'bg-[#1E293B]'
                  )}
                >
                  <span
                    className={cn(
                      'w-4 h-4 rounded-full bg-white absolute top-1 transition-transform',
                      (settings.appearance as any)?.highContrastRisk ? 'left-6' : 'left-1'
                    )}
                  />
                </button>
              </div>

              <div className="p-4 flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-semibold text-slate-200">Compact Dashboard Grid</h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Reduce vertical padding on statistics cards for high-density monitor displays
                  </p>
                </div>
                <button
                  onClick={() => handleToggle('appearance', 'compactMode')}
                  className={cn(
                    'w-11 h-6 rounded-full transition-colors relative focus:outline-none',
                    settings.appearance.compactMode ? 'bg-cyan-500' : 'bg-[#1E293B]'
                  )}
                >
                  <span
                    className={cn(
                      'w-4 h-4 rounded-full bg-white absolute top-1 transition-transform',
                      settings.appearance.compactMode ? 'left-6' : 'left-1'
                    )}
                  />
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Tab 3: Notifications */}
        {activeTab === 'notifications' && (
          <div className="bg-[#111827] border border-[#263244] rounded-2xl p-6 lg:p-8 shadow-xl space-y-6">
            <div>
              <h3 className="text-base font-semibold text-slate-100">Notification Preferences</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Configure immediate alert dispatches for critical threats
              </p>
            </div>

            <div className="divide-y divide-[#263244] rounded-xl border border-[#263244] bg-[#0B1120] overflow-hidden">
              <div className="p-4 flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-semibold text-slate-200">Email Notifications for Phishing</h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Receive immediate email when a scan reaches Risk Score &gt; 85
                  </p>
                </div>
                <button
                  onClick={() => handleToggle('notifications', 'emailOnCriticalThreat')}
                  className={cn(
                    'w-11 h-6 rounded-full transition-colors relative focus:outline-none',
                    settings.notifications.emailOnCriticalThreat ? 'bg-cyan-500' : 'bg-[#1E293B]'
                  )}
                >
                  <span
                    className={cn(
                      'w-4 h-4 rounded-full bg-white absolute top-1 transition-transform',
                      settings.notifications.emailOnCriticalThreat ? 'left-6' : 'left-1'
                    )}
                  />
                </button>
              </div>

              <div className="p-4 flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-semibold text-slate-200">Browser In-App Toast Alerts</h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Display transient notification toasts on scan completion
                  </p>
                </div>
                <button
                  onClick={() => handleToggle('notifications', 'browserAlerts')}
                  className={cn(
                    'w-11 h-6 rounded-full transition-colors relative focus:outline-none',
                    settings.notifications.browserAlerts ? 'bg-cyan-500' : 'bg-[#1E293B]'
                  )}
                >
                  <span
                    className={cn(
                      'w-4 h-4 rounded-full bg-white absolute top-1 transition-transform',
                      settings.notifications.browserAlerts ? 'left-6' : 'left-1'
                    )}
                  />
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Tab 4: Security Preferences */}
        {activeTab === 'security' && (
          <div className="bg-[#111827] border border-[#263244] rounded-2xl p-6 lg:p-8 shadow-xl space-y-6">
            <div>
              <h3 className="text-base font-semibold text-slate-100">Heuristic Engine Tuning</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Fine-tune lexical parsing sensitivity and automatic domain anomaly detection
              </p>
            </div>

            <div className="divide-y divide-[#263244] rounded-xl border border-[#263244] bg-[#0B1120] overflow-hidden">
              <div className="p-4 flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-semibold text-slate-200">Deep Lexical Token Heuristics</h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Inspect path segments, query parameters, and fragmented tokens for credential harvesting signatures
                  </p>
                </div>
                <button
                  onClick={() => handleToggle('security', 'deepUrlHeuristics')}
                  className={cn(
                    'w-11 h-6 rounded-full transition-colors relative focus:outline-none',
                    settings.security.deepUrlHeuristics ? 'bg-cyan-500' : 'bg-[#1E293B]'
                  )}
                >
                  <span
                    className={cn(
                      'w-4 h-4 rounded-full bg-white absolute top-1 transition-transform',
                      settings.security.deepUrlHeuristics ? 'left-6' : 'left-1'
                    )}
                  />
                </button>
              </div>

              <div className="p-4 flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-semibold text-slate-200">Auto-Flag Suspicious TLDs</h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Extract authoritative DNS and TLD entropy characteristics
                  </p>
                </div>
                <button
                  onClick={() => handleToggle('security', 'autoFlagSuspiciousTlds')}
                  className={cn(
                    'w-11 h-6 rounded-full transition-colors relative focus:outline-none',
                    settings.security.autoFlagSuspiciousTlds ? 'bg-cyan-500' : 'bg-[#1E293B]'
                  )}
                >
                  <span
                    className={cn(
                      'w-4 h-4 rounded-full bg-white absolute top-1 transition-transform',
                      settings.security.autoFlagSuspiciousTlds ? 'left-6' : 'left-1'
                    )}
                  />
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
