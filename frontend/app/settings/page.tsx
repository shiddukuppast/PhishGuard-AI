'use client';

import React, { useState, useEffect } from 'react';
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
  Save,
  CheckCircle2,
  Sparkles,
} from 'lucide-react';
import { UserSettings } from '@/types';
import { getStoredSettings, saveSettingsToStorage } from '@/lib/storage';
import { useToast } from '@/components/shared/ToastContext';
import { cn } from '@/lib/utils';

export default function SettingsPage() {
  const { success, info } = useToast();
  const [settings, setSettings] = useState<UserSettings>(getStoredSettings());
  const [activeTab, setActiveTab] = useState<'profile' | 'appearance' | 'notifications' | 'security'>('profile');
  const [copiedKey, setCopiedKey] = useState(false);

  useEffect(() => {
    setSettings(getStoredSettings());
  }, []);

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
    success('Preference Saved', 'Configuration saved to local profile cache.');
  };

  const handleProfileChange = (field: keyof UserSettings['profile'], value: string) => {
    setSettings((prev) => {
      const updated = {
        ...prev,
        profile: {
          ...prev.profile,
          [field]: value,
        },
      };
      saveSettingsToStorage(updated);
      return updated;
    });
  };

  const copyApiKey = () => {
    navigator.clipboard.writeText(settings.profile.apiKey);
    setCopiedKey(true);
    info('API Key copied to clipboard');
    setTimeout(() => setCopiedKey(false), 2000);
  };

  const regenerateApiKey = () => {
    const newKey = 'pg_live_' + Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
    handleProfileChange('apiKey', newKey);
    success('API Key Regenerated', 'Updated active client bearer token.');
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
            { id: 'security', label: 'Security & ML Rules', icon: Shield },
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
            <div>
              <h3 className="text-base font-semibold text-slate-100">Security Analyst Profile</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Manage your credentials, organization metadata, and API access keys
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              <div className="space-y-1.5">
                <label className="text-xs font-mono text-slate-400 uppercase">Full Name</label>
                <input
                  type="text"
                  value={settings.profile.name}
                  onChange={(e) => handleProfileChange('name', e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#0B1120] border border-[#263244] text-xs text-slate-100 font-sans focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-mono text-slate-400 uppercase">Work Email</label>
                <input
                  type="email"
                  value={settings.profile.email}
                  onChange={(e) => handleProfileChange('email', e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#0B1120] border border-[#263244] text-xs text-slate-100 font-sans focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-mono text-slate-400 uppercase">Role / Clearance</label>
                <input
                  type="text"
                  value={settings.profile.role}
                  onChange={(e) => handleProfileChange('role', e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#0B1120] border border-[#263244] text-xs text-slate-100 font-sans focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-mono text-slate-400 uppercase">Organization</label>
                <input
                  type="text"
                  value={settings.profile.organization}
                  onChange={(e) => handleProfileChange('organization', e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#0B1120] border border-[#263244] text-xs text-slate-100 font-sans focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            {/* API Key management */}
            <div className="pt-4 border-t border-[#263244] space-y-3">
              <div className="flex items-center gap-2">
                <Key className="w-4 h-4 text-cyan-400" />
                <h4 className="text-xs font-mono font-semibold uppercase text-slate-200">
                  FastAPI Engine Access Key
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
                Used to authenticate automated requests to the upcoming FastAPI prediction cluster.
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
                    settings.appearance.highContrastRisk ? 'bg-cyan-500' : 'bg-[#1E293B]'
                  )}
                >
                  <span
                    className={cn(
                      'w-4 h-4 rounded-full bg-white absolute top-1 transition-transform',
                      settings.appearance.highContrastRisk ? 'left-6' : 'left-1'
                    )}
                  />
                </button>
              </div>

              <div className="p-4 flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-semibold text-slate-200">Show Scanning Stage Animations</h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Display the 5-step heuristic pipeline progression animation when scanning URLs
                  </p>
                </div>
                <button
                  onClick={() => handleToggle('appearance', 'showAnimationStage')}
                  className={cn(
                    'w-11 h-6 rounded-full transition-colors relative focus:outline-none',
                    settings.appearance.showAnimationStage ? 'bg-cyan-500' : 'bg-[#1E293B]'
                  )}
                >
                  <span
                    className={cn(
                      'w-4 h-4 rounded-full bg-white absolute top-1 transition-transform',
                      settings.appearance.showAnimationStage ? 'left-6' : 'left-1'
                    )}
                  />
                </button>
              </div>

              <div className="p-4 flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-semibold text-slate-200">Compact Dashboard Density</h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Condense table row paddings and metrics spacing for high-density monitors
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

        {/* Tab 3: Notification Preferences */}
        {activeTab === 'notifications' && (
          <div className="bg-[#111827] border border-[#263244] rounded-2xl p-6 lg:p-8 shadow-xl space-y-6">
            <div>
              <h3 className="text-base font-semibold text-slate-100">Notification Alerts</h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Configure immediate security alerting thresholds and periodic digests
              </p>
            </div>

            <div className="divide-y divide-[#263244] rounded-xl border border-[#263244] bg-[#0B1120] overflow-hidden">
              <div className="p-4 flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-semibold text-slate-200">Email on Critical Threat (Risk &gt; 80)</h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Dispatch immediate notification to SOC responders when an active phishing lure is confirmed
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
                  <h4 className="text-xs font-semibold text-slate-200">Daily Threat Digest</h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Summary of all intercepted URLs, trending impersonated brands, and blocked IP hosts
                  </p>
                </div>
                <button
                  onClick={() => handleToggle('notifications', 'dailyDigest')}
                  className={cn(
                    'w-11 h-6 rounded-full transition-colors relative focus:outline-none',
                    settings.notifications.dailyDigest ? 'bg-cyan-500' : 'bg-[#1E293B]'
                  )}
                >
                  <span
                    className={cn(
                      'w-4 h-4 rounded-full bg-white absolute top-1 transition-transform',
                      settings.notifications.dailyDigest ? 'left-6' : 'left-1'
                    )}
                  />
                </button>
              </div>

              <div className="p-4 flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-semibold text-slate-200">Weekly Security Intelligence Report</h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Consolidated executive compliance report delivered in Markdown and CSV formats
                  </p>
                </div>
                <button
                  onClick={() => handleToggle('notifications', 'weeklySecurityReport')}
                  className={cn(
                    'w-11 h-6 rounded-full transition-colors relative focus:outline-none',
                    settings.notifications.weeklySecurityReport ? 'bg-cyan-500' : 'bg-[#1E293B]'
                  )}
                >
                  <span
                    className={cn(
                      'w-4 h-4 rounded-full bg-white absolute top-1 transition-transform',
                      settings.notifications.weeklySecurityReport ? 'left-6' : 'left-1'
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
                  <h4 className="text-xs font-semibold text-slate-200">Auto-Flag Elevated-Abuse TLDs</h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Automatically increase risk baseline for disposable extensions (.xyz, .top, .buzz, .rest)
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

              <div className="p-4 flex items-center justify-between">
                <div>
                  <h4 className="text-xs font-semibold text-slate-200">Strict HTTPS Enforcement</h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Flag any plaintext HTTP destination containing authentication keywords with critical penalty
                  </p>
                </div>
                <button
                  onClick={() => handleToggle('security', 'strictHttpsEnforcement')}
                  className={cn(
                    'w-11 h-6 rounded-full transition-colors relative focus:outline-none',
                    settings.security.strictHttpsEnforcement ? 'bg-cyan-500' : 'bg-[#1E293B]'
                  )}
                >
                  <span
                    className={cn(
                      'w-4 h-4 rounded-full bg-white absolute top-1 transition-transform',
                      settings.security.strictHttpsEnforcement ? 'left-6' : 'left-1'
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

