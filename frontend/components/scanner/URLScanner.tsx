'use client';

import React, { useState, useEffect } from 'react';
import {
  Search,
  Clipboard,
  X,
  AlertCircle,
  ShieldCheck,
  CheckCircle2,
  Loader2,
  Sparkles,
  ArrowRight,
  Shield,
  Info,
  ExternalLink,
} from 'lucide-react';
import { ScanResult } from '@/types';
import { analyzeUrlHeuristics } from '@/lib/scanner';
import { saveScanToStorage } from '@/lib/storage';
import { ResultCard } from './ResultCard';
import { useToast } from '../shared/ToastContext';
import { cn } from '@/lib/utils';

const SCAN_STAGES = [
  'Extracting URL characteristics...',
  'Analyzing domain structure...',
  'Evaluating security indicators...',
  'Running ML-based detection...',
  'Generating risk assessment...',
];

const PRESET_EXAMPLES = [
  {
    label: 'Account Verification Lure',
    url: 'http://secure-account-verification.example.test',
    type: 'Critical Phish',
    badgeColor: 'text-red-400 bg-red-500/10 border-red-500/20',
  },
  {
    label: 'IP Host Credential Harvester',
    url: 'http://192.168.1.104/paypal-update/login.php',
    type: 'Critical Phish',
    badgeColor: 'text-red-400 bg-red-500/10 border-red-500/20',
  },
  {
    label: 'Package Delivery Smishing',
    url: 'https://track-package-order-update.xyz/status',
    type: 'Suspicious',
    badgeColor: 'text-amber-400 bg-amber-500/10 border-amber-500/20',
  },
  {
    label: 'Legitimate Platform',
    url: 'https://stripe.com/docs/api',
    type: 'Safe',
    badgeColor: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20',
  },
];

export function URLScanner({
  initialUrl = '',
  onScanComplete,
}: {
  initialUrl?: string;
  onScanComplete?: (result: ScanResult) => void;
}) {
  const { success, error: toastError, info } = useToast();
  const [urlInput, setUrlInput] = useState(initialUrl);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [activeStageIndex, setActiveStageIndex] = useState(0);
  const [currentResult, setCurrentResult] = useState<ScanResult | null>(null);

  // Validate URL syntax
  const validateInput = (value: string): boolean => {
    const trimmed = value.trim();
    if (!trimmed) {
      setErrorMessage('Please enter a target URL to analyze.');
      return false;
    }

    // Basic format check: needs at least a domain or protocol
    // Support formats like "google.com", "http://domain.tld", "192.168.1.1/login"
    const generalUrlPattern = /^(https?:\/\/)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d+)?(\/.*)?$|^(https?:\/\/)?((\d{1,3}\.){3}\d{1,3})(:\d+)?(\/.*)?$/;
    
    // Also allow pseudo-tlds like .test for security testing
    const testPattern = /^(https?:\/\/)?[a-zA-Z0-9.-]+\.test(\/.*)?$/;

    if (!generalUrlPattern.test(trimmed) && !testPattern.test(trimmed) && !trimmed.includes('.')) {
      setErrorMessage('Invalid URL format. Please enter a valid domain or web address (e.g., https://example.com).');
      return false;
    }

    setErrorMessage(null);
    return true;
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setUrlInput(text.trim());
        setErrorMessage(null);
        info('URL pasted from clipboard');
      }
    } catch {
      toastError('Clipboard access denied', 'Please paste manually into the input box.');
    }
  };

  const handleClear = () => {
    setUrlInput('');
    setErrorMessage(null);
  };

  const executeScan = () => {
    if (!validateInput(urlInput)) return;

    setIsScanning(true);
    setActiveStageIndex(0);
    setCurrentResult(null);

    // Multi-stage progress simulation
    const stageDuration = 450; // ms per stage (total ~2.2s for crisp cybersecurity feel)

    const interval = setInterval(() => {
      setActiveStageIndex((prev) => {
        if (prev < SCAN_STAGES.length - 1) {
          return prev + 1;
        } else {
          clearInterval(interval);
          return prev;
        }
      });
    }, stageDuration);

    setTimeout(() => {
      clearInterval(interval);
      // Run heuristic analysis
      const analysisResult = analyzeUrlHeuristics(urlInput);
      
      // Persist to storage
      saveScanToStorage(analysisResult);

      setCurrentResult(analysisResult);
      setIsScanning(false);
      success('Scan Complete', `Analysis finished for ${analysisResult.domain}`);

      if (onScanComplete) {
        onScanComplete(analysisResult);
      }
    }, stageDuration * SCAN_STAGES.length + 200);
  };

  const handlePresetSelect = (presetUrl: string) => {
    setUrlInput(presetUrl);
    setErrorMessage(null);
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Title & Subtitle Banner */}
      <div className="space-y-1.5 text-center sm:text-left">
        <h2 className="text-xl sm:text-2xl font-bold text-slate-100 tracking-tight flex items-center justify-center sm:justify-start gap-2.5">
          <Shield className="w-6 h-6 text-cyan-400" />
          <span>URL Security Scanner</span>
        </h2>
        <p className="text-xs sm:text-sm text-slate-400 max-w-2xl">
          Analyze suspicious URLs and identify potential phishing threats using intelligent security analysis.
        </p>
      </div>

      {/* Main Scanner Card */}
      <div className="bg-[#111827] border border-[#263244] rounded-2xl p-5 sm:p-7 shadow-2xl relative overflow-hidden">
        {/* Subtle top cyan line highlight */}
        <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-500/50 to-transparent" />

        <div className="space-y-4">
          {/* Input container with buttons */}
          <div className="space-y-2">
            <div className="relative flex flex-col sm:flex-row items-stretch gap-2.5">
              <div className="relative flex-1">
                <Search className="w-5 h-5 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
                <input
                  type="text"
                  value={urlInput}
                  onChange={(e) => {
                    setUrlInput(e.target.value);
                    if (errorMessage) setErrorMessage(null);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !isScanning) {
                      executeScan();
                    }
                  }}
                  placeholder="https://example.com"
                  disabled={isScanning}
                  className={cn(
                    'w-full pl-11 pr-20 py-3.5 rounded-xl bg-[#0B1120] border text-sm text-slate-100 placeholder-slate-500 font-mono transition-all focus:outline-none disabled:opacity-50',
                    errorMessage
                      ? 'border-red-500/60 focus:border-red-400'
                      : 'border-[#263244] focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30'
                  )}
                />

                {/* Clear & Paste helpers inside the input */}
                <div className="absolute right-2.5 top-1/2 -translate-y-1/2 flex items-center gap-1">
                  {urlInput && !isScanning && (
                    <button
                      onClick={handleClear}
                      className="p-1 rounded-md text-slate-500 hover:text-slate-300 hover:bg-[#162032] transition-colors"
                      title="Clear input"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  )}
                  <button
                    onClick={handlePaste}
                    disabled={isScanning}
                    className="p-1.5 rounded-md text-slate-400 hover:text-cyan-400 hover:bg-[#162032] transition-colors"
                    title="Paste URL"
                  >
                    <Clipboard className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Scan URL Primary Action */}
              <button
                onClick={executeScan}
                disabled={isScanning}
                className="px-6 py-3.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-[#041C24] font-bold text-sm tracking-wide transition-all shadow-lg shadow-cyan-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 shrink-0 group"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <Sparkles className="w-4 h-4" />
                    <span>Scan URL</span>
                    <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
                  </>
                )}
              </button>
            </div>

            {/* Error Message */}
            {errorMessage && (
              <div className="flex items-center gap-2 text-red-400 text-xs font-mono pt-1 animate-in fade-in">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{errorMessage}</span>
              </div>
            )}
          </div>

          {/* Privacy Notice Requirement */}
          <div className="flex items-start gap-2 p-3 rounded-lg bg-[#0B1120]/80 border border-[#263244] text-[11px] text-slate-400">
            <Info className="w-4 h-4 text-cyan-400/80 shrink-0 mt-0.5" />
            <p className="leading-relaxed">
              <span className="font-semibold text-slate-300">Privacy Notice:</span> Only scan URLs you are authorized to analyze. Avoid opening suspicious links directly in your personal browser session.
            </p>
          </div>

          {/* Quick-test Presets */}
          <div className="pt-2">
            <span className="text-[11px] font-mono uppercase text-slate-500 block mb-2">
              Select verification scenario (sample telemetry):
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
              {PRESET_EXAMPLES.map((preset, idx) => (
                <button
                  key={idx}
                  onClick={() => handlePresetSelect(preset.url)}
                  disabled={isScanning}
                  className="p-2.5 rounded-lg bg-[#0B1120] hover:bg-[#162032] border border-[#263244] hover:border-[#384961] text-left transition-all flex flex-col justify-between group disabled:opacity-50"
                >
                  <div className="flex items-center justify-between gap-1 mb-1">
                    <span className="text-xs font-medium text-slate-300 group-hover:text-cyan-300 transition-colors truncate">
                      {preset.label}
                    </span>
                    <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded border ${preset.badgeColor}`}>
                      {preset.type}
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-slate-500 truncate block">
                    {preset.url}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Multi-Stage Scanning Process Animation */}
        {isScanning && (
          <div className="mt-6 pt-6 border-t border-[#263244] space-y-4 animate-in fade-in">
            <div className="flex items-center justify-between text-xs font-mono">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                <span className="text-slate-200 font-semibold">
                  {SCAN_STAGES[activeStageIndex]}
                </span>
              </div>
              <span className="text-cyan-400">
                Step {activeStageIndex + 1} of {SCAN_STAGES.length}
              </span>
            </div>

            {/* Progress bar */}
            <div className="w-full h-1.5 rounded-full bg-[#0B1120] overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-300 ease-out"
                style={{
                  width: `${((activeStageIndex + 1) / SCAN_STAGES.length) * 100}%`,
                }}
              />
            </div>

            {/* Stages checklist */}
            <div className="grid grid-cols-1 sm:grid-cols-5 gap-2 pt-2">
              {SCAN_STAGES.map((stage, idx) => {
                const isDone = idx < activeStageIndex;
                const isCurrent = idx === activeStageIndex;

                return (
                  <div
                    key={idx}
                    className={cn(
                      'p-2 rounded-lg border text-[11px] font-mono flex items-center gap-2 transition-all',
                      isDone
                        ? 'bg-emerald-950/20 border-emerald-500/30 text-emerald-300'
                        : isCurrent
                        ? 'bg-cyan-950/30 border-cyan-500/40 text-cyan-200'
                        : 'bg-[#0B1120]/50 border-[#1E293B] text-slate-600'
                    )}
                  >
                    {isDone ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    ) : isCurrent ? (
                      <Loader2 className="w-3.5 h-3.5 text-cyan-400 animate-spin shrink-0" />
                    ) : (
                      <span className="w-3.5 h-3.5 rounded-full border border-slate-700 flex items-center justify-center text-[9px] text-slate-600 shrink-0">
                        {idx + 1}
                      </span>
                    )}
                    <span className="truncate">{stage.replace('...', '')}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Dynamic Scan Result Component */}
      {currentResult && (
        <div className="animate-in fade-in slide-in-from-bottom-4 duration-300">
          <ResultCard
            result={currentResult}
            onScanAnother={() => {
              setCurrentResult(null);
              setUrlInput('');
            }}
          />
        </div>
      )}
    </div>
  );
}

