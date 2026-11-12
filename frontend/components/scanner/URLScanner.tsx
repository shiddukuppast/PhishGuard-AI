'use client';

import React, { useState } from 'react';
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
  RefreshCw,
} from 'lucide-react';
import { ScanResult } from '@/types';
import { scannerApi } from '@/lib/api';
import { ResultCard } from './ResultCard';
import { useToast } from '../shared/ToastContext';
import { cn } from '@/lib/utils';

const SCAN_STAGES = [
  'Extracting URL characteristics & lexical tokens...',
  'Analyzing host structure & protocol security...',
  'Evaluating rule-based security indicators...',
  'Checking ML model availability...',
  'Generating risk score & forensic recommendations...',
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
  const [scanError, setScanError] = useState<string | null>(null);
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

    const generalUrlPattern =
      /^(https?:\/\/)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d+)?(\/.*)?$|^(https?:\/\/)?((\d{1,3}\.){3}\d{1,3})(:\d+)?(\/.*)?$/;
    const testPattern = /^(https?:\/\/)?[a-zA-Z0-9.-]+\.test(\/.*)?$/;

    if (!generalUrlPattern.test(trimmed) && !testPattern.test(trimmed) && !trimmed.includes('.')) {
      setErrorMessage(
        'Invalid URL format. Please enter a valid domain or web address (e.g., https://example.com).'
      );
      return false;
    }

    setErrorMessage(null);
    setScanError(null);
    return true;
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setUrlInput(text.trim());
        setErrorMessage(null);
        setScanError(null);
        info('URL pasted from clipboard');
      }
    } catch {
      toastError('Clipboard access denied', 'Please paste manually into the input box.');
    }
  };

  const handleClear = () => {
    setUrlInput('');
    setErrorMessage(null);
    setScanError(null);
  };

  const executeScan = async () => {
    if (!validateInput(urlInput)) return;

    setIsScanning(true);
    setScanError(null);
    setActiveStageIndex(0);
    setCurrentResult(null);

    const stageDuration = 350; // ms per stage transition

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

    try {
      // Execute actual scan against Python FastAPI POST /api/v1/scanner/scan
      const scanPromise = scannerApi.scanUrl(urlInput.trim());
      const minProgressDelay = new Promise((resolve) =>
        setTimeout(resolve, stageDuration * SCAN_STAGES.length)
      );

      const [finalResult] = await Promise.all([scanPromise, minProgressDelay]);

      clearInterval(interval);
      setCurrentResult(finalResult);
      setIsScanning(false);
      success('Scan Complete', `Forensic analysis finished for ${finalResult.domain}`);

      if (onScanComplete) {
        onScanComplete(finalResult);
      }
    } catch (err: any) {
      clearInterval(interval);
      setIsScanning(false);
      const errorMsg =
        err?.message ||
        'Failed to connect to the PhishGuard analysis service. Please verify the backend is running at http://127.0.0.1:8000.';
      setScanError(errorMsg);
      toastError('Scan Failed', errorMsg);
    }
  };

  const handlePresetSelect = (presetUrl: string) => {
    setUrlInput(presetUrl);
    setErrorMessage(null);
    setScanError(null);
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
          Analyze suspicious URLs, identify potential phishing threats, and inspect structural anomaly indicators using the PhishGuard AI backend.
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
                    if (scanError) setScanError(null);
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
                    errorMessage || scanError
                      ? 'border-red-500 focus:border-red-500 focus:ring-1 focus:ring-red-500/30'
                      : 'border-[#263244] focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30'
                  )}
                />

                {/* Clear Button */}
                {urlInput && !isScanning && (
                  <button
                    onClick={handleClear}
                    className="absolute right-3 top-1/2 -translate-y-1/2 p-1 rounded-md text-slate-500 hover:text-slate-300 transition-colors"
                    title="Clear input"
                  >
                    <X className="w-4 h-4" />
                  </button>
                )}
              </div>

              {/* Paste from Clipboard Button */}
              <button
                onClick={handlePaste}
                disabled={isScanning}
                className="px-4 py-3.5 rounded-xl bg-[#162032] hover:bg-[#1E293B] border border-[#263244] text-slate-300 hover:text-white text-xs font-mono transition-all flex items-center justify-center gap-2 disabled:opacity-50"
                title="Paste from clipboard"
              >
                <Clipboard className="w-4 h-4 text-slate-400" />
                <span className="hidden sm:inline">Paste</span>
              </button>

              {/* Scan Now CTA */}
              <button
                onClick={executeScan}
                disabled={isScanning || !urlInput.trim()}
                className="px-7 py-3.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:bg-cyan-500/30 disabled:text-cyan-900/50 text-[#041C24] font-bold text-sm tracking-wide transition-all shadow-lg shadow-cyan-500/20 flex items-center justify-center gap-2"
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
                  </>
                )}
              </button>
            </div>

            {/* Validation Error Banner */}
            {errorMessage && (
              <div className="flex items-center gap-2 text-xs text-red-400 font-mono mt-2 animate-in fade-in duration-200">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{errorMessage}</span>
              </div>
            )}

            {/* Backend Scan Network/API Error Banner */}
            {scanError && (
              <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 flex items-start justify-between gap-3 text-xs text-red-300 font-mono mt-2 animate-in fade-in">
                <div className="flex items-start gap-2.5">
                  <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <span className="font-bold text-red-200">Analysis Error</span>
                    <p className="text-[11px] text-red-300/90 leading-relaxed">{scanError}</p>
                  </div>
                </div>
                <button
                  onClick={executeScan}
                  className="px-3 py-1.5 rounded-lg bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-red-200 font-mono text-[11px] flex items-center gap-1.5 shrink-0 transition-colors"
                >
                  <RefreshCw className="w-3 h-3" />
                  <span>Retry</span>
                </button>
              </div>
            )}
          </div>

          {/* Quick Presets / Test Lures */}
          <div className="pt-2">
            <div className="flex items-center gap-2 mb-2 text-xs text-slate-400 font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
              <span>Or test with a sample security target:</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
              {PRESET_EXAMPLES.map((preset, index) => (
                <button
                  key={index}
                  onClick={() => handlePresetSelect(preset.url)}
                  disabled={isScanning}
                  className="p-2.5 rounded-lg bg-[#0B1120] hover:bg-[#162032] border border-[#263244] hover:border-[#334155] text-left transition-all group flex flex-col justify-between gap-1 disabled:opacity-50"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-slate-200 group-hover:text-cyan-300 transition-colors truncate">
                      {preset.label}
                    </span>
                    <span className={cn('text-[9px] font-mono px-1.5 py-0.2 rounded border', preset.badgeColor)}>
                      {preset.type}
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-500 truncate block">
                    {preset.url}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Live Multi-Stage Progress Animation */}
        {isScanning && (
          <div className="mt-6 pt-6 border-t border-[#263244] space-y-4 animate-in fade-in duration-300">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-cyan-400 font-semibold flex items-center gap-2">
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                <span>Stage {activeStageIndex + 1} of {SCAN_STAGES.length}</span>
              </span>
              <span className="text-slate-400">
                {Math.round(((activeStageIndex + 1) / SCAN_STAGES.length) * 100)}%
              </span>
            </div>

            {/* Progress Track */}
            <div className="h-1.5 w-full bg-[#0B1120] rounded-full overflow-hidden border border-[#263244]">
              <div
                className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full transition-all duration-300 ease-out"
                style={{ width: `${((activeStageIndex + 1) / SCAN_STAGES.length) * 100}%` }}
              />
            </div>

            {/* Stage Items */}
            <div className="space-y-1.5 font-mono text-xs">
              {SCAN_STAGES.map((stage, idx) => (
                <div
                  key={idx}
                  className={cn(
                    'flex items-center gap-2 transition-colors',
                    idx < activeStageIndex
                      ? 'text-emerald-400'
                      : idx === activeStageIndex
                      ? 'text-cyan-300 font-semibold'
                      : 'text-slate-600'
                  )}
                >
                  {idx < activeStageIndex ? (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  ) : idx === activeStageIndex ? (
                    <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400 shrink-0" />
                  ) : (
                    <span className="w-3.5 h-3.5 rounded-full border border-slate-700 shrink-0" />
                  )}
                  <span>{stage}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Analysis Result Card */}
      {currentResult && !isScanning && (
        <ResultCard
          result={currentResult}
          onScanAnother={() => {
            setCurrentResult(null);
            setUrlInput('');
          }}
        />
      )}
    </div>
  );
}
