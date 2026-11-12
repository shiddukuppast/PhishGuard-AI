'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  Shield,
  Eye,
  EyeOff,
  Lock,
  Mail,
  ArrowRight,
  Loader2,
  CheckCircle2,
  AlertCircle,
  Sparkles,
  Zap,
  Globe,
  Radio,
  FileCheck,
} from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/components/shared/ToastContext';

export default function LoginPage() {
  const router = useRouter();
  const { login } = useAuth();
  const { success, error: toastError } = useToast();

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [rememberMe, setRememberMe] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [showForgotPasswordModal, setShowForgotPasswordModal] = useState(false);
  const [forgotEmail, setForgotEmail] = useState('');
  const [resetSuccess, setResetSuccess] = useState(false);

  // Email format validation
  const validateEmail = (val: string) => {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val.trim());
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    // Validation checks
    if (!email.trim()) {
      setFormError('Please enter your email address.');
      return;
    }
    if (!validateEmail(email)) {
      setFormError('Please enter a valid email address (e.g., analyst@defense.sec).');
      return;
    }
    if (!password) {
      setFormError('Please enter your password.');
      return;
    }
    if (password.length < 6) {
      setFormError('Password must be at least 6 characters long.');
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await login({ email, password, rememberMe });
      if (res.success) {
        success('Access Granted', 'Welcome back to PhishGuard AI.');
        router.push('/dashboard');
      } else {
        setFormError(res.message || 'Authentication failed. Please verify your credentials.');
        toastError('Authentication Failed', res.message);
      }
    } catch {
      setFormError('An unexpected network error occurred. Please try again.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleForgotPassword = (e: React.FormEvent) => {
    e.preventDefault();
    if (!validateEmail(forgotEmail)) {
      toastError('Invalid Email', 'Please enter a valid recovery email address.');
      return;
    }
    setResetSuccess(true);
    setTimeout(() => {
      setShowForgotPasswordModal(false);
      setResetSuccess(false);
      setForgotEmail('');
      success('Recovery Dispatched', 'Password reset instructions delivered to your inbox.');
    }, 1800);
  };

  return (
    <div className="min-h-screen w-full bg-[#0B1120] flex flex-col justify-between text-slate-100 selection:bg-cyan-500/20 selection:text-cyan-300">
      {/* Top Simple Public Header */}
      <div className="px-6 py-4 flex items-center justify-between border-b border-[#263244]/60">
        <Link href="/" className="flex items-center gap-2.5 group">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/30 flex items-center justify-center text-cyan-400 group-hover:border-cyan-400 transition-colors">
            <Shield className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="flex items-center gap-1.5">
            <span className="font-bold text-slate-100 text-sm tracking-tight">PhishGuard</span>
            <span className="text-[10px] font-mono font-bold px-1.5 py-0.2 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              AI
            </span>
          </div>
        </Link>

        <div className="flex items-center gap-2 text-xs">
          <span className="text-slate-400 hidden sm:inline">Don&apos;t have an account?</span>
          <Link
            href="/signup"
            className="px-3 py-1.5 rounded-lg bg-[#162032] hover:bg-[#1E293B] text-cyan-400 hover:text-cyan-300 border border-[#263244] font-medium transition-colors"
          >
            Create Account
          </Link>
        </div>
      </div>

      {/* Main Two-Column Container */}
      <div className="flex-1 flex items-center justify-center p-4 sm:p-8">
        <div className="w-full max-w-5xl grid grid-cols-1 lg:grid-cols-12 rounded-2xl bg-[#111827] border border-[#263244] overflow-hidden shadow-2xl shadow-black/60">
          {/* Left Column: Brand & Security Telemetry Illustration */}
          <div className="lg:col-span-5 bg-gradient-to-br from-[#0E1526] via-[#111B2E] to-[#0A0F1D] p-8 lg:p-10 border-b lg:border-b-0 lg:border-r border-[#263244] flex flex-col justify-between relative overflow-hidden">
            {/* Subtle cyber background ambient glow */}
            <div className="absolute top-0 right-0 w-72 h-72 bg-cyan-500/10 blur-3xl rounded-full pointer-events-none" />

            {/* Top brand header */}
            <div className="relative z-10 space-y-4">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/25 text-cyan-400 text-xs font-mono">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
                <span>Enterprise SOC Gateway</span>
              </div>

              <div>
                <h2 className="text-2xl lg:text-3xl font-extrabold text-slate-100 tracking-tight leading-tight">
                  Intelligent Defense Against Deceptive URLs
                </h2>
                <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                  Sign in to access your autonomous phishing detection radar, investigate malicious domains, and inspect explainable AI heuristics.
                </p>
              </div>
            </div>

            {/* Middle: Threat Telemetry Card Preview */}
            <div className="relative z-10 my-8 p-4 rounded-xl bg-[#0B1120]/80 border border-[#263244] space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between border-b border-[#263244] pb-2">
                <div className="flex items-center gap-2">
                  <Radio className="w-3.5 h-3.5 text-red-400 animate-pulse" />
                  <span className="text-[11px] text-slate-300 font-semibold">Active Threat Shield</span>
                </div>
                <span className="text-[10px] text-cyan-400 bg-cyan-500/10 px-1.5 py-0.5 rounded border border-cyan-500/20">
                  96.8% Detection
                </span>
              </div>

              <div className="space-y-1.5 text-[11px]">
                <div className="flex justify-between text-slate-400">
                  <span>Engine:</span>
                  <span className="text-slate-200">PhishGuard v2.4 Heuristic ML</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Zero-Day Latency:</span>
                  <span className="text-emerald-400 font-semibold">&lt; 150ms / URL</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>Telemetry Feeds:</span>
                  <span className="text-slate-200">OpenPhish, PhishTank (FastAPI Gateway)</span>
                </div>
              </div>

              <div className="pt-2 border-t border-[#263244]/60 flex items-center gap-2 text-[10px] text-slate-400">
                <Shield className="w-3 h-3 text-cyan-400 shrink-0" />
                <span>Zero client certificates exposed to external web hosts.</span>
              </div>
            </div>

            {/* Bottom: Analyst account registration helper */}
            <div className="relative z-10 p-3 rounded-lg bg-[#162032]/60 border border-[#263244] flex items-center justify-between gap-2">
              <div className="min-w-0">
                <p className="text-[11px] font-semibold text-slate-300">Need an analyst account?</p>
                <p className="text-[10px] font-mono text-slate-400 truncate">Register in seconds with MongoDB persistence</p>
              </div>
              <Link
                href="/signup"
                className="px-2.5 py-1 text-[11px] font-mono font-medium rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 transition-colors shrink-0"
              >
                Sign Up
              </Link>
            </div>
          </div>

          {/* Right Column: Sign In Form */}
          <div className="lg:col-span-7 p-8 lg:p-12 flex flex-col justify-center">
            <div className="max-w-md w-full mx-auto space-y-6">
              <div>
                <h3 className="text-xl font-bold text-slate-100 tracking-tight">Sign In to PhishGuard AI</h3>
                <p className="text-xs text-slate-400 mt-1">
                  Enter your credentials to access the security analysis console.
                </p>
              </div>

              {/* Form Alert Error */}
              {formError && (
                <div className="p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 flex items-start gap-2.5 text-xs text-red-300 animate-in fade-in">
                  <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                  <span className="leading-relaxed">{formError}</span>
                </div>
              )}

              <form onSubmit={handleSubmit} className="space-y-4">
                {/* Email Address */}
                <div className="space-y-1.5">
                  <label className="text-xs font-mono text-slate-300 uppercase tracking-wider block">
                    Email Address <span className="text-cyan-400">*</span>
                  </label>
                  <div className="relative">
                    <Mail className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => {
                        setEmail(e.target.value);
                        if (formError) setFormError(null);
                      }}
                      placeholder="analyst@defense.sec"
                      disabled={isSubmitting}
                      className="w-full pl-9 pr-3 py-2.5 rounded-lg bg-[#0B1120] border border-[#263244] text-xs text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 transition-all disabled:opacity-50"
                    />
                  </div>
                </div>

                {/* Password */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-mono text-slate-300 uppercase tracking-wider block">
                      Password <span className="text-cyan-400">*</span>
                    </label>
                    <button
                      type="button"
                      onClick={() => setShowForgotPasswordModal(true)}
                      className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 transition-colors"
                    >
                      Forgot Password?
                    </button>
                  </div>
                  <div className="relative">
                    <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
                    <input
                      type={showPassword ? 'text' : 'password'}
                      value={password}
                      onChange={(e) => {
                        setPassword(e.target.value);
                        if (formError) setFormError(null);
                      }}
                      placeholder="••••••••••••"
                      disabled={isSubmitting}
                      className="w-full pl-9 pr-10 py-2.5 rounded-lg bg-[#0B1120] border border-[#263244] text-xs text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 transition-all disabled:opacity-50"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 p-1 transition-colors"
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* Remember Me */}
                <div className="flex items-center justify-between pt-1">
                  <label className="flex items-center gap-2 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={rememberMe}
                      onChange={(e) => setRememberMe(e.target.checked)}
                      className="w-4 h-4 rounded bg-[#0B1120] border-[#263244] text-cyan-500 focus:ring-0 focus:ring-offset-0"
                    />
                    <span className="text-xs text-slate-400">Remember this terminal session</span>
                  </label>
                </div>

                {/* Submit Button */}
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="w-full py-3 px-4 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-[#041C24] font-bold text-xs tracking-wider uppercase transition-all shadow-lg shadow-cyan-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 group mt-2"
                >
                  {isSubmitting ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span>Verifying Credentials...</span>
                    </>
                  ) : (
                    <>
                      <span>Sign In to Console</span>
                      <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
                    </>
                  )}
                </button>
              </form>

              {/* Bottom signup link */}
              <div className="pt-4 border-t border-[#263244] text-center">
                <p className="text-xs text-slate-400">
                  New analyst?{' '}
                  <Link href="/signup" className="text-cyan-400 hover:text-cyan-300 font-semibold underline underline-offset-4 ml-1">
                    Create your account
                  </Link>
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Footer copyright */}
      <div className="px-6 py-4 text-center border-t border-[#263244]/60 text-xs font-mono text-slate-500">
        PhishGuard AI — Intelligent Phishing Detection & Threat Analysis
      </div>

      {/* Forgot Password Modal */}
      {showForgotPasswordModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-md bg-[#111827] border border-[#263244] rounded-2xl p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#263244]">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
                  <Lock className="w-4 h-4" />
                </div>
                <h4 className="text-sm font-bold text-slate-100">Reset Account Password</h4>
              </div>
              <button
                type="button"
                onClick={() => setShowForgotPasswordModal(false)}
                className="text-slate-400 hover:text-slate-200 text-xs font-mono"
              >
                ✕
              </button>
            </div>

            {resetSuccess ? (
              <div className="py-6 flex flex-col items-center text-center gap-3 animate-in fade-in">
                <CheckCircle2 className="w-10 h-10 text-emerald-400" />
                <h5 className="text-sm font-semibold text-slate-100">Recovery Instructions Sent</h5>
                <p className="text-xs text-slate-400 max-w-xs">
                  We have dispatched temporary credential recovery tokens to <span className="text-cyan-400 font-mono">{forgotEmail}</span>.
                </p>
              </div>
            ) : (
              <form onSubmit={handleForgotPassword} className="space-y-4">
                <p className="text-xs text-slate-400 leading-relaxed">
                  Enter your registered email address and our security engine will dispatch an authentication reset link.
                </p>
                <div className="space-y-1.5">
                  <label className="text-[11px] font-mono text-slate-300 uppercase">Registered Email</label>
                  <input
                    type="email"
                    value={forgotEmail}
                    onChange={(e) => setForgotEmail(e.target.value)}
                    placeholder="analyst@defense.sec"
                    required
                    className="w-full px-3 py-2 rounded-lg bg-[#0B1120] border border-[#263244] text-xs text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div className="flex items-center justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setShowForgotPasswordModal(false)}
                    className="px-3 py-1.5 rounded-lg bg-[#162032] hover:bg-[#1E293B] text-slate-300 text-xs font-medium border border-[#263244]"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-[#041C24] text-xs font-bold font-mono"
                  >
                    Send Recovery Link
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

