'use client';

import React, { useState, useMemo } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import {
  Shield,
  Eye,
  EyeOff,
  Lock,
  Mail,
  User as UserIcon,
  ArrowRight,
  Loader2,
  CheckCircle2,
  AlertCircle,
  ShieldCheck,
  Check,
  Sparkles,
} from 'lucide-react';
import { useAuth } from '@/context/AuthContext';
import { useToast } from '@/components/shared/ToastContext';

export default function SignupPage() {
  const router = useRouter();
  const { register } = useAuth();
  const { success, error: toastError } = useToast();

  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [termsAccepted, setTermsAccepted] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Email format validation
  const validateEmail = (val: string) => {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val.trim());
  };

  // Password strength calculation
  const passwordStrength = useMemo(() => {
    if (!password) return { score: 0, label: 'None', color: 'bg-slate-700' };

    let score = 0;
    if (password.length >= 8) score += 1;
    if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score += 1;
    if (/[0-9]/.test(password)) score += 1;
    if (/[^A-Za-z0-9]/.test(password)) score += 1;

    switch (score) {
      case 1:
        return { score: 1, label: 'Weak', color: 'bg-red-500', textColor: 'text-red-400' };
      case 2:
        return { score: 2, label: 'Fair', color: 'bg-amber-500', textColor: 'text-amber-400' };
      case 3:
        return { score: 3, label: 'Good', color: 'bg-blue-500', textColor: 'text-blue-400' };
      case 4:
        return { score: 4, label: 'Strong', color: 'bg-emerald-500', textColor: 'text-emerald-400' };
      default:
        return { score: 0, label: 'Too Short', color: 'bg-red-500', textColor: 'text-red-400' };
    }
  }, [password]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    // Validation
    if (!name.trim()) {
      setFormError('Please enter your full name.');
      return;
    }
    if (!email.trim()) {
      setFormError('Please enter your email address.');
      return;
    }
    if (!validateEmail(email)) {
      setFormError('Please enter a valid work or personal email address.');
      return;
    }
    if (password.length < 8) {
      setFormError('Password must contain at least 8 characters.');
      return;
    }
    if (password !== confirmPassword) {
      setFormError('Password confirmation does not match.');
      return;
    }
    if (!termsAccepted) {
      setFormError('You must agree to the PhishGuard AI Terms and Privacy Policy to continue.');
      return;
    }

    setIsSubmitting(true);
    try {
      const res = await register({
        name,
        email,
        password,
        termsAccepted,
      });

      if (res.success) {
        success('Account Created', 'Welcome to PhishGuard AI. Directing to your security dashboard.');
        router.push('/dashboard');
      } else {
        setFormError(res.message || 'Registration failed. Please review your information.');
        toastError('Registration Failed', res.message);
      }
    } catch {
      setFormError('An unexpected network error occurred while provisioning your account.');
    } finally {
      setIsSubmitting(false);
    }
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
          <span className="text-slate-400 hidden sm:inline">Already registered?</span>
          <Link
            href="/login"
            className="px-3 py-1.5 rounded-lg bg-[#162032] hover:bg-[#1E293B] text-cyan-400 hover:text-cyan-300 border border-[#263244] font-medium transition-colors"
          >
            Sign In
          </Link>
        </div>
      </div>

      {/* Main Two-Column Container */}
      <div className="flex-1 flex items-center justify-center p-4 sm:p-8">
        <div className="w-full max-w-5xl grid grid-cols-1 lg:grid-cols-12 rounded-2xl bg-[#111827] border border-[#263244] overflow-hidden shadow-2xl shadow-black/60">
          {/* Left Column: Benefits & Security Commitments */}
          <div className="lg:col-span-5 bg-gradient-to-br from-[#0E1526] via-[#111B2E] to-[#0A0F1D] p-8 lg:p-10 border-b lg:border-b-0 lg:border-r border-[#263244] flex flex-col justify-between relative overflow-hidden">
            <div className="absolute top-0 right-0 w-72 h-72 bg-cyan-500/10 blur-3xl rounded-full pointer-events-none" />

            {/* Top brand header */}
            <div className="relative z-10 space-y-4">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/25 text-cyan-400 text-xs font-mono">
                <Sparkles className="w-3.5 h-3.5" />
                <span>Instant Analyst Onboarding</span>
              </div>

              <div>
                <h2 className="text-2xl lg:text-3xl font-extrabold text-slate-100 tracking-tight leading-tight">
                  Join the Frontline of Autonomous URL Defense
                </h2>
                <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                  Provision your analyst workspace to inspect suspicious web hosts, export SOC incident dossiers, and monitor live phishing telemetry.
                </p>
              </div>
            </div>

            {/* Middle: Feature highlights */}
            <div className="relative z-10 my-6 space-y-3 font-mono text-xs">
              <div className="flex items-start gap-3 p-3 rounded-lg bg-[#0B1120]/80 border border-[#263244]">
                <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                <div>
                  <p className="text-xs font-semibold text-slate-200">Explainable AI Classifications</p>
                  <p className="text-[11px] text-slate-400 mt-0.5 leading-normal">
                    Receive transparent reasoning on token structures, typosquatting, and heuristic weights.
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-3 p-3 rounded-lg bg-[#0B1120]/80 border border-[#263244]">
                <Check className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <div>
                  <p className="text-xs font-semibold text-slate-200">Local Telemetry Persistence</p>
                  <p className="text-[11px] text-slate-400 mt-0.5 leading-normal">
                    Audit logs, report histories, and scanner telemetry persist across sessions.
                  </p>
                </div>
              </div>

              <div className="flex items-start gap-3 p-3 rounded-lg bg-[#0B1120]/80 border border-[#263244]">
                <Check className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                <div>
                  <p className="text-xs font-semibold text-slate-200">FastAPI ML Ready Architecture</p>
                  <p className="text-[11px] text-slate-400 mt-0.5 leading-normal">
                    Seamless bridge to upcoming Python machine learning prediction endpoints.
                  </p>
                </div>
              </div>
            </div>

            {/* Bottom: Security Notice */}
            <div className="relative z-10 text-[11px] text-slate-500 font-mono flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
              <span>Zero-knowledge client-side credential tokenization.</span>
            </div>
          </div>

          {/* Right Column: Sign Up Form */}
          <div className="lg:col-span-7 p-8 lg:p-12 flex flex-col justify-center">
            <div className="max-w-md w-full mx-auto space-y-6">
              <div>
                <h3 className="text-xl font-bold text-slate-100 tracking-tight">Create Analyst Account</h3>
                <p className="text-xs text-slate-400 mt-1">
                  Get started with free intelligent phishing analysis and threat intelligence.
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
                {/* Full Name */}
                <div className="space-y-1.5">
                  <label className="text-xs font-mono text-slate-300 uppercase tracking-wider block">
                    Full Name <span className="text-cyan-400">*</span>
                  </label>
                  <div className="relative">
                    <UserIcon className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
                    <input
                      type="text"
                      value={name}
                      onChange={(e) => {
                        setName(e.target.value);
                        if (formError) setFormError(null);
                      }}
                      placeholder="Jane Doe"
                      disabled={isSubmitting}
                      className="w-full pl-9 pr-3 py-2.5 rounded-lg bg-[#0B1120] border border-[#263244] text-xs text-slate-100 placeholder-slate-500 font-sans focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 transition-all disabled:opacity-50"
                    />
                  </div>
                </div>

                {/* Email Address */}
                <div className="space-y-1.5">
                  <label className="text-xs font-mono text-slate-300 uppercase tracking-wider block">
                    Work or Personal Email <span className="text-cyan-400">*</span>
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
                      placeholder="jane.doe@organization.sec"
                      disabled={isSubmitting}
                      className="w-full pl-9 pr-3 py-2.5 rounded-lg bg-[#0B1120] border border-[#263244] text-xs text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 transition-all disabled:opacity-50"
                    />
                  </div>
                </div>

                {/* Password */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <label className="text-xs font-mono text-slate-300 uppercase tracking-wider block">
                      Password (min. 8 chars) <span className="text-cyan-400">*</span>
                    </label>
                    {password && (
                      <span className={`text-[10px] font-mono font-bold ${passwordStrength.textColor}`}>
                        Strength: {passwordStrength.label}
                      </span>
                    )}
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

                  {/* Password Strength Progress Bar */}
                  {password && (
                    <div className="w-full h-1 bg-[#0B1120] rounded-full overflow-hidden mt-1 flex gap-1">
                      {[1, 2, 3, 4].map((step) => (
                        <div
                          key={step}
                          className={`flex-1 h-full rounded-full transition-all duration-300 ${
                            step <= passwordStrength.score ? passwordStrength.color : 'bg-slate-800'
                          }`}
                        />
                      ))}
                    </div>
                  )}
                </div>

                {/* Confirm Password */}
                <div className="space-y-1.5">
                  <label className="text-xs font-mono text-slate-300 uppercase tracking-wider block">
                    Confirm Password <span className="text-cyan-400">*</span>
                  </label>
                  <div className="relative">
                    <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500 pointer-events-none" />
                    <input
                      type={showConfirmPassword ? 'text' : 'password'}
                      value={confirmPassword}
                      onChange={(e) => {
                        setConfirmPassword(e.target.value);
                        if (formError) setFormError(null);
                      }}
                      placeholder="••••••••••••"
                      disabled={isSubmitting}
                      className="w-full pl-9 pr-10 py-2.5 rounded-lg bg-[#0B1120] border border-[#263244] text-xs text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 transition-all disabled:opacity-50"
                    />
                    <button
                      type="button"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 p-1 transition-colors"
                      aria-label={showConfirmPassword ? 'Hide password' : 'Show password'}
                    >
                      {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* Terms and Conditions Checkbox */}
                <div className="pt-1">
                  <label className="flex items-start gap-2.5 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={termsAccepted}
                      onChange={(e) => {
                        setTermsAccepted(e.target.checked);
                        if (formError) setFormError(null);
                      }}
                      className="w-4 h-4 mt-0.5 rounded bg-[#0B1120] border-[#263244] text-cyan-500 focus:ring-0 focus:ring-offset-0 shrink-0"
                    />
                    <span className="text-xs text-slate-400 leading-normal">
                      I accept the{' '}
                      <span className="text-cyan-400 hover:underline">Terms of Service</span> and acknowledge that URL analysis telemetry conforms to responsible digital security research.
                    </span>
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
                      <span>Creating Analyst Account...</span>
                    </>
                  ) : (
                    <>
                      <span>Complete Registration</span>
                      <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
                    </>
                  )}
                </button>
              </form>

              {/* Bottom signin link */}
              <div className="pt-4 border-t border-[#263244] text-center">
                <p className="text-xs text-slate-400">
                  Already have an account?{' '}
                  <Link href="/login" className="text-cyan-400 hover:text-cyan-300 font-semibold underline underline-offset-4 ml-1">
                    Sign in to console
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
    </div>
  );
}

