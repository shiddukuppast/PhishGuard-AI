'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import {
  Shield,
  ShieldCheck,
  Search,
  Sparkles,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  ShieldAlert,
  Cpu,
  Layers,
  Gauge,
  FileText,
  Radio,
  Lock,
  Unlock,
  ChevronRight,
  Menu,
  X,
  ExternalLink,
  Zap,
  Globe,
  Terminal,
} from 'lucide-react';
import { useAuth } from '@/context/AuthContext';

export default function LandingPage() {
  const { isAuthenticated, user } = useAuth();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  return (
    <div className="min-h-screen bg-[#0B1120] text-slate-100 flex flex-col selection:bg-cyan-500/20 selection:text-cyan-300 font-sans">
      {/* ================================================== */}
      {/* HEADER NAVIGATION                                  */}
      {/* ================================================== */}
      <header className="sticky top-0 z-50 bg-[#0B1120]/80 backdrop-blur-md border-b border-[#263244]">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          {/* Logo & Shield Icon */}
          <Link href="/" className="flex items-center gap-3 group">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/30 flex items-center justify-center text-cyan-400 group-hover:border-cyan-400 transition-colors shadow-sm">
              <Shield className="w-5 h-5 text-cyan-400" />
            </div>
            <div className="flex flex-col">
              <div className="flex items-center gap-1.5">
                <span className="font-extrabold text-slate-100 text-base tracking-tight">PhishGuard</span>
                <span className="text-xs font-mono font-bold px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                  AI
                </span>
              </div>
              <span className="text-[9px] text-slate-500 uppercase tracking-widest font-mono">
                Detect • Analyze • Protect
              </span>
            </div>
          </Link>

          {/* Desktop Navigation Links */}
          <nav className="hidden md:flex items-center gap-8 text-xs font-medium text-slate-300">
            <Link href="/" className="text-cyan-400 hover:text-cyan-300 transition-colors">
              Home
            </Link>
            <a href="#features" className="hover:text-slate-100 transition-colors">
              Features
            </a>
            <a href="#how-it-works" className="hover:text-slate-100 transition-colors">
              How It Works
            </a>
            <a href="#about" className="hover:text-slate-100 transition-colors">
              About
            </a>
          </nav>

          {/* Right Action Buttons */}
          <div className="hidden md:flex items-center gap-3">
            {isAuthenticated ? (
              <Link
                href="/dashboard"
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-[#041C24] font-bold text-xs tracking-wide transition-all shadow-md shadow-cyan-500/20"
              >
                <span>Console Dashboard</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </Link>
            ) : (
              <>
                <Link
                  href="/login"
                  className="px-4 py-2 rounded-lg text-xs font-medium text-slate-300 hover:text-white hover:bg-[#162032] border border-transparent hover:border-[#263244] transition-colors"
                >
                  Sign In
                </Link>
                <Link
                  href="/signup"
                  className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-[#041C24] font-bold text-xs tracking-wide transition-all shadow-md shadow-cyan-500/20"
                >
                  <span>Get Started</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </Link>
              </>
            )}
          </div>

          {/* Mobile menu trigger */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="md:hidden p-2 rounded-lg text-slate-400 hover:text-white hover:bg-[#162032]"
            aria-label="Toggle navigation menu"
          >
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>

        {/* Mobile dropdown drawer */}
        {mobileMenuOpen && (
          <div className="md:hidden border-b border-[#263244] bg-[#0E1526] px-6 py-4 space-y-3">
            <nav className="flex flex-col space-y-2 text-sm text-slate-300">
              <Link
                href="/"
                onClick={() => setMobileMenuOpen(false)}
                className="py-1 text-cyan-400 font-medium"
              >
                Home
              </Link>
              <a
                href="#features"
                onClick={() => setMobileMenuOpen(false)}
                className="py-1 hover:text-slate-100"
              >
                Features
              </a>
              <a
                href="#how-it-works"
                onClick={() => setMobileMenuOpen(false)}
                className="py-1 hover:text-slate-100"
              >
                How It Works
              </a>
              <a
                href="#about"
                onClick={() => setMobileMenuOpen(false)}
                className="py-1 hover:text-slate-100"
              >
                About
              </a>
            </nav>

            <div className="pt-3 border-t border-[#263244] flex flex-col gap-2">
              {isAuthenticated ? (
                <Link
                  href="/dashboard"
                  onClick={() => setMobileMenuOpen(false)}
                  className="w-full py-2.5 rounded-lg bg-cyan-500 text-center text-[#041C24] font-bold text-xs"
                >
                  Open Dashboard
                </Link>
              ) : (
                <>
                  <Link
                    href="/login"
                    onClick={() => setMobileMenuOpen(false)}
                    className="w-full py-2.5 rounded-lg bg-[#162032] text-center text-slate-200 border border-[#263244] text-xs font-medium"
                  >
                    Sign In
                  </Link>
                  <Link
                    href="/signup"
                    onClick={() => setMobileMenuOpen(false)}
                    className="w-full py-2.5 rounded-lg bg-cyan-500 text-center text-[#041C24] font-bold text-xs"
                  >
                    Get Started
                  </Link>
                </>
              )}
            </div>
          </div>
        )}
      </header>

      {/* ================================================== */}
      {/* HERO SECTION                                       */}
      {/* ================================================== */}
      <section className="relative pt-16 pb-20 lg:pt-24 lg:pb-32 overflow-hidden border-b border-[#263244]/60">
        {/* Subtle radial cybersecurity glow backdrop */}
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[450px] bg-gradient-to-tr from-cyan-500/10 via-blue-500/10 to-transparent blur-3xl pointer-events-none rounded-full" />

        <div className="max-w-7xl mx-auto px-6 relative z-10">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-8 items-center">
            {/* Left Column: Heading, Description, CTAs, Trust Badge */}
            <div className="lg:col-span-7 space-y-6 text-center lg:text-left">
              {/* Trust Tag */}
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#111827] border border-[#263244] text-xs font-mono text-cyan-400 shadow-sm">
                <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                <span>Intelligent URL Security Analysis</span>
              </div>

              {/* Main Heading */}
              <h1 className="text-3xl sm:text-4xl lg:text-5xl font-black text-slate-100 tracking-tight leading-[1.15]">
                Stay One Step Ahead of <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-teal-300 to-blue-500">Phishing Attacks.</span>
              </h1>

              {/* Description */}
              <p className="text-sm sm:text-base text-slate-400 leading-relaxed max-w-2xl mx-auto lg:mx-0">
                Protect yourself from malicious websites with intelligent phishing detection, advanced URL analysis and explainable AI-powered security insights.
              </p>

              {/* Primary & Secondary CTAs */}
              <div className="flex flex-col sm:flex-row items-center justify-center lg:justify-start gap-3.5 pt-2">
                <Link
                  href={isAuthenticated ? '/scanner' : '/signup'}
                  className="w-full sm:w-auto px-7 py-3.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-[#041C24] font-bold text-sm tracking-wide transition-all shadow-xl shadow-cyan-500/25 flex items-center justify-center gap-2 group"
                >
                  <Sparkles className="w-4 h-4" />
                  <span>Start Scanning</span>
                  <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                </Link>

                <a
                  href="#features"
                  className="w-full sm:w-auto px-6 py-3.5 rounded-xl bg-[#111827] hover:bg-[#162032] text-slate-200 border border-[#263244] hover:border-[#384961] font-semibold text-sm transition-colors text-center"
                >
                  Explore Features
                </a>
              </div>

              {/* Security Metrics Pills */}
              <div className="pt-6 border-t border-[#263244]/60 grid grid-cols-3 gap-3 max-w-lg mx-auto lg:mx-0 text-left">
                <div>
                  <span className="text-xs font-mono text-slate-500 uppercase">Detection Rate</span>
                  <p className="text-lg font-bold text-slate-100 font-sans">96.8%</p>
                </div>
                <div>
                  <span className="text-xs font-mono text-slate-500 uppercase">Heuristic Layers</span>
                  <p className="text-lg font-bold text-cyan-400 font-sans">6 Engine Checks</p>
                </div>
                <div>
                  <span className="text-xs font-mono text-slate-500 uppercase">Analysis Speed</span>
                  <p className="text-lg font-bold text-emerald-400 font-sans">&lt; 2.5s Scan</p>
                </div>
              </div>
            </div>

            {/* Right Column: Visual Representation of URL Threat Analysis */}
            <div className="lg:col-span-5 relative">
              <div className="relative mx-auto max-w-md bg-[#111827] border border-[#263244] rounded-2xl p-5 shadow-2xl shadow-cyan-950/30 overflow-hidden space-y-4">
                {/* Cyber Scanner Header */}
                <div className="flex items-center justify-between border-b border-[#263244] pb-3">
                  <div className="flex items-center gap-2">
                    <div className="w-2.5 h-2.5 rounded-full bg-red-500" />
                    <div className="w-2.5 h-2.5 rounded-full bg-amber-500" />
                    <div className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                    <span className="text-[11px] font-mono text-slate-400 ml-2">PhishGuard Heuristics Inspector</span>
                  </div>
                  <span className="text-[10px] font-mono text-red-400 bg-red-500/10 px-2 py-0.5 rounded border border-red-500/20">
                    THREAT FLAGGED
                  </span>
                </div>

                {/* Analyzed URL preview */}
                <div className="p-3 rounded-lg bg-[#0B1120] border border-[#263244] space-y-1 font-mono text-xs">
                  <div className="flex items-center justify-between text-[10px] text-slate-500">
                    <span>TARGET DESTINATION</span>
                    <span className="text-red-400 flex items-center gap-1">
                      <Unlock className="w-3 h-3" /> Plaintext HTTP
                    </span>
                  </div>
                  <p className="text-red-300 font-mono text-xs break-all">
                    http://secure-account-verification.example.test
                  </p>
                </div>

                {/* Simulated Risk Score Gauge Mini Card */}
                <div className="grid grid-cols-2 gap-3 items-center p-3 rounded-xl bg-[#0B1120]/60 border border-[#263244]">
                  <div className="text-center p-2 rounded-lg bg-[#111827] border border-red-500/30">
                    <span className="text-[10px] font-mono text-slate-400 uppercase block">Risk Score</span>
                    <span className="text-2xl font-black text-red-400 font-sans">92<span className="text-xs text-slate-500 font-mono">/100</span></span>
                    <span className="text-[9px] font-mono font-bold text-red-400 uppercase block mt-0.5">Critical Risk</span>
                  </div>

                  <div className="space-y-1.5 text-[11px] font-mono">
                    <div className="flex items-center justify-between text-slate-300">
                      <span className="text-slate-500">Classification:</span>
                      <span className="text-red-400 font-semibold">Phishing</span>
                    </div>
                    <div className="flex items-center justify-between text-slate-300">
                      <span className="text-slate-500">Keywords:</span>
                      <span className="text-amber-400 font-semibold">3 Flagged</span>
                    </div>
                    <div className="flex items-center justify-between text-slate-300">
                      <span className="text-slate-500">Latency:</span>
                      <span className="text-cyan-400">142ms</span>
                    </div>
                  </div>
                </div>

                {/* Key Heuristic Indicators Checklist */}
                <div className="space-y-2 pt-1 font-mono text-xs">
                  <div className="flex items-center justify-between p-2 rounded bg-[#0B1120] border border-[#263244]">
                    <div className="flex items-center gap-2">
                      <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                      <span className="text-slate-300 text-[11px]">Domain Typosquatting</span>
                    </div>
                    <span className="text-[10px] text-red-400 font-semibold">Detected</span>
                  </div>

                  <div className="flex items-center justify-between p-2 rounded bg-[#0B1120] border border-[#263244]">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                      <span className="text-slate-300 text-[11px]">Credential Keywords</span>
                    </div>
                    <span className="text-[10px] text-amber-300 font-semibold">Suspicious</span>
                  </div>

                  <div className="flex items-center justify-between p-2 rounded bg-[#0B1120] border border-[#263244]">
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-slate-300 text-[11px]">Numeric IP Masquerading</span>
                    </div>
                    <span className="text-[10px] text-emerald-400 font-semibold">Clean</span>
                  </div>
                </div>

                {/* Live simulation banner */}
                <div className="pt-2 border-t border-[#263244] flex items-center justify-between text-[10px] font-mono text-slate-500">
                  <span>Engine: Heuristics v2.4</span>
                  <span className="text-cyan-400 flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                    Live Heuristic Radar
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ================================================== */}
      {/* FEATURES SECTION                                   */}
      {/* ================================================== */}
      <section id="features" className="py-20 lg:py-28 max-w-7xl mx-auto px-6 scroll-mt-16">
        <div className="text-center space-y-3 mb-16">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/25 text-cyan-400 text-xs font-mono">
            <span>Core Capabilities</span>
          </div>
          <h2 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-slate-100 tracking-tight">
            Advanced Protection. Intelligent Detection.
          </h2>
          <p className="text-xs sm:text-sm text-slate-400 max-w-2xl mx-auto">
            Comprehensive heuristic, machine learning, and threat intelligence components engineered to neutralize sophisticated phishing vectors.
          </p>
        </div>

        {/* 6 Feature Cards using Lucide Icons */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* Feature 1 */}
          <div className="p-6 rounded-2xl bg-[#111827] border border-[#263244] hover:border-[#384961] transition-all space-y-3 group">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/25 flex items-center justify-center text-cyan-400 group-hover:scale-105 transition-transform">
              <Cpu className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-slate-100">AI-Powered Detection</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Identify potentially malicious URLs using machine learning.
            </p>
          </div>

          {/* Feature 2 */}
          <div className="p-6 rounded-2xl bg-[#111827] border border-[#263244] hover:border-[#384961] transition-all space-y-3 group">
            <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/25 flex items-center justify-center text-blue-400 group-hover:scale-105 transition-transform">
              <Layers className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-slate-100">Intelligent URL Analysis</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Analyze URL structure, suspicious keywords and domain characteristics.
            </p>
          </div>

          {/* Feature 3 */}
          <div className="p-6 rounded-2xl bg-[#111827] border border-[#263244] hover:border-[#384961] transition-all space-y-3 group">
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/25 flex items-center justify-center text-amber-400 group-hover:scale-105 transition-transform">
              <Gauge className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-slate-100">Risk Assessment</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Understand potential threats through an intuitive risk score.
            </p>
          </div>

          {/* Feature 4 */}
          <div className="p-6 rounded-2xl bg-[#111827] border border-[#263244] hover:border-[#384961] transition-all space-y-3 group">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/25 flex items-center justify-center text-emerald-400 group-hover:scale-105 transition-transform">
              <Sparkles className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-slate-100">Explainable AI</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Understand why a URL has been classified as suspicious.
            </p>
          </div>

          {/* Feature 5 */}
          <div className="p-6 rounded-2xl bg-[#111827] border border-[#263244] hover:border-[#384961] transition-all space-y-3 group">
            <div className="w-10 h-10 rounded-xl bg-red-500/10 border border-red-500/25 flex items-center justify-center text-red-400 group-hover:scale-105 transition-transform">
              <Radio className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-slate-100">Threat Intelligence</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Compare URLs against known threat intelligence sources when available.
            </p>
          </div>

          {/* Feature 6 */}
          <div className="p-6 rounded-2xl bg-[#111827] border border-[#263244] hover:border-[#384961] transition-all space-y-3 group">
            <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/25 flex items-center justify-center text-purple-400 group-hover:scale-105 transition-transform">
              <FileText className="w-5 h-5" />
            </div>
            <h3 className="text-base font-semibold text-slate-100">Security Reports</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Generate detailed reports containing analysis results and recommendations.
            </p>
          </div>
        </div>
      </section>

      {/* ================================================== */}
      {/* HOW IT WORKS SECTION                               */}
      {/* ================================================== */}
      <section id="how-it-works" className="py-20 bg-[#0E1526]/60 border-y border-[#263244]/60 scroll-mt-16">
        <div className="max-w-7xl mx-auto px-6">
          <div className="text-center space-y-3 mb-16">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/25 text-cyan-400 text-xs font-mono">
              <span>Three-Step Workflow</span>
            </div>
            <h2 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-slate-100 tracking-tight">
              How PhishGuard AI Protects You
            </h2>
            <p className="text-xs sm:text-sm text-slate-400 max-w-xl mx-auto">
              A frictionless process designed to evaluate suspicious links before you risk credential compromise.
            </p>
          </div>

          {/* Horizontal layout on desktop, vertical on mobile */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 relative">
            {/* Step 1 */}
            <div className="p-6 rounded-2xl bg-[#111827] border border-[#263244] relative space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-500/10 px-2.5 py-1 rounded border border-cyan-500/20">
                  STEP 01
                </span>
                <Search className="w-4 h-4 text-slate-500" />
              </div>
              <h3 className="text-base font-bold text-slate-100 pt-2">Enter URL</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Paste the URL you want to analyze.
              </p>
            </div>

            {/* Step 2 */}
            <div className="p-6 rounded-2xl bg-[#111827] border border-[#263244] relative space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-blue-400 bg-blue-500/10 px-2.5 py-1 rounded border border-blue-500/20">
                  STEP 02
                </span>
                <Cpu className="w-4 h-4 text-slate-500" />
              </div>
              <h3 className="text-base font-bold text-slate-100 pt-2">Intelligent Analysis</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                The system evaluates URL characteristics and applies ML-based detection.
              </p>
            </div>

            {/* Step 3 */}
            <div className="p-6 rounded-2xl bg-[#111827] border border-[#263244] relative space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded border border-emerald-500/20">
                  STEP 03
                </span>
                <ShieldCheck className="w-4 h-4 text-slate-500" />
              </div>
              <h3 className="text-base font-bold text-slate-100 pt-2">Get Security Insights</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                View the risk score, detected indicators and recommended actions.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ================================================== */}
      {/* CALL TO ACTION SECTION                             */}
      {/* ================================================== */}
      <section className="py-20 lg:py-28 max-w-7xl mx-auto px-6 w-full">
        <div className="rounded-3xl bg-gradient-to-br from-[#111827] via-[#142033] to-[#111827] border border-[#263244] p-8 lg:p-16 text-center space-y-6 relative overflow-hidden shadow-2xl">
          <div className="absolute inset-0 bg-cyan-500/5 blur-3xl pointer-events-none" />

          <div className="relative z-10 max-w-2xl mx-auto space-y-4">
            <h2 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold text-slate-100 tracking-tight leading-tight">
              Don&apos;t Let Phishing Catch You Off Guard.
            </h2>
            <p className="text-xs sm:text-sm text-slate-400 leading-relaxed">
              Take control of your online security with intelligent phishing detection.
            </p>

            <div className="pt-4">
              <Link
                href={isAuthenticated ? '/dashboard' : '/signup'}
                className="inline-flex items-center gap-2 px-8 py-4 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-[#041C24] font-bold text-sm tracking-wide transition-all shadow-xl shadow-cyan-500/25"
              >
                <span>Get Started – It&apos;s Free</span>
                <ArrowRight className="w-4 h-4" />
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* ================================================== */}
      {/* ABOUT / TRANSPARENCY SECTION                       */}
      {/* ================================================== */}
      <section id="about" className="py-16 border-t border-[#263244]/60 bg-[#0B1120] scroll-mt-16">
        <div className="max-w-7xl mx-auto px-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 items-center">
            <div className="space-y-3">
              <h3 className="text-lg font-bold text-slate-100">About PhishGuard AI</h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                PhishGuard AI was conceived as an intelligent digital defense platform designed to make advanced cybersecurity heuristics transparent and accessible. By analyzing lexical characteristics, domain structure, protocol integrity, and known abuse databases, PhishGuard AI bridges the gap between complex SOC telemetry and actionable user guidance.
              </p>
            </div>
            <div className="p-5 rounded-xl bg-[#111827] border border-[#263244] space-y-2 text-xs font-mono text-slate-400">
              <div className="flex items-center gap-2 text-cyan-400 font-semibold">
                <Terminal className="w-4 h-4" />
                <span>Modern Cybersecurity Engineering</span>
              </div>
              <p className="text-[11px] leading-relaxed text-slate-400">
                Architected with Next.js App Router, Tailwind CSS, and Recharts, with native schema compatibility for upcoming Python FastAPI backend endpoints and MongoDB persistence.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ================================================== */}
      {/* FOOTER                                             */}
      {/* ================================================== */}
      <footer className="border-t border-[#263244] bg-[#0E1526] py-12 text-slate-400">
        <div className="max-w-7xl mx-auto px-6 space-y-8">
          <div className="grid grid-cols-1 md:grid-cols-12 gap-8">
            {/* Brand column */}
            <div className="md:col-span-5 space-y-3">
              <div className="flex items-center gap-2.5">
                <div className="w-7 h-7 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
                  <Shield className="w-4 h-4 text-cyan-400" />
                </div>
                <span className="font-bold text-slate-100 text-sm tracking-tight">PhishGuard AI</span>
              </div>
              <p className="text-xs text-slate-400 max-w-sm leading-relaxed">
                Autonomous threat detection platform that analyzes URLs, detects suspicious characteristics, assigns risk scores, and provides explainable security recommendations.
              </p>
              <p className="text-[11px] font-mono text-cyan-400">
                Built with a focus on smarter digital security.
              </p>
            </div>

            {/* Navigation Links */}
            <div className="md:col-span-3 space-y-2">
              <p className="text-xs font-mono uppercase tracking-wider text-slate-200 font-semibold">
                Platform
              </p>
              <ul className="space-y-1.5 text-xs">
                <li>
                  <a href="#features" className="hover:text-cyan-400 transition-colors">
                    Features
                  </a>
                </li>
                <li>
                  <a href="#how-it-works" className="hover:text-cyan-400 transition-colors">
                    How It Works
                  </a>
                </li>
                <li>
                  <a href="#about" className="hover:text-cyan-400 transition-colors">
                    About
                  </a>
                </li>
                <li>
                  <Link href="/scanner" className="hover:text-cyan-400 transition-colors">
                    Live URL Scanner
                  </Link>
                </li>
              </ul>
            </div>

            {/* Legal / Contact */}
            <div className="md:col-span-4 space-y-2">
              <p className="text-xs font-mono uppercase tracking-wider text-slate-200 font-semibold">
                Governance & Security
              </p>
              <ul className="space-y-1.5 text-xs">
                <li>
                  <span className="hover:text-slate-200 cursor-pointer">Privacy Policy</span>
                </li>
                <li>
                  <span className="hover:text-slate-200 cursor-pointer">Terms of Service</span>
                </li>
                <li>
                  <span className="hover:text-slate-200 cursor-pointer">Contact Security Operations</span>
                </li>
                <li>
                  <span className="text-[11px] text-slate-500 font-mono">
                    Responsible Disclosure & Heuristic Research
                  </span>
                </li>
              </ul>
            </div>
          </div>

          <div className="pt-8 border-t border-[#263244]/60 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs font-mono text-slate-500">
            <p>© {new Date().getFullYear()} PhishGuard AI. All rights reserved.</p>
            <p>Detect. Analyze. Protect.</p>
          </div>
        </div>
      </footer>
    </div>
  );
}
