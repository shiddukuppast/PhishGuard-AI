'use client';

import React, { useEffect } from 'react';
import { usePathname, useRouter } from 'next/navigation';
import { useAuth } from '@/context/AuthContext';
import { Sidebar } from '@/components/layout/Sidebar';
import { Shield, Loader2 } from 'lucide-react';

const PUBLIC_ROUTES = ['/', '/login', '/signup'];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { isAuthenticated, isLoading } = useAuth();

  const isPublicRoute = PUBLIC_ROUTES.includes(pathname);

  // Route protection effects
  useEffect(() => {
    if (isLoading) return;

    // 1. If user is unauthenticated and visits a protected route -> redirect to /login
    if (!isAuthenticated && !isPublicRoute) {
      router.replace('/login');
    }

    // 2. If user is already authenticated and visits /login or /signup -> redirect to /dashboard
    if (isAuthenticated && (pathname === '/login' || pathname === '/signup')) {
      router.replace('/dashboard');
    }
  }, [isAuthenticated, isLoading, pathname, isPublicRoute, router]);

  // Loading screen for protected routes while verifying session
  if (isLoading && !isPublicRoute) {
    return (
      <div className="min-h-screen w-full bg-[#0B1120] flex flex-col items-center justify-center p-4">
        <div className="flex flex-col items-center gap-4 animate-in fade-in duration-300">
          <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-xl shadow-cyan-500/10 relative">
            <Shield className="w-6 h-6 text-cyan-400 animate-pulse" />
            <div className="absolute inset-0 rounded-xl border border-cyan-400/20 animate-ping" />
          </div>
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
            <span>Verifying Security Clearance...</span>
          </div>
        </div>
      </div>
    );
  }

  // Prevent flash of protected content if not authenticated
  if (!isAuthenticated && !isPublicRoute) {
    return null;
  }

  // Public pages (Landing, Login, Signup) render without sidebar
  if (isPublicRoute) {
    return <main className="min-h-screen w-full bg-[#0B1120]">{children}</main>;
  }

  // Protected application layout with persistent sidebar
  return (
    <div className="flex min-h-screen w-full bg-[#0B1120]">
      {/* Persistent Sidebar */}
      <Sidebar />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 bg-[#0B1120]">
        <main className="flex-1 pb-12">{children}</main>
      </div>
    </div>
  );
}

