import type { Metadata } from 'next';
import './globals.css';
import { ToastProvider } from '@/components/shared/ToastContext';
import { AuthProvider } from '@/context/AuthContext';
import { AppShell } from '@/components/layout/AppShell';

export const metadata: Metadata = {
  title: 'PhishGuard AI — Detect. Analyze. Protect.',
  description: 'AI-powered phishing detection platform providing real-time URL risk analysis, domain heuristics, and actionable cybersecurity threat intelligence.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#0B1120] text-slate-100 min-h-screen antialiased selection:bg-cyan-500/20 selection:text-cyan-300 font-sans">
        <AuthProvider>
          <ToastProvider>
            <AppShell>{children}</AppShell>
          </ToastProvider>
        </AuthProvider>
      </body>
    </html>
  );
}
