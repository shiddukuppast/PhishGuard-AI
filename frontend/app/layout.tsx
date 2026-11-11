import type { Metadata } from 'next';
import './globals.css';
import { Sidebar } from '@/components/layout/Sidebar';
import { ToastProvider } from '@/components/shared/ToastContext';

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
        <ToastProvider>
          <div className="flex min-h-screen w-full">
            {/* Persistent Sidebar */}
            <Sidebar />

            {/* Main Content Area */}
            <div className="flex-1 flex flex-col min-w-0 bg-[#0B1120]">
              <main className="flex-1 pb-12">
                {children}
              </main>
            </div>
          </div>
        </ToastProvider>
      </body>
    </html>
  );
}
