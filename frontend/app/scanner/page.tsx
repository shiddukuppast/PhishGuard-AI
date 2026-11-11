'use client';

import React from 'react';
import { Header } from '@/components/layout/Header';
import { URLScanner } from '@/components/scanner/URLScanner';

export default function ScannerPage() {
  return (
    <div className="flex flex-col min-h-screen">
      <Header
        title="URL Security Scanner"
        subtitle="Analyze suspicious URLs and identify potential phishing threats using intelligent security analysis."
      />

      <div className="p-6 lg:p-8">
        <URLScanner />
      </div>
    </div>
  );
}

