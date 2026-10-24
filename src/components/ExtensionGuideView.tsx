/**
 * Chrome Browser Extension Developer-Mode Installation Guide
 */

import React from 'react';
import { AnalysisResult } from '../lib/analysis/types.ts';

interface ExtensionGuideViewProps {
  onBack: () => void;
  onSimulatePageInspection: (result: AnalysisResult) => void;
}

export const ExtensionGuideView: React.FC<ExtensionGuideViewProps> = () => {
  return (
    <div className="w-full max-w-4xl mx-auto space-y-8 py-4 animate-in fade-in duration-300">
      <div>
        <h2 className="text-2xl font-bold text-slate-100">
          PhishLens Active Tab Browser Extension
        </h2>
        <p className="text-sm text-slate-400 mt-1 max-w-2xl">
          Inspects active webpage DOM signals on explicit user activation. Evaluates login forms, external submission
          targets, and brand text consistency using least-privilege permissions.
        </p>
      </div>
    </div>
  );
};
