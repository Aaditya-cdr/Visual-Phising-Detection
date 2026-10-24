/**
 * Finding item component displaying severity, title, concise description, and observed evidence.
 */

import React from 'react';
import { AlertCircle, AlertTriangle, Info } from 'lucide-react';
import { Finding } from '../lib/analysis/types.ts';

interface FindingItemProps {
  finding: Finding;
}

export const FindingItem: React.FC<FindingItemProps> = ({ finding }) => {
  const getSeverityBadge = (severity: Finding['severity']) => {
    switch (severity) {
      case 'high':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-bold px-2 py-0.5 rounded-md bg-red-950/90 text-red-300 border border-red-700/60 font-mono uppercase tracking-wide shrink-0">
            <AlertCircle className="w-3 h-3 text-red-400" />
            High Severity
          </span>
        );
      case 'medium':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-bold px-2 py-0.5 rounded-md bg-amber-950/90 text-amber-300 border border-amber-700/60 font-mono uppercase tracking-wide shrink-0">
            <AlertTriangle className="w-3 h-3 text-amber-400" />
            Medium Severity
          </span>
        );
      case 'low':
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-bold px-2 py-0.5 rounded-md bg-sky-950/90 text-sky-300 border border-sky-700/60 font-mono uppercase tracking-wide shrink-0">
            <Info className="w-3 h-3 text-sky-400" />
            Low Severity
          </span>
        );
      case 'info':
      default:
        return (
          <span className="inline-flex items-center gap-1 text-[11px] font-bold px-2 py-0.5 rounded-md bg-slate-800 text-slate-300 border border-slate-700 font-mono uppercase tracking-wide shrink-0">
            Info
          </span>
        );
    }
  };

  return (
    <div className="p-4 border border-slate-800/90 bg-slate-900/50 rounded-xl space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h4 className="text-sm font-semibold text-slate-100">{finding.title}</h4>
        {getSeverityBadge(finding.severity)}
      </div>

      <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">{finding.description}</p>

      {finding.evidence && (
        <div className="pt-1 flex flex-wrap items-baseline gap-1.5 text-xs">
          <span className="text-slate-400 font-medium shrink-0">Evidence:</span>
          <code className="px-2 py-0.5 rounded bg-slate-950 border border-slate-800 font-mono text-sky-300 break-all">
            {finding.evidence}
          </code>
        </div>
      )}
    </div>
  );
};
