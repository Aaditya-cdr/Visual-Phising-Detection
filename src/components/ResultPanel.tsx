/**
 * Structured Results Panel
 * Displays:
 * 1. Risk status (Suspicious, Needs Review, No Evidence Found, or Not Analysed) & one concise summary
 * 2. One recommended next action
 * 3. Short list of actual findings with severity
 * 4. Checks completed and unavailable
 * 5. Button to return to a new inspection
 */

import React from 'react';
import {
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  AlertCircle,
  CheckCircle2,
  HelpCircle,
  ArrowRight,
  Check,
  RotateCcw,
} from 'lucide-react';
import { AnalysisResult } from '../lib/analysis/types.ts';
import { FindingItem } from './FindingItem.tsx';

interface ResultPanelProps {
  result: AnalysisResult;
  sourceMode?: 'api' | 'local-fallback';
  onReset: () => void;
}

export const ResultPanel: React.FC<ResultPanelProps> = ({
  result,
  sourceMode = 'api',
  onReset,
}) => {
  const getStatusConfig = (category: AnalysisResult['riskCategory']) => {
    switch (category) {
      case 'SUSPICIOUS':
        return {
          label: 'Suspicious',
          headline: 'Phishing Warning Signs Detected',
          icon: ShieldAlert,
          containerClass: 'border-red-500/40 bg-red-950/20',
          badgeClass: 'bg-red-500/20 text-red-300 border-red-500/40',
          accentColor: 'text-red-400',
        };
      case 'NEEDS_REVIEW':
        return {
          label: 'Needs Review',
          headline: 'Anomalies Identified — Verify Independently',
          icon: AlertTriangle,
          containerClass: 'border-amber-500/40 bg-amber-950/20',
          badgeClass: 'bg-amber-500/20 text-amber-300 border-amber-500/40',
          accentColor: 'text-amber-400',
        };
      case 'NO_EVIDENCE_FOUND':
        return {
          label: 'No Evidence Found',
          headline: 'Standard Heuristic Checks Passed',
          icon: ShieldCheck,
          containerClass: 'border-emerald-500/40 bg-emerald-950/20',
          badgeClass: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40',
          accentColor: 'text-emerald-400',
        };
      case 'NOT_ANALYSED':
      default:
        return {
          label: 'Not Analysed',
          headline: 'Invalid or Unsupported Input',
          icon: AlertCircle,
          containerClass: 'border-slate-700 bg-slate-900/60',
          badgeClass: 'bg-slate-800 text-slate-300 border-slate-700',
          accentColor: 'text-slate-400',
        };
    }
  };

  const statusConfig = getStatusConfig(result.riskCategory);
  const StatusIcon = statusConfig.icon;

  return (
    <section
      aria-label="Inspection Results"
      className="w-full bg-slate-950/70 border border-slate-800/80 rounded-2xl p-5 sm:p-6 shadow-xl space-y-6 animate-in fade-in duration-300"
    >
      {/* Fallback / Demo Banner if Backend API was unreachable */}
      {sourceMode === 'local-fallback' && (
        <div
          role="status"
          className="p-3 rounded-xl bg-amber-950/40 border border-amber-700/50 text-amber-200 text-xs flex items-center gap-2"
        >
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
          <span>
            <strong>Offline Local Demo Mode:</strong> Backend API was unreachable. Showing client-side heuristic demonstration results only.
          </span>
        </div>
      )}

      {/* 1. Risk Status & Concise Summary */}
      <div className={`p-5 rounded-xl border ${statusConfig.containerClass}`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
          <div className="flex items-start sm:items-center gap-3">
            <div className="p-2.5 rounded-xl bg-slate-950/80 border border-slate-800 shrink-0">
              <StatusIcon className={`w-6 h-6 ${statusConfig.accentColor}`} />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs uppercase tracking-wider text-slate-400 font-medium">
                  Risk Status:
                </span>
                <span
                  className={`text-xs font-bold px-2.5 py-0.5 rounded-md border ${statusConfig.badgeClass}`}
                >
                  {statusConfig.label}
                </span>
                {result.status === 'partial' && (
                  <span className="text-[11px] text-amber-300/90 bg-amber-950/60 border border-amber-800/50 px-2 py-0.5 rounded font-mono">
                    Partial Analysis
                  </span>
                )}
              </div>
              <h2 className="text-base sm:text-lg font-bold text-white mt-1">
                {statusConfig.headline}
              </h2>
            </div>
          </div>

          <div className="text-xs text-slate-400 font-mono truncate max-w-xs sm:text-right">
            Target: <span className="text-sky-300">{result.targetSummary}</span>
          </div>
        </div>

        {/* One concise summary */}
        <p className="mt-3.5 text-sm text-slate-200 leading-relaxed">
          {result.summary}
        </p>
      </div>

      {/* 2. One Recommended Next Action */}
      <div className="p-4 rounded-xl border border-sky-800/50 bg-sky-950/20 flex items-start gap-3">
        <ArrowRight className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
        <div className="space-y-0.5">
          <h3 className="text-xs font-bold uppercase tracking-wider text-sky-300">
            Recommended Next Action
          </h3>
          <p className="text-sm text-slate-100 font-medium leading-relaxed">
            {result.recommendedNextStep}
          </p>
        </div>
      </div>

      {/* 3. Short List of Actual Findings with Severity */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">
            Findings ({result.findings.length})
          </h3>
          <span className="text-xs text-slate-500">
            Explainable rule triggers
          </span>
        </div>

        {result.findings.length > 0 ? (
          <div className="space-y-2.5">
            {result.findings.map((finding, idx) => (
              <FindingItem key={`${finding.code}-${idx}`} finding={finding} />
            ))}
          </div>
        ) : (
          <div className="p-5 rounded-xl border border-slate-800/90 bg-slate-900/40 flex items-center gap-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            <p className="text-xs sm:text-sm text-slate-300">
              No heuristic phishing indicators were triggered in the inspected input. Remember that passing structural checks does not guarantee a sender or website is legitimate.
            </p>
          </div>
        )}
      </div>

      {/* 4. Checks Completed and Unavailable */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="p-4 rounded-xl border border-slate-800/80 bg-slate-900/40 text-xs space-y-2">
          <h3 className="font-bold uppercase tracking-wider text-slate-300">
            Checks Completed ({result.checksPerformed.length})
          </h3>
          <ul className="space-y-1.5 text-slate-300">
            {result.checksPerformed.map((check, i) => (
              <li key={i} className="flex items-start gap-2">
                <Check className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                <span>{check}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="p-4 rounded-xl border border-slate-800/80 bg-slate-900/40 text-xs space-y-2">
          <h3 className="font-bold uppercase tracking-wider text-slate-300">
            Checks Unavailable ({result.uncompletedChecks.length})
          </h3>
          {result.uncompletedChecks.length > 0 ? (
            <ul className="space-y-1.5 text-slate-400">
              {result.uncompletedChecks.map((uncheck, i) => (
                <li key={i} className="flex items-start gap-2">
                  <HelpCircle className="w-3.5 h-3.5 text-amber-400/80 shrink-0 mt-0.5" />
                  <span>{uncheck}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-slate-400">All configured checks were completed.</p>
          )}
        </div>
      </div>

      {/* 5. Button to Return to a New Inspection */}
      <div className="pt-2 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <p className="text-[11px] text-slate-500 leading-relaxed">
          {result.limitations}
        </p>

        <button
          type="button"
          onClick={onReset}
          className="px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-100 font-semibold rounded-xl text-xs transition-colors flex items-center justify-center gap-2 whitespace-nowrap shrink-0 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500/60"
        >
          <RotateCcw className="w-3.5 h-3.5 text-sky-400" />
          <span>New Inspection</span>
        </button>
      </div>
    </section>
  );
};
