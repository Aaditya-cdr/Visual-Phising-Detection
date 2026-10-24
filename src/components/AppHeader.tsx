/**
 * Top Navigation Header for PhishLens — Visual Phishing Detection
 * 3 Zones: Brand title — Navigation tabs (Inspect, Extension) — New Inspection button
 */

import React from 'react';
import { RotateCcw } from 'lucide-react';

interface AppHeaderProps {
  activeView: 'inspect' | 'extension';
  setActiveView: (view: 'inspect' | 'extension') => void;
  onReset: () => void;
}

export const AppHeader: React.FC<AppHeaderProps> = ({
  activeView,
  setActiveView,
  onReset,
}) => {
  return (
    <header className="w-full border-b border-slate-800/80 bg-[#0b0f19]/90 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-5xl mx-auto px-3 sm:px-6 h-16 flex items-center justify-between gap-1.5 sm:gap-6">
        {/* Zone 1: Brand Title */}
        <button
          type="button"
          aria-label="Visual Phishing Detection"
          onClick={() => {
            setActiveView('inspect');
            onReset();
          }}
          className="flex items-center text-left group focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500/60 rounded-lg py-1 min-w-0"
        >
          <span className="text-[11px] sm:text-sm font-medium tracking-tight text-slate-300 group-hover:text-slate-100 transition-colors truncate">
            Visual Phishing Detection
          </span>
        </button>

        {/* Zone 2 & 3: Navigation Tabs & New Inspection Action */}
        <div className="flex items-center gap-1 sm:gap-5 shrink-0">
          <nav
            className="flex items-center gap-0.5 sm:gap-2 text-[11px] sm:text-sm font-medium"
            aria-label="Main Navigation"
          >
            <button
              type="button"
              onClick={() => setActiveView('inspect')}
              aria-current={activeView === 'inspect' ? 'page' : undefined}
              className={`px-2 sm:px-2.5 py-1 sm:py-1.5 rounded-lg whitespace-nowrap transition-colors ${
                activeView === 'inspect'
                  ? 'text-sky-400 bg-sky-500/10 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              Inspect
            </button>
            <button
              type="button"
              onClick={() => setActiveView('extension')}
              aria-current={activeView === 'extension' ? 'page' : undefined}
              className={`px-2 sm:px-2.5 py-1 sm:py-1.5 rounded-lg whitespace-nowrap transition-colors ${
                activeView === 'extension'
                  ? 'text-sky-400 bg-sky-500/10 font-semibold'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              Extension
            </button>
          </nav>

          <button
            type="button"
            onClick={() => {
              setActiveView('inspect');
              onReset();
            }}
            className="px-2 sm:px-3 py-1 sm:py-1.5 text-[11px] sm:text-xs font-semibold text-slate-200 bg-slate-900 border border-slate-700/80 rounded-lg hover:bg-slate-800 hover:text-white hover:border-slate-600 focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-500/60 transition-all flex items-center gap-1.5 whitespace-nowrap shrink-0"
          >
            <RotateCcw className="w-3.5 h-3.5 text-sky-400 hidden sm:inline-block" />
            <span>New Inspection</span>
          </button>
        </div>
      </div>
    </header>
  );
};
