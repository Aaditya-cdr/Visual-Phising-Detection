/**
 * PhishLens — Visual Phishing Detection Application
 * Core inspection workflow for websites, emails, and messages.
 */

import React, { useState } from 'react';
import {
  Globe,
  Mail,
  MessageSquare,
  AlertTriangle,
} from 'lucide-react';

import { AppHeader } from './components/AppHeader.tsx';
import { UrlInputForm } from './components/UrlInputForm.tsx';
import { TextInputForm } from './components/TextInputForm.tsx';
import { ResultPanel } from './components/ResultPanel.tsx';
import { ExtensionGuideView } from './components/ExtensionGuideView.tsx';

import { AnalysisResult } from './lib/analysis/types.ts';
import { analyzeUrl, analyzeText } from './lib/analysis/rule-engine.ts';

export default function App() {
  const [activeView, setActiveView] = useState<'inspect' | 'extension'>('inspect');
  const [activeTab, setActiveTab] = useState<'url' | 'email' | 'message'>('url');

  // Input states
  const [url, setUrl] = useState('');
  const [textContent, setTextContent] = useState('');
  const [senderAddress, setSenderAddress] = useState('');

  // Analysis states
  const [isLoading, setIsLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState<string>('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [sourceMode, setSourceMode] = useState<'api' | 'local-fallback'>('api');
  const [apiError, setApiError] = useState<string | null>(null);

  const handleClearUrl = () => {
    setUrl('');
    setApiError(null);
  };

  const handleClearText = () => {
    setTextContent('');
    setSenderAddress('');
    setApiError(null);
  };

  const handleReset = () => {
    setResult(null);
    setApiError(null);
  };

  const handleNewInspection = () => {
    setResult(null);
    setApiError(null);
    setUrl('');
    setTextContent('');
    setSenderAddress('');
  };

  // URL Analysis Runner
  const handleAnalyzeUrl = async (targetUrl: string) => {
    setIsLoading(true);
    setApiError(null);
    setResult(null);
    setLoadingStep('Validating URL syntax and domain heuristics...');

    try {
      const res = await fetch('/api/analyze/url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl }),
      });

      if (res.ok) {
        const data: AnalysisResult = await res.json();
        setSourceMode('api');
        setResult(data);
      } else {
        const errBody = await res.json().catch(() => null);
        if (res.status === 400 && errBody?.error) {
          setApiError(errBody.error);
        } else {
          const clientResult = await analyzeUrl(targetUrl);
          setSourceMode('local-fallback');
          setResult(clientResult);
        }
      }
    } catch {
      try {
        const clientResult = await analyzeUrl(targetUrl);
        setSourceMode('local-fallback');
        setResult(clientResult);
      } catch (clientErr: unknown) {
        setApiError(clientErr instanceof Error ? clientErr.message : 'Unable to complete URL analysis.');
      }
    } finally {
      setIsLoading(false);
      setLoadingStep('');
    }
  };

  // Text Analysis Runner (Email or Message)
  const handleAnalyzeText = async (text: string, mode: 'email' | 'message', sender?: string) => {
    setIsLoading(true);
    setApiError(null);
    setResult(null);
    setLoadingStep('Inspecting text signals and embedded links...');

    try {
      const res = await fetch('/api/analyze/text', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, type: mode, sender }),
      });

      if (res.ok) {
        const data: AnalysisResult = await res.json();
        setSourceMode('api');
        setResult(data);
      } else {
        const errBody = await res.json().catch(() => null);
        if (res.status === 400 && errBody?.error) {
          setApiError(errBody.error);
        } else {
          const clientResult = await analyzeText(text, mode, sender);
          setSourceMode('local-fallback');
          setResult(clientResult);
        }
      }
    } catch {
      try {
        const clientResult = await analyzeText(text, mode, sender);
        setSourceMode('local-fallback');
        setResult(clientResult);
      } catch (clientErr: unknown) {
        setApiError(clientErr instanceof Error ? clientErr.message : 'Unable to complete text analysis.');
      }
    } finally {
      setIsLoading(false);
      setLoadingStep('');
    }
  };

  return (
    <div className="min-h-screen bg-[#0b0f19] text-slate-100 flex flex-col font-sans selection:bg-sky-500/30 selection:text-sky-200">
      {/* Header with PhishLens — Visual Phishing Detection, Inspect & Extension tabs, and New Inspection button */}
      <AppHeader
        activeView={activeView}
        setActiveView={setActiveView}
        onReset={handleNewInspection}
      />

      {/* Centered Inspection Workspace */}
      <main className="flex-1 max-w-3xl w-full mx-auto px-4 sm:px-6 py-8 sm:py-10">
        {activeView === 'extension' ? (
          <ExtensionGuideView
            onBack={() => setActiveView('inspect')}
            onSimulatePageInspection={(simResult) => {
              setResult(simResult);
              setActiveView('inspect');
            }}
          />
        ) : (
          <div className="space-y-6 animate-in fade-in duration-300">
            {/* Main Heading */}
            <div className="text-center max-w-xl mx-auto space-y-2">
              <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
                Check before you trust.
              </h1>
              <p className="text-sm sm:text-base text-slate-400 leading-relaxed">
                Inspect suspicious links, websites, emails, and messages for phishing warning signs.
              </p>
            </div>

            {/* Centered Inspection Card */}
            <div className="bg-slate-950/70 border border-slate-800/80 rounded-2xl p-5 sm:p-6 shadow-xl">
              {/* Three Input Tabs */}
              <div
                role="tablist"
                aria-label="Inspection Input Type"
                className="grid grid-cols-3 gap-1 p-1 bg-slate-900 border border-slate-800 rounded-xl mb-5"
              >
                <button
                  type="button"
                  role="tab"
                  aria-selected={activeTab === 'url'}
                  onClick={() => {
                    setActiveTab('url');
                    handleReset();
                  }}
                  className={`py-2 px-1.5 sm:px-3 text-[11px] sm:text-xs font-semibold rounded-lg transition-all flex items-center justify-center gap-1.5 whitespace-nowrap ${
                    activeTab === 'url'
                      ? 'bg-sky-500 text-slate-950 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <Globe className="w-3.5 h-3.5 shrink-0 hidden sm:inline-block" />
                  <span>Website URL</span>
                </button>

                <button
                  type="button"
                  role="tab"
                  aria-selected={activeTab === 'email'}
                  onClick={() => {
                    setActiveTab('email');
                    handleReset();
                  }}
                  className={`py-2 px-1.5 sm:px-3 text-[11px] sm:text-xs font-semibold rounded-lg transition-all flex items-center justify-center gap-1.5 whitespace-nowrap ${
                    activeTab === 'email'
                      ? 'bg-sky-500 text-slate-950 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <Mail className="w-3.5 h-3.5 shrink-0 hidden sm:inline-block" />
                  <span>Email Body</span>
                </button>

                <button
                  type="button"
                  role="tab"
                  aria-selected={activeTab === 'message'}
                  onClick={() => {
                    setActiveTab('message');
                    handleReset();
                  }}
                  className={`py-2 px-1.5 sm:px-3 text-[11px] sm:text-xs font-semibold rounded-lg transition-all flex items-center justify-center gap-1.5 whitespace-nowrap ${
                    activeTab === 'message'
                      ? 'bg-sky-500 text-slate-950 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <MessageSquare className="w-3.5 h-3.5 shrink-0 hidden sm:inline-block" />
                  <span>Message / SMS</span>
                </button>
              </div>

              {/* Active Tab Input Form */}
              {activeTab === 'url' ? (
                <UrlInputForm
                  url={url}
                  setUrl={setUrl}
                  onAnalyze={handleAnalyzeUrl}
                  isLoading={isLoading}
                  onClear={handleClearUrl}
                />
              ) : (
                <TextInputForm
                  mode={activeTab}
                  text={textContent}
                  setText={setTextContent}
                  sender={senderAddress}
                  setSender={setSenderAddress}
                  onAnalyze={handleAnalyzeText}
                  isLoading={isLoading}
                  onClear={handleClearText}
                />
              )}

              {/* API Error State */}
              {apiError && (
                <div
                  role="alert"
                  className="mt-4 p-3 rounded-xl bg-red-950/40 border border-red-800/50 text-red-300 text-xs flex items-center gap-2"
                >
                  <AlertTriangle className="w-4 h-4 shrink-0" />
                  <span>{apiError}</span>
                </div>
              )}

              {/* Loading State */}
              {isLoading && (
                <div
                  role="status"
                  aria-live="polite"
                  className="mt-5 p-5 rounded-xl border border-sky-800/30 bg-sky-950/10 text-center space-y-2.5"
                >
                  <div className="inline-block w-5 h-5 border-2 border-sky-400/20 border-t-sky-400 rounded-full animate-spin" />
                  <p className="text-sm font-semibold text-slate-200">Analyzing input...</p>
                  <p className="text-xs text-sky-300/80 font-mono">{loadingStep}</p>
                </div>
              )}
            </div>

            {/* Results Panel shown after analysis */}
            {result && !isLoading && (
              <div id="results-section">
                <ResultPanel
                  result={result}
                  sourceMode={sourceMode}
                  onReset={handleNewInspection}
                />
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
