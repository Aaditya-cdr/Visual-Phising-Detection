/**
 * URL Inspection Input Form
 * Validates empty and malformed inputs, displays privacy & scope note, and triggers URL analysis.
 */

import React, { useState } from 'react';
import { Globe, ArrowRight, X, Lock, AlertCircle } from 'lucide-react';

interface UrlInputFormProps {
  url: string;
  setUrl: (url: string) => void;
  onAnalyze: (url: string) => void;
  isLoading: boolean;
  onClear: () => void;
}

export const UrlInputForm: React.FC<UrlInputFormProps> = ({
  url,
  setUrl,
  onAnalyze,
  isLoading,
  onClear,
}) => {
  const [validationError, setValidationError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = url.trim();

    if (!trimmed) {
      setValidationError('Please enter a website URL to inspect (e.g., https://example.com).');
      return;
    }

    if (/\s/.test(trimmed)) {
      setValidationError('Invalid URL format: URLs cannot contain spaces. Please enter a valid web address.');
      return;
    }

    if (trimmed.length > 4096) {
      setValidationError('URL exceeds maximum supported length (4,096 characters).');
      return;
    }

    setValidationError(null);
    onAnalyze(trimmed);
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setUrl(e.target.value);
    if (validationError) setValidationError(null);
  };

  return (
    <form onSubmit={handleSubmit} className="w-full space-y-3" noValidate>
      <div>
        <label htmlFor="url-input" className="block text-xs font-medium text-slate-300 mb-2">
          Website URL to Inspect
        </label>
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5">
          <div className="relative flex-1 flex items-center">
            <div className="absolute left-3.5 text-slate-500 pointer-events-none">
              <Globe className="w-4 h-4" />
            </div>
            <input
              id="url-input"
              type="url"
              value={url}
              onChange={handleInputChange}
              placeholder="https://example.com/login"
              disabled={isLoading}
              aria-invalid={Boolean(validationError)}
              aria-describedby={validationError ? 'url-validation-error' : 'url-privacy-note'}
              className={`w-full h-11 pl-10 pr-10 bg-slate-900/90 border rounded-xl text-slate-100 placeholder-slate-500 font-mono text-sm leading-normal focus:outline-none focus:ring-2 focus:ring-sky-500/50 transition-all ${
                validationError
                  ? 'border-red-500/70 focus:border-red-500'
                  : 'border-slate-800 focus:border-sky-500'
              }`}
            />
            {url && !isLoading && (
              <button
                type="button"
                onClick={() => {
                  setValidationError(null);
                  onClear();
                }}
                className="absolute right-2.5 p-1.5 text-slate-400 hover:text-slate-200 rounded-lg hover:bg-slate-800 transition-colors"
                aria-label="Clear URL input"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="h-11 px-5 bg-sky-500 text-slate-950 font-semibold rounded-xl text-xs sm:text-sm hover:bg-sky-400 active:bg-sky-500 disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 transition-all flex items-center justify-center gap-2 whitespace-nowrap shrink-0 shadow-sm"
          >
            <span>{isLoading ? 'Analyzing...' : 'Analyze'}</span>
            {!isLoading && <ArrowRight className="w-4 h-4" />}
          </button>
        </div>

        {validationError && (
          <div
            id="url-validation-error"
            role="alert"
            className="mt-2 flex items-center gap-1.5 text-xs text-red-400"
          >
            <AlertCircle className="w-3.5 h-3.5 shrink-0" />
            <span>{validationError}</span>
          </div>
        )}
      </div>

      {/* Small privacy and analysis-scope note */}
      <p
        id="url-privacy-note"
        className="text-xs text-slate-400 flex items-start sm:items-center gap-1.5 leading-relaxed pt-0.5"
      >
        <Lock className="w-3.5 h-3.5 text-sky-400/80 shrink-0 mt-0.5 sm:mt-0" />
        <span>
          Privacy &amp; Scope: URLs are parsed passively in-memory and never visited or executed. Heuristic checks flag warning signs and do not guarantee safety.
        </span>
      </p>
    </form>
  );
};
