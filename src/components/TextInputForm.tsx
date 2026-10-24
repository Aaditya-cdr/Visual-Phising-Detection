/**
 * Email Body and Message / SMS Inspection Form
 * Validates empty and invalid inputs, displays privacy & scope note, and triggers text analysis.
 */

import React, { useState } from 'react';
import { ArrowRight, X, Lock, AtSign, AlertCircle } from 'lucide-react';

interface TextInputFormProps {
  mode: 'email' | 'message';
  text: string;
  setText: (val: string) => void;
  sender: string;
  setSender: (val: string) => void;
  onAnalyze: (text: string, mode: 'email' | 'message', sender?: string) => void;
  isLoading: boolean;
  onClear: () => void;
}

const MAX_CHAR_LIMIT = 50000;

export const TextInputForm: React.FC<TextInputFormProps> = ({
  mode,
  text,
  setText,
  sender,
  setSender,
  onAnalyze,
  isLoading,
  onClear,
}) => {
  const [validationError, setValidationError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = text.trim();
    const trimmedSender = sender.trim();

    if (!trimmed) {
      setValidationError(
        mode === 'email'
          ? 'Please paste the email body content to inspect.'
          : 'Please paste the message or SMS text to inspect.'
      );
      return;
    }

    if (trimmed.length < 4) {
      setValidationError('Input is too short to analyze. Please paste the full email or message text.');
      return;
    }

    if (trimmed.length > MAX_CHAR_LIMIT) {
      setValidationError(`Content exceeds maximum allowed limit (${MAX_CHAR_LIMIT.toLocaleString()} characters).`);
      return;
    }

    if (mode === 'email' && trimmedSender) {
      // Validate sender email or domain format if provided
      const validSenderPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$|^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (!validSenderPattern.test(trimmedSender)) {
        setValidationError('Invalid sender address format. Enter an email (e.g., support@paypal.com) or leave blank.');
        return;
      }
    }

    setValidationError(null);
    onAnalyze(trimmed, mode, mode === 'email' && trimmedSender ? trimmedSender : undefined);
  };

  const handleTextChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setText(e.target.value);
    if (validationError) setValidationError(null);
  };

  const handleSenderChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSender(e.target.value);
    if (validationError) setValidationError(null);
  };

  const placeholderText =
    mode === 'email'
      ? 'Paste suspicious email body text here...\n\nExample: "URGENT: Your account has been suspended. Verify your credentials immediately at https://paypa1-security.com/verify"'
      : 'Paste suspicious SMS or chat message here...\n\nExample: "USPS: Your package cannot be delivered due to an unpaid $2.45 fee. Pay now at https://usps-redelivery.top/pay"';

  return (
    <form onSubmit={handleSubmit} className="w-full space-y-3" noValidate>
      {mode === 'email' && (
        <div>
          <label htmlFor="sender-input" className="block text-xs font-medium text-slate-300 mb-1.5">
            Sender Address / From Header <span className="text-slate-500 font-normal">(Optional)</span>
          </label>
          <div className="relative flex items-center">
            <div className="absolute left-3.5 text-slate-500 pointer-events-none">
              <AtSign className="w-4 h-4" />
            </div>
            <input
              id="sender-input"
              type="text"
              value={sender}
              onChange={handleSenderChange}
              placeholder="e.g. service@paypal.com"
              disabled={isLoading}
              className="w-full pl-10 pr-4 py-2.5 bg-slate-900/90 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-500 font-mono text-xs sm:text-sm focus:outline-none focus:ring-2 focus:ring-sky-500/50 focus:border-sky-500 transition-all"
            />
          </div>
        </div>
      )}

      <div>
        <div className="flex items-center justify-between mb-1.5">
          <label htmlFor="content-textarea" className="block text-xs font-medium text-slate-300">
            {mode === 'email' ? 'Email Body Content' : 'Message / SMS Text'}
          </label>
          <div className="flex items-center gap-3">
            {(text || sender) && !isLoading && (
              <button
                type="button"
                onClick={() => {
                  setValidationError(null);
                  onClear();
                }}
                className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1 transition-colors"
                aria-label="Clear text input"
              >
                <X className="w-3.5 h-3.5" />
                <span>Clear</span>
              </button>
            )}
            <span className="text-[11px] text-slate-500 tabular-nums">
              {text.length.toLocaleString()} / {MAX_CHAR_LIMIT.toLocaleString()}
            </span>
          </div>
        </div>

        <textarea
          id="content-textarea"
          value={text}
          onChange={handleTextChange}
          placeholder={placeholderText}
          disabled={isLoading}
          rows={5}
          aria-invalid={Boolean(validationError)}
          aria-describedby={validationError ? 'text-validation-error' : 'text-privacy-note'}
          className={`w-full p-3.5 bg-slate-900/90 border rounded-xl text-slate-100 placeholder-slate-500 text-sm leading-relaxed focus:outline-none focus:ring-2 focus:ring-sky-500/50 transition-all font-sans ${
            validationError
              ? 'border-red-500/70 focus:border-red-500'
              : 'border-slate-800 focus:border-sky-500'
          }`}
        />

        {validationError && (
          <div
            id="text-validation-error"
            role="alert"
            className="mt-2 flex items-center gap-1.5 text-xs text-red-400"
          >
            <AlertCircle className="w-3.5 h-3.5 shrink-0" />
            <span>{validationError}</span>
          </div>
        )}
      </div>

      <div className="pt-1 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        {/* Small privacy and analysis-scope note */}
        <p
          id="text-privacy-note"
          className="text-xs text-slate-400 flex items-start sm:items-center gap-1.5 leading-relaxed"
        >
          <Lock className="w-3.5 h-3.5 text-sky-400/80 shrink-0 mt-0.5 sm:mt-0" />
          <span>
            Privacy &amp; Scope: Text and embedded links are analyzed in-memory without storing content. Heuristic checks do not guarantee safety.
          </span>
        </p>

        {/* Primary Analyze Button */}
        <button
          type="submit"
          disabled={isLoading}
          className="px-5 py-2.5 bg-sky-500 text-slate-950 font-semibold rounded-xl text-xs sm:text-sm hover:bg-sky-400 active:bg-sky-500 disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 transition-all flex items-center justify-center gap-2 whitespace-nowrap shrink-0 shadow-sm"
        >
          <span>{isLoading ? 'Analyzing...' : 'Analyze'}</span>
          {!isLoading && <ArrowRight className="w-4 h-4" />}
        </button>
      </div>
    </form>
  );
};
