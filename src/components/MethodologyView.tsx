/**
 * Detection Methodology and Security Limitations View
 */

import React from 'react';
import { ShieldCheck, AlertCircle, Eye, Database, Lock, CheckCircle2, CircleDashed, Check } from 'lucide-react';

interface MethodologyViewProps {
  onBack: () => void;
}

export const MethodologyView: React.FC<MethodologyViewProps> = ({ onBack }) => {
  return (
    <div className="w-full max-w-4xl mx-auto space-y-8 py-4 animate-in fade-in duration-300">
      {/* Title */}
      <div>
        <div className="inline-block text-xs font-mono text-sky-400 mb-1 tracking-wider uppercase">
          Technical Specification · PS 089
        </div>
        <h2 className="text-2xl font-bold text-slate-100">
          Detection Methodology & Operational Principles
        </h2>
        <p className="text-sm text-slate-400 mt-1 max-w-2xl">
          PhishLens operates on explainable, deterministic security heuristics. We prioritize clear evidence,
          actionable guidance, and rigorous privacy over opaque single-score algorithms.
        </p>
      </div>

      {/* Core Principles Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/50">
          <div className="flex items-center gap-2 text-sky-400 font-semibold text-xs mb-2">
            <Lock className="w-4 h-4" />
            <span>Privacy by Default</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Zero credential storage. No inbox access required. Submitted URLs are inspected through syntactic
            parsing and reputation queries without server-side HTTP navigation (SSRF prevention).
          </p>
        </div>

        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/50">
          <div className="flex items-center gap-2 text-sky-400 font-semibold text-xs mb-2">
            <Eye className="w-4 h-4" />
            <span>Explainable Findings</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Every alert pairs a stable rule code with exact observed evidence, why it represents a threat,
            and an actionable next step for the end user.
          </p>
        </div>

        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/50">
          <div className="flex items-center gap-2 text-sky-400 font-semibold text-xs mb-2">
            <AlertCircle className="w-4 h-4" />
            <span>No Unsupported Guarantees</span>
          </div>
          <p className="text-xs text-slate-300 leading-relaxed">
            Absence of evidence is never proof of safety. Emerging campaigns, compromised legitimate hosts,
            or bespoke spear-phishing lures are explicitly acknowledged in limitations.
          </p>
        </div>
      </div>

      {/* Signals Inspected Table */}
      <div className="border border-slate-800 bg-slate-900/40 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 bg-slate-900/80">
          <h3 className="text-sm font-semibold text-slate-200">Signals Evaluated by the Engine</h3>
        </div>
        <div className="divide-y divide-slate-800/80 text-xs">
          <div className="p-4 grid grid-cols-1 md:grid-cols-3 gap-2">
            <span className="font-semibold text-slate-300">URL & Hostname Structure</span>
            <div className="md:col-span-2 text-slate-400 space-y-1">
              <p>• WHATWG scheme validation (permits http/https; blocks dangerous javascript/data URI exploits).</p>
              <p>• Direct numerical IP hosts (IPv4, IPv6, dword representations).</p>
              <p>• Deceptive user-info patterns (`user@target.com`).</p>
              <p>• Internationalized domain names (Punycode `xn--`) and mixed-script confusables (Latin vs Cyrillic).</p>
              <p>• Excessive subdomain nesting (&gt;3 levels) and non-standard banking ports.</p>
            </div>
          </div>

          <div className="p-4 grid grid-cols-1 md:grid-cols-3 gap-2">
            <span className="font-semibold text-slate-300">Domain & Brand Impersonation</span>
            <div className="md:col-span-2 text-slate-400 space-y-1">
              <p>• Public suffix and registrable domain separation using `tldts`.</p>
              <p>• Typosquatting detection via normalized Levenshtein distance against known high-value brand targets.</p>
              <p>• Confusables / homoglyph normalization (0 → o, 1 → l, rn → m, vv → w).</p>
              <p>• Brand tokens embedded in subdomains (e.g. `paypal.com.attacker-server.net`).</p>
              <p>• Hyphenated token conjunctions (e.g. `apple-security-check.com`).</p>
            </div>
          </div>

          <div className="p-4 grid grid-cols-1 md:grid-cols-3 gap-2">
            <span className="font-semibold text-slate-300">Linguistic Coercion & Lures</span>
            <div className="md:col-span-2 text-slate-400 space-y-1">
              <p>• Artificial urgency deadlines ("within 24 hours", "immediate verification required").</p>
              <p>• Credential harvesting solicitations ("confirm your password", "re-enter credentials").</p>
              <p>• Intimidation patterns ("legal action pending", "warrant", "account suspended").</p>
              <p>• Parcel delivery fee lures and fake windfall rewards.</p>
              <p>• Sender domain vs embedded link destination domain conflicts.</p>
            </div>
          </div>

          <div className="p-4 grid grid-cols-1 md:grid-cols-3 gap-2">
            <span className="font-semibold text-slate-300">Page DOM Inspection (Extension)</span>
            <div className="md:col-span-2 text-slate-400 space-y-1">
              <p>• Password input field existence (zero value reading).</p>
              <p>• Form action target verification: cross-origin destination mismatch with credential fields.</p>
              <p>• Unencrypted HTTP submission of login data.</p>
              <p>• Discrepancies between visible brand text on the page and the actual registered host.</p>
            </div>
          </div>
        </div>
      </div>

      {/* Implemented vs Planned Features */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-4 rounded-xl border border-emerald-900/30 bg-emerald-950/10">
          <span className="flex items-center gap-1.5 text-xs font-semibold text-emerald-400 mb-2">
            <CheckCircle2 className="w-4 h-4" />
            Implemented in Prototype (v1.0)
          </span>
          <ul className="text-xs text-slate-300 space-y-2">
            <li className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" /> WHATWG URL & RFC 3986 scheme parser</li>
            <li className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" /> Domain feature extraction using tldts</li>
            <li className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" /> Brand typosquatting & confusable heuristics</li>
            <li className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" /> Linguistic urgency & credential prompt extractor</li>
            <li className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" /> Form destination DOM inspector (Extension)</li>
            <li className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" /> Pluggable Threat Intelligence (Google Safe Browsing)</li>
            <li className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" /> Chrome Extension Manifest V3 package with popup</li>
            <li className="flex items-center gap-1.5"><Check className="w-3.5 h-3.5 text-emerald-400 shrink-0" /> Strict SSRF prevention architecture</li>
          </ul>
        </div>

        <div className="p-4 rounded-xl border border-slate-800 bg-slate-900/40">
          <span className="flex items-center gap-1.5 text-xs font-semibold text-slate-400 mb-2">
            <CircleDashed className="w-4 h-4 text-slate-500" />
            Planned Future Capabilities
          </span>
          <ul className="text-xs text-slate-400 space-y-2">
            <li className="flex items-center gap-1.5"><CircleDashed className="w-3.5 h-3.5 text-slate-500 shrink-0" /> Client-side visual OCR for brand marks</li>
            <li className="flex items-center gap-1.5"><CircleDashed className="w-3.5 h-3.5 text-slate-500 shrink-0" /> Perceptual image hashing for logo similarity</li>
            <li className="flex items-center gap-1.5"><CircleDashed className="w-3.5 h-3.5 text-slate-500 shrink-0" /> Real-time DNS WHOIS registration age prober</li>
            <li className="flex items-center gap-1.5"><CircleDashed className="w-3.5 h-3.5 text-slate-500 shrink-0" /> Certificate Transparency log stream correlation</li>
            <li className="flex items-center gap-1.5"><CircleDashed className="w-3.5 h-3.5 text-slate-500 shrink-0" /> Automated sandbox crawler with egress gateway</li>
          </ul>
        </div>
      </div>

      <div className="pt-2 text-center">
        <button
          onClick={onBack}
          className="px-6 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold rounded-xl text-xs transition-colors"
        >
          Return to Inspection
        </button>
      </div>
    </div>
  );
};
