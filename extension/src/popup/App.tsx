import React, { useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Info,
  Loader2,
  Lock,
  Search,
  Shield,
  ShieldAlert,
  Slash,
} from 'lucide-react';
import { checkUrlInspectability, parseDomainWithTldts } from '../shared/domain-parser.ts';
import { evaluatePageSignals } from '../shared/evaluator.ts';
import { extractPageSignalsFromDocument } from '../content/inspect-page.ts';
import {
  ActiveTabContext,
  ExtensionResponseMessage,
  InspectionError,
  PageAnalysisReport,
  PopupViewState,
} from '../shared/types.ts';

function isChromeExtensionRuntime(): boolean {
  return (
    typeof chrome !== 'undefined' &&
    Boolean(chrome.runtime?.id) &&
    typeof chrome.runtime?.sendMessage === 'function'
  );
}

export const App: React.FC = () => {
  const [viewState, setViewState] = useState<PopupViewState>('READY');
  const [tabContext, setTabContext] = useState<ActiveTabContext>({
    tabId: null,
    url: null,
    hostname: null,
    registrableDomain: null,
    canInspect: true,
  });
  const [report, setReport] = useState<PageAnalysisReport | null>(null);
  const [inspectionError, setInspectionError] = useState<InspectionError | null>(null);

  // Query active tab metadata on popup open (without automatically running DOM inspection)
  useEffect(() => {
    let cancelled = false;

    async function loadInitialTabContext() {
      if (isChromeExtensionRuntime()) {
        try {
          const response = (await chrome.runtime.sendMessage({
            type: 'GET_ACTIVE_TAB_CONTEXT',
          })) as ExtensionResponseMessage | undefined;

          if (cancelled) return;

          if (response && response.ok && response.type === 'ACTIVE_TAB_CONTEXT') {
            setTabContext(response.context);
            if (!response.context.canInspect) {
              setViewState('NOT_ANALYSED');
              setInspectionError(
                response.context.unavailableError || {
                  code: 'RESTRICTED_BROWSER_PAGE',
                  title: 'Inspection Unavailable',
                  message: 'This page cannot be inspected by browser extensions.',
                  recoverable: false,
                }
              );
            } else {
              setViewState('READY');
              setInspectionError(null);
            }
          } else if (response && !response.ok) {
            setViewState('NOT_ANALYSED');
            setInspectionError(response.error);
          }
        } catch (err: unknown) {
          if (cancelled) return;
          setViewState('NOT_ANALYSED');
          setInspectionError({
            code: 'SERVICE_WORKER_ERROR',
            title: 'Extension Background Unavailable',
            message:
              err instanceof Error
                ? err.message
                : 'Could not reach the extension service worker.',
            recoverable: true,
          });
        }
        return;
      }

      // Standalone browser preview mode (when opened outside chrome-extension:// runtime)
      const params = new URLSearchParams(window.location.search);
      const targetUrl = params.get('targetUrl') || window.location.href;
      const inspectability = checkUrlInspectability(targetUrl);

      if (!inspectability.canInspect) {
        setTabContext({
          tabId: null,
          url: targetUrl,
          hostname: targetUrl,
          registrableDomain: null,
          canInspect: false,
          unavailableError: inspectability.error,
        });
        setViewState('NOT_ANALYSED');
        setInspectionError(inspectability.error || null);
        return;
      }

      const parsed = parseDomainWithTldts(targetUrl);
      setTabContext({
        tabId: 1,
        url: targetUrl,
        hostname: parsed.hostname || null,
        registrableDomain: parsed.registrableDomain,
        canInspect: true,
      });
      setViewState('READY');
    }

    loadInitialTabContext();
    return () => {
      cancelled = true;
    };
  }, []);

  const handleAnalysePage = useCallback(async () => {
    if (!tabContext.canInspect || viewState === 'ANALYSING') return;

    setViewState('ANALYSING');
    setInspectionError(null);

    if (isChromeExtensionRuntime()) {
      try {
        const response = (await chrome.runtime.sendMessage({
          type: 'ANALYSE_ACTIVE_TAB',
        })) as ExtensionResponseMessage | undefined;

        if (!response) {
          setViewState('NOT_ANALYSED');
          setInspectionError({
            code: 'SERVICE_WORKER_ERROR',
            title: 'Empty Service Worker Response',
            message: 'The background service worker did not return an inspection report.',
            recoverable: true,
          });
          return;
        }

        if (!response.ok) {
          setViewState('NOT_ANALYSED');
          setInspectionError(response.error);
          return;
        }

        if (response.type === 'ANALYSIS_COMPLETE') {
          setReport(response.report);
          setViewState(response.report.riskCategory);
        }
      } catch (err: unknown) {
        setViewState('NOT_ANALYSED');
        setInspectionError({
          code: 'SERVICE_WORKER_ERROR',
          title: 'Inspection Request Failed',
          message:
            err instanceof Error
              ? err.message
              : 'Failed to communicate with extension background worker.',
          recoverable: true,
        });
      }
      return;
    }

    // Standalone document fallback when popup HTML is opened directly in a browser tab
    try {
      const localSignals = extractPageSignalsFromDocument(document, window.location);
      const params = new URLSearchParams(window.location.search);
      const overrideUrl = params.get('targetUrl');
      if (overrideUrl) {
        try {
          const u = new URL(overrideUrl);
          localSignals.url = u.href;
          localSignals.origin = u.origin;
          localSignals.hostname = u.hostname.toLowerCase();
          localSignals.protocol = u.protocol.toLowerCase();
        } catch {
          // Ignore invalid override
        }
      }

      const evaluated = evaluatePageSignals(localSignals, {
        backendStatus: 'not_connected',
        reputationStatus: 'not_connected',
      });
      setReport(evaluated);
      setViewState(evaluated.riskCategory);
    } catch (err: unknown) {
      setViewState('NOT_ANALYSED');
      setInspectionError({
        code: 'CONTENT_SCRIPT_ERROR',
        title: 'Local Inspection Failed',
        message:
          err instanceof Error ? err.message : 'Unable to inspect the current document.',
        recoverable: true,
      });
    }
  }, [tabContext.canInspect, viewState]);

  const isAnalysing = viewState === 'ANALYSING';
  const isInspectDisabled = !tabContext.canInspect || isAnalysing;

  return (
    <div className="popup-shell">
      {/* Header */}
      <header className="popup-header">
        <div className="brand-lockup">
          <div className="brand-icon-wrap" aria-hidden="true">
            <Shield size={16} />
          </div>
          <div className="brand-text-group">
            <span className="brand-name">PhishLens</span>
            <span className="section-kicker">ACTIVE TAB INSPECTION</span>
          </div>
        </div>
      </header>

      {/* Active Website Hostname Bar */}
      <section className="target-card" aria-label="Active website target">
        <div className="target-label-row">
          <span>Current Website Hostname</span>
          {tabContext.registrableDomain &&
            tabContext.registrableDomain !== tabContext.hostname && (
              <span>Domain: {tabContext.registrableDomain}</span>
            )}
        </div>
        <div
          className={`target-hostname ${!tabContext.hostname ? 'muted' : ''}`}
          data-testid="active-hostname"
        >
          {tabContext.hostname || 'No inspectable website active'}
        </div>
      </section>

      {/* Primary Action Button */}
      <button
        type="button"
        className="primary-btn"
        onClick={handleAnalysePage}
        disabled={isInspectDisabled}
      >
        {isAnalysing ? (
          <>
            <Loader2 size={15} className="spin-icon" aria-hidden="true" />
            <span>Analysing active tab...</span>
          </>
        ) : (
          <>
            <Search size={15} aria-hidden="true" />
            <span>Analyse this page</span>
          </>
        )}
      </button>

      {/* Compact Results Area */}
      <main className="results-area" aria-live="polite">
        {/* STATE 1: Ready to analyse (Neutral Empty State) */}
        {viewState === 'READY' && (
          <div className="state-card ready" data-testid="state-ready">
            <div className="status-title-row" style={{ color: '#e2e8f0' }}>
              <Info size={15} style={{ color: '#38bdf8' }} aria-hidden="true" />
              <span>Ready to analyse</span>
            </div>
            <p className="status-summary muted">
              No analysis has run on this tab yet. Click{' '}
              <strong style={{ color: '#f1f5f9' }}>Analyse this page</strong> to inspect
              registrable domain structure, password fields, and form submission targets.
            </p>
          </div>
        )}

        {/* STATE 2: Analysing */}
        {viewState === 'ANALYSING' && (
          <div className="state-card ready" data-testid="state-analysing">
            <div className="status-title-row" style={{ color: '#38bdf8' }}>
              <Loader2 size={15} className="spin-icon" aria-hidden="true" />
              <span>Analysing page signals...</span>
            </div>
            <p className="status-summary muted">
              Extracting active DOM form destinations, credential input presence, and
              registrable domain boundaries.
            </p>
          </div>
        )}

        {/* STATE 6: Not analysed / Inspection unavailable */}
        {viewState === 'NOT_ANALYSED' && (
          <div className="state-card unavailable" data-testid="state-not-analysed">
            <div className="status-header">
              <div className="status-title-row unavailable">
                <Slash size={15} aria-hidden="true" />
                <span>Not Analysed · Inspection Unavailable</span>
              </div>
            </div>
            <p className="status-summary">
              {inspectionError?.message ||
                'This browser tab cannot be inspected. Switch to an HTTP or HTTPS webpage and try again.'}
            </p>
            {inspectionError?.code && (
              <div className="subsection">
                <span className="finding-evidence">Reason code: {inspectionError.code}</span>
              </div>
            )}
          </div>
        )}

        {/* STATES 3, 4, 5: Completed / Partial Inspection Report */}
        {report &&
          (viewState === 'SUSPICIOUS' ||
            viewState === 'NEEDS_REVIEW' ||
            viewState === 'NO_EVIDENCE_FOUND') && (
            <div
              className={`state-card ${
                viewState === 'SUSPICIOUS'
                  ? 'suspicious'
                  : viewState === 'NEEDS_REVIEW'
                  ? 'review'
                  : 'clean'
              }`}
              data-testid={`state-${viewState.toLowerCase()}`}
            >
              {/* Status Heading */}
              <div className="status-header">
                {viewState === 'SUSPICIOUS' && (
                  <div className="status-title-row suspicious">
                    <ShieldAlert size={16} aria-hidden="true" />
                    <span>Suspicious</span>
                  </div>
                )}
                {viewState === 'NEEDS_REVIEW' && (
                  <div className="status-title-row review">
                    <AlertTriangle size={16} aria-hidden="true" />
                    <span>Needs Review</span>
                  </div>
                )}
                {viewState === 'NO_EVIDENCE_FOUND' && (
                  <div className="status-title-row clean">
                    <CheckCircle2 size={16} aria-hidden="true" />
                    <span>No Evidence Found</span>
                  </div>
                )}
              </div>

              {/* Concise Summary */}
              <p className="status-summary">{report.summary}</p>

              {/* Findings (Risk Conclusions) */}
              {report.findings.length > 0 && (
                <div className="subsection">
                  <span className="subsection-label">
                    Findings ({report.findings.length})
                  </span>
                  <ul className="finding-list">
                    {report.findings.map(finding => (
                      <li key={finding.code} className="finding-item">
                        <div className="finding-item-header">
                          <span className="finding-title">{finding.title}</span>
                          <span className={`finding-severity ${finding.severity}`}>
                            {finding.severity}
                          </span>
                        </div>
                        <p className="finding-desc">{finding.description}</p>
                        {finding.evidence && (
                          <span className="finding-evidence">{finding.evidence}</span>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Neutral Extracted Observations */}
              <div className="subsection">
                <span className="subsection-label">Extracted Page Observations</span>
                <ul className="obs-list">
                  {report.observations.map(obs => (
                    <li key={obs.id} className="obs-row">
                      <span className="obs-label">{obs.label}</span>
                      <span className="obs-value">{obs.value}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Recommended Next Action */}
              <div className="action-box">
                <div className="action-box-label">Recommended Next Step</div>
                <div>{report.recommendedAction}</div>
              </div>

              {/* Backend / Reputation Scope Status */}
              {report.checksUnavailable.length > 0 && (
                <div className="subsection">
                  <span className="subsection-label">Checks Not Run / Scope Limits</span>
                  <ul className="scope-list">
                    {report.checksUnavailable.map((item, idx) => (
                      <li key={idx}>· {item}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
      </main>

      {/* Subtle Privacy Note */}
      <footer className="privacy-footer">
        <Lock size={12} style={{ marginTop: '2px', flexShrink: 0 }} aria-hidden="true" />
        <span>
          Inspects the active tab only when you click Analyse. Never reads password values,
          cookies, or browsing history.
        </span>
      </footer>
    </div>
  );
};
