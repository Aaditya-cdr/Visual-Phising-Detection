/**
 * PhishLens Chrome Extension — Manifest V3 Background Service Worker
 *
 * Coordinates explicit user-triggered active tab inspection:
 *  - Never inspects tabs automatically on navigation
 *  - Uses chrome.tabs to identify the active tab on request
 *  - Uses chrome.scripting to execute content/inspect-page.js only when requested
 *  - Validates all structured messages and handles restricted pages gracefully
 *  - Integrates with the PhishLens backend API (/api/analyze/page) when reachable,
 *    or falls back transparently to local observation/heuristic analysis without
 *    fabricating reputation lookups.
 */

import { checkUrlInspectability, parseDomainWithTldts } from '../shared/domain-parser.ts';
import { evaluatePageSignals } from '../shared/evaluator.ts';
import {
  ActiveTabContext,
  BackendConnectionState,
  ExtensionResponseMessage,
  InspectionFinding,
  isValidContentScriptResponse,
  isValidExtensionRequest,
  PageInspectionSignals,
  ReputationLookupState,
} from '../shared/types.ts';

const DEFAULT_API_ENDPOINT = 'http://localhost:3000/api/analyze/page';
const API_TIMEOUT_MS = 2500;

/**
 * Queries the currently active tab in the focused window.
 */
async function queryActiveTab(): Promise<chrome.tabs.Tab | null> {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs && tabs.length > 0 ? tabs[0] ?? null : null;
}

/**
 * Builds the ActiveTabContext for the popup header and initial readiness state.
 */
async function getActiveTabContext(): Promise<ActiveTabContext> {
  const tab = await queryActiveTab();
  if (!tab || typeof tab.id !== 'number') {
    return {
      tabId: null,
      url: null,
      hostname: null,
      registrableDomain: null,
      canInspect: false,
      unavailableError: {
        code: 'NO_ACTIVE_TAB',
        title: 'No Active Tab Found',
        message: 'Could not locate an active browser tab in the current window.',
        recoverable: true,
      },
    };
  }

  const rawUrl = tab.url || tab.pendingUrl || null;
  const inspectability = checkUrlInspectability(rawUrl);

  if (!inspectability.canInspect || !rawUrl) {
    let displayHost: string | null = null;
    if (rawUrl) {
      try {
        const u = new URL(rawUrl);
        displayHost = u.hostname || `${u.protocol}//${u.pathname}`;
      } catch {
        displayHost = rawUrl.slice(0, 60);
      }
    }

    return {
      tabId: tab.id,
      url: rawUrl,
      hostname: displayHost,
      registrableDomain: null,
      canInspect: false,
      unavailableError: inspectability.error,
    };
  }

  const domainInfo = parseDomainWithTldts(rawUrl);

  return {
    tabId: tab.id,
    url: rawUrl,
    hostname: domainInfo.hostname || null,
    registrableDomain: domainInfo.registrableDomain,
    canInspect: true,
  };
}

/**
 * Injects content/inspect-page.js into the active tab and requests DOM signals.
 */
async function extractSignalsFromTab(
  tabId: number
): Promise<
  | { ok: true; signals: PageInspectionSignals }
  | { ok: false; errorTitle: string; errorMessage: string }
> {
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['content/inspect-page.js'],
    });
  } catch (err: unknown) {
    const rawMsg = err instanceof Error ? err.message : String(err);
    const isPermissionError =
      rawMsg.includes('Cannot access') ||
      rawMsg.includes('extensions gallery') ||
      rawMsg.includes('chrome://');

    return {
      ok: false,
      errorTitle: isPermissionError
        ? 'Restricted Page Access'
        : 'Content Script Injection Failed',
      errorMessage: isPermissionError
        ? 'Chrome restricts extensions from inspecting this page. Open a standard HTTP/HTTPS webpage and click the extension icon again.'
        : `Could not inject the page inspector into the active tab (${rawMsg}). Reload the tab and try again.`,
    };
  }

  try {
    const rawResponse: unknown = await chrome.tabs.sendMessage(tabId, {
      type: 'EXTRACT_DOM_SIGNALS',
    });

    if (!isValidContentScriptResponse(rawResponse)) {
      return {
        ok: false,
        errorTitle: 'Malformed Inspection Response',
        errorMessage:
          'The page inspection script returned an unexpected payload format.',
      };
    }

    if (!rawResponse.ok) {
      return {
        ok: false,
        errorTitle: 'DOM Extraction Error',
        errorMessage: rawResponse.error,
      };
    }

    return { ok: true, signals: rawResponse.signals };
  } catch (err: unknown) {
    const rawMsg = err instanceof Error ? err.message : String(err);
    return {
      ok: false,
      errorTitle: 'Inspection Messaging Failed',
      errorMessage: `Unable to communicate with the active tab inspector (${rawMsg}). Try reloading the webpage.`,
    };
  }
}

/**
 * Optionally queries the PhishLens backend API (/api/analyze/page) if available.
 * Never fabricates reputation results when the backend is offline or unconfigured.
 */
async function queryBackendAnalysisApi(
  signals: PageInspectionSignals,
  apiEndpoint: string = DEFAULT_API_ENDPOINT
): Promise<{
  backendStatus: BackendConnectionState;
  reputationStatus: ReputationLookupState;
  backendFindings: InspectionFinding[];
  backendUncompletedChecks: string[];
}> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), API_TIMEOUT_MS);

  try {
    const response = await fetch(apiEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: signals.url,
        hasPasswordField: signals.hasPasswordField,
        hasLoginForm:
          signals.hasPasswordField || signals.forms.some(f => f.hasPasswordField),
        forms: signals.forms.map(f => ({
          action: f.actionRaw || f.actionOrigin,
          method: f.method,
          hasPasswordField: f.hasPasswordField,
        })),
        visibleTextSample: signals.visibleTextSample,
        linksCount: signals.linksCount,
        externalLinksCount: signals.externalLinksCount,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      return {
        backendStatus: 'not_connected',
        reputationStatus: 'not_connected',
        backendFindings: [],
        backendUncompletedChecks: [],
      };
    }

    const data = (await response.json()) as {
      findings?: Array<{
        code?: string;
        title?: string;
        severity?: 'high' | 'medium' | 'low' | 'info';
        description?: string;
        evidence?: string;
      }>;
      uncompletedChecks?: string[];
      details?: Record<string, unknown>;
    };

    const backendFindings: InspectionFinding[] = [];
    if (Array.isArray(data.findings)) {
      for (const f of data.findings) {
        if (f && typeof f.code === 'string' && typeof f.title === 'string') {
          backendFindings.push({
            code: f.code,
            title: f.title,
            severity: f.severity || 'medium',
            description: f.description || '',
            evidence: f.evidence,
          });
        }
      }
    }

    const backendUncompletedChecks = Array.isArray(data.uncompletedChecks)
      ? data.uncompletedChecks.filter((c): c is string => typeof c === 'string')
      : [];

    const reputationUnavailable = backendUncompletedChecks.some(c =>
      c.toLowerCase().includes('threat intelligence')
    );

    return {
      backendStatus: 'connected',
      reputationStatus: reputationUnavailable ? 'not_configured' : 'checked',
      backendFindings,
      backendUncompletedChecks,
    };
  } catch {
    clearTimeout(timeoutId);
    return {
      backendStatus: 'not_connected',
      reputationStatus: 'not_connected',
      backendFindings: [],
      backendUncompletedChecks: [],
    };
  }
}

/**
 * Handles explicit requests from the extension popup.
 */
async function handleExtensionMessage(
  rawMessage: unknown
): Promise<ExtensionResponseMessage> {
  if (!isValidExtensionRequest(rawMessage)) {
    return {
      ok: false,
      type: 'INSPECTION_ERROR',
      error: {
        code: 'MALFORMED_MESSAGE',
        title: 'Invalid Extension Request',
        message: 'Received an unrecognized or malformed message in the service worker.',
        recoverable: false,
      },
    };
  }

  try {
    if (rawMessage.type === 'GET_ACTIVE_TAB_CONTEXT') {
      const context = await getActiveTabContext();
      return {
        ok: true,
        type: 'ACTIVE_TAB_CONTEXT',
        context,
      };
    }

    if (rawMessage.type === 'ANALYSE_ACTIVE_TAB') {
      const context = await getActiveTabContext();
      if (!context.canInspect || context.tabId === null) {
        return {
          ok: false,
          type: 'INSPECTION_ERROR',
          error: context.unavailableError || {
            code: 'RESTRICTED_BROWSER_PAGE',
            title: 'Inspection Unavailable',
            message: 'This tab cannot be inspected by browser extensions.',
            recoverable: false,
          },
        };
      }

      const extraction = await extractSignalsFromTab(context.tabId);
      if (!extraction.ok) {
        return {
          ok: false,
          type: 'INSPECTION_ERROR',
          error: {
            code: 'SCRIPT_INJECTION_FAILED',
            title: extraction.errorTitle,
            message: extraction.errorMessage,
            recoverable: true,
          },
        };
      }

      const apiOutcome = await queryBackendAnalysisApi(
        extraction.signals,
        rawMessage.apiEndpoint || DEFAULT_API_ENDPOINT
      );

      const report = evaluatePageSignals(extraction.signals, apiOutcome);

      return {
        ok: true,
        type: 'ANALYSIS_COMPLETE',
        report,
      };
    }

    return {
      ok: false,
      type: 'INSPECTION_ERROR',
      error: {
        code: 'MALFORMED_MESSAGE',
        title: 'Unsupported Action',
        message: 'Requested extension action is not supported.',
        recoverable: false,
      },
    };
  } catch (err: unknown) {
    return {
      ok: false,
      type: 'INSPECTION_ERROR',
      error: {
        code: 'SERVICE_WORKER_ERROR',
        title: 'Service Worker Failure',
        message:
          err instanceof Error
            ? err.message
            : 'An unexpected error occurred in the background service worker.',
        recoverable: true,
      },
    };
  }
}

// Register Chrome Extension MV3 lifecycle and messaging listeners
if (typeof chrome !== 'undefined' && chrome.runtime) {
  chrome.runtime.onInstalled?.addListener(details => {
    console.info(
      `[PhishLens] Extension ${details.reason}. On-demand activeTab inspection ready.`
    );
  });

  chrome.runtime.onMessage?.addListener((message: unknown, _sender, sendResponse) => {
    handleExtensionMessage(message)
      .then(response => {
        sendResponse(response);
      })
      .catch((err: unknown) => {
        const fallback: ExtensionResponseMessage = {
          ok: false,
          type: 'INSPECTION_ERROR',
          error: {
            code: 'SERVICE_WORKER_ERROR',
            title: 'Unhandled Background Error',
            message:
              err instanceof Error ? err.message : 'Service worker message handler failed.',
            recoverable: true,
          },
        };
        sendResponse(fallback);
      });

    // Return true to keep the message channel open for asynchronous response
    return true;
  });
}
