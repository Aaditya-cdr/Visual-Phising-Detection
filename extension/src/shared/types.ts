/**
 * PhishLens Chrome Extension — Strict Shared Types & Message Contracts
 * Covers page inspection signals, extension messaging, analysis results,
 * finding severities, and structured inspection errors.
 */

export type FindingSeverity = 'high' | 'medium' | 'low' | 'info';

export type InspectionRiskCategory =
  | 'SUSPICIOUS'
  | 'NEEDS_REVIEW'
  | 'NO_EVIDENCE_FOUND'
  | 'NOT_ANALYSED';

export type PopupViewState =
  | 'READY'
  | 'ANALYSING'
  | 'SUSPICIOUS'
  | 'NEEDS_REVIEW'
  | 'NO_EVIDENCE_FOUND'
  | 'NOT_ANALYSED';

export type InspectionErrorCode =
  | 'NO_ACTIVE_TAB'
  | 'MISSING_TAB_URL'
  | 'RESTRICTED_BROWSER_PAGE'
  | 'UNSUPPORTED_PROTOCOL'
  | 'SCRIPT_INJECTION_FAILED'
  | 'CONTENT_SCRIPT_ERROR'
  | 'MALFORMED_MESSAGE'
  | 'SERVICE_WORKER_ERROR';

export interface InspectionError {
  code: InspectionErrorCode;
  title: string;
  message: string;
  recoverable: boolean;
}

export interface ParsedDomainInfo {
  rawUrl: string;
  isValidUrl: boolean;
  protocol: string;
  origin: string;
  hostname: string;
  registrableDomain: string | null;
  publicSuffix: string | null;
  subdomain: string | null;
  subdomainDepth: number;
  isIp: boolean;
  isLocalhostOrPrivate: boolean;
  hasUserInfo: boolean;
  isPunycode: boolean;
}

export interface FormInspectionSignal {
  /** Raw action attribute value (null if omitted) */
  actionRaw: string | null;
  /** Resolved origin of the form action target */
  actionOrigin: string;
  /** Resolved hostname of the form action target */
  actionHostname: string;
  /** Resolved protocol of the form action target (e.g. 'https:', 'http:') */
  actionProtocol: string;
  /** HTTP method normalized to uppercase */
  method: string;
  /** Whether the form contains an input[type="password"] element */
  hasPasswordField: boolean;
  /** Whether the resolved action origin differs from the current page origin */
  submitsToDifferentOrigin: boolean;
  /** Whether the form action could not be safely parsed */
  actionParseFailed: boolean;
}

/**
 * Minimal, privacy-preserving DOM signals extracted from the active page.
 * Never includes input values, cookies, tokens, or raw HTML.
 */
export interface PageInspectionSignals {
  url: string;
  origin: string;
  hostname: string;
  protocol: string;
  documentTitle: string;
  hasPasswordField: boolean;
  passwordFieldCount: number;
  forms: FormInspectionSignal[];
  /** Bounded excerpt of visible page text for brand consistency checks */
  visibleTextSample: string;
  linksCount: number;
  externalLinksCount: number;
  crossOriginFrameCount: number;
  incompleteInspection: boolean;
  incompleteReasons: string[];
  extractedAt: string;
}

/**
 * Neutral factual observation extracted from the page or domain.
 * Observations describe what exists on the page without implying malice.
 */
export interface PageObservation {
  id: string;
  label: string;
  value: string;
}

/**
 * Risk-evaluated finding with explicit severity and evidence.
 */
export interface InspectionFinding {
  code: string;
  title: string;
  severity: FindingSeverity;
  description: string;
  evidence?: string;
}

export type BackendConnectionState = 'connected' | 'not_connected';
export type ReputationLookupState = 'checked' | 'not_configured' | 'not_connected';

export interface PageAnalysisReport {
  url: string;
  hostname: string;
  registrableDomain: string | null;
  riskCategory: InspectionRiskCategory;
  summary: string;
  recommendedAction: string;
  observations: PageObservation[];
  findings: InspectionFinding[];
  checksCompleted: string[];
  checksUnavailable: string[];
  backendStatus: BackendConnectionState;
  reputationStatus: ReputationLookupState;
  incompleteInspection: boolean;
  evaluatedAt: string;
}

export interface ActiveTabContext {
  tabId: number | null;
  url: string | null;
  hostname: string | null;
  registrableDomain: string | null;
  canInspect: boolean;
  unavailableError?: InspectionError;
}

/**
 * Extension Messaging Contracts (Popup <-> Service Worker <-> Content Script)
 */
export type ExtensionRequestMessage =
  | { type: 'GET_ACTIVE_TAB_CONTEXT' }
  | { type: 'ANALYSE_ACTIVE_TAB'; apiEndpoint?: string };

export type ExtensionResponseMessage =
  | {
      ok: true;
      type: 'ACTIVE_TAB_CONTEXT';
      context: ActiveTabContext;
    }
  | {
      ok: true;
      type: 'ANALYSIS_COMPLETE';
      report: PageAnalysisReport;
    }
  | {
      ok: false;
      type: 'INSPECTION_ERROR';
      error: InspectionError;
    };

export interface ContentScriptExtractRequest {
  type: 'EXTRACT_DOM_SIGNALS';
}

export type ContentScriptExtractResponse =
  | {
      ok: true;
      signals: PageInspectionSignals;
    }
  | {
      ok: false;
      error: string;
    };

/**
 * Runtime type guards for untrusted / cross-context messages
 */
export function isValidExtensionRequest(msg: unknown): msg is ExtensionRequestMessage {
  if (!msg || typeof msg !== 'object') return false;
  const candidate = msg as Record<string, unknown>;
  if (candidate.type === 'GET_ACTIVE_TAB_CONTEXT') return true;
  if (candidate.type === 'ANALYSE_ACTIVE_TAB') {
    return (
      candidate.apiEndpoint === undefined || typeof candidate.apiEndpoint === 'string'
    );
  }
  return false;
}

export function isValidPageInspectionSignals(data: unknown): data is PageInspectionSignals {
  if (!data || typeof data !== 'object') return false;
  const d = data as Record<string, unknown>;
  return (
    typeof d.url === 'string' &&
    typeof d.origin === 'string' &&
    typeof d.hostname === 'string' &&
    typeof d.protocol === 'string' &&
    typeof d.hasPasswordField === 'boolean' &&
    typeof d.passwordFieldCount === 'number' &&
    Array.isArray(d.forms) &&
    typeof d.visibleTextSample === 'string' &&
    typeof d.incompleteInspection === 'boolean' &&
    Array.isArray(d.incompleteReasons)
  );
}

export function isValidContentScriptResponse(
  msg: unknown
): msg is ContentScriptExtractResponse {
  if (!msg || typeof msg !== 'object') return false;
  const candidate = msg as Record<string, unknown>;
  if (candidate.ok === true) {
    return isValidPageInspectionSignals(candidate.signals);
  }
  if (candidate.ok === false) {
    return typeof candidate.error === 'string';
  }
  return false;
}
