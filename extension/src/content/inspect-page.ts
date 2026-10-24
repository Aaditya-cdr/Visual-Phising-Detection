/**
 * PhishLens Chrome Extension — Safe Active-Page DOM Inspector (Content Script)
 *
 * Security & Privacy Invariants:
 *  - NEVER reads input.value or password field contents
 *  - NEVER reads document.cookie, localStorage, or sessionStorage
 *  - NEVER submits forms, clicks links, or mutates webpage DOM
 *  - NEVER extracts raw innerHTML or outerHTML
 *  - Treats all DOM attributes and text as untrusted input
 */

import {
  ContentScriptExtractResponse,
  FormInspectionSignal,
  PageInspectionSignals,
} from '../shared/types.ts';

declare global {
  interface Window {
    __PHISHLENS_CONTENT_LISTENER_INSTALLED__?: boolean;
  }
}

const MAX_FORMS_TO_INSPECT = 25;
const MAX_VISIBLE_TEXT_LENGTH = 800;

/**
 * Scrubs potential personal identifiers (email addresses, phone numbers,
 * credit-card/account-like digit sequences) from visible text excerpts so only
 * brand/heading context is retained.
 */
export function sanitizeVisibleTextExcerpt(rawText: string): string {
  if (!rawText) return '';
  return rawText
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[redacted-email]')
    .replace(/\b\d{4,}\b/g, '[redacted-digits]')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, MAX_VISIBLE_TEXT_LENGTH);
}

/**
 * Safely resolves a form's action attribute against the current page URL.
 */
export function inspectFormElement(
  rawActionAttr: string | null,
  rawMethodAttr: string | null,
  hasPasswordField: boolean,
  pageHref: string,
  pageOrigin: string
): FormInspectionSignal {
  const method = (rawMethodAttr || 'GET').trim().toUpperCase().slice(0, 16) || 'GET';
  const trimmedAction = rawActionAttr ? rawActionAttr.trim() : null;

  if (
    !trimmedAction ||
    trimmedAction === '#' ||
    trimmedAction.toLowerCase().startsWith('javascript:')
  ) {
    let fallbackHostname = '';
    let fallbackProtocol = 'https:';
    try {
      const pageUrl = new URL(pageHref);
      fallbackHostname = pageUrl.hostname.toLowerCase();
      fallbackProtocol = pageUrl.protocol.toLowerCase();
    } catch {
      // Ignore invalid fallback
    }

    return {
      actionRaw: trimmedAction ? trimmedAction.slice(0, 256) : null,
      actionOrigin: pageOrigin,
      actionHostname: fallbackHostname,
      actionProtocol: fallbackProtocol,
      method,
      hasPasswordField,
      submitsToDifferentOrigin: false,
      actionParseFailed: false,
    };
  }

  try {
    const resolved = new URL(trimmedAction, pageHref);
    const resolvedOrigin = resolved.origin;
    const resolvedHostname = resolved.hostname.toLowerCase();
    const resolvedProtocol = resolved.protocol.toLowerCase();

    return {
      actionRaw: trimmedAction.slice(0, 256),
      actionOrigin: resolvedOrigin,
      actionHostname: resolvedHostname,
      actionProtocol: resolvedProtocol,
      method,
      hasPasswordField,
      submitsToDifferentOrigin: resolvedOrigin !== pageOrigin,
      actionParseFailed: false,
    };
  } catch {
    return {
      actionRaw: trimmedAction.slice(0, 256),
      actionOrigin: 'invalid',
      actionHostname: '',
      actionProtocol: '',
      method,
      hasPasswordField,
      submitsToDifferentOrigin: false,
      actionParseFailed: true,
    };
  }
}

/**
 * Extracts minimal, structured DOM signals from the current document.
 */
export function extractPageSignalsFromDocument(doc: Document, loc: Location): PageInspectionSignals {
  const incompleteReasons: string[] = [];

  if (doc.readyState === 'loading') {
    incompleteReasons.push('Document was still loading when inspection ran');
  }

  const pageUrl = loc.href;
  const pageOrigin = loc.origin;
  const pageHostname = loc.hostname.toLowerCase();
  const pageProtocol = loc.protocol.toLowerCase();
  const documentTitle = sanitizeVisibleTextExcerpt((doc.title || '').slice(0, 200));

  // 1. Check password field existence ONLY (never access .value)
  let passwordFieldCount = 0;
  try {
    const passwordInputs = doc.querySelectorAll('input[type="password"]');
    passwordFieldCount = passwordInputs.length;
  } catch {
    incompleteReasons.push('Unable to query password input elements');
  }

  // 2. Inspect forms and their action destinations safely
  const forms: FormInspectionSignal[] = [];
  try {
    const formNodeList = doc.querySelectorAll('form');
    const totalForms = formNodeList.length;
    const limit = Math.min(totalForms, MAX_FORMS_TO_INSPECT);

    for (let i = 0; i < limit; i++) {
      const formEl = formNodeList[i];
      if (!formEl) continue;

      let formHasPwd = false;
      try {
        formHasPwd = formEl.querySelector('input[type="password"]') !== null;
      } catch {
        formHasPwd = false;
      }

      const rawAction = formEl.getAttribute('action');
      const rawMethod = formEl.getAttribute('method');
      const signal = inspectFormElement(
        rawAction,
        rawMethod,
        formHasPwd,
        pageUrl,
        pageOrigin
      );
      forms.push(signal);

      if (signal.actionParseFailed) {
        incompleteReasons.push('One or more form action attributes contained a malformed URL');
      }
    }

    if (totalForms > MAX_FORMS_TO_INSPECT) {
      incompleteReasons.push(
        `Page contains ${totalForms} forms; inspected first ${MAX_FORMS_TO_INSPECT}`
      );
    }
  } catch {
    incompleteReasons.push('Unable to inspect form elements on page');
  }

  // 3. Check for cross-origin iframes that cannot be inspected under browser Same-Origin Policy
  let crossOriginFrameCount = 0;
  try {
    const iframes = doc.querySelectorAll('iframe');
    for (let i = 0; i < iframes.length; i++) {
      const frame = iframes[i];
      if (!frame) continue;
      try {
        // Accessing contentDocument on a cross-origin iframe either returns null or throws SecurityError
        const frameDoc = frame.contentDocument;
        if (!frameDoc) {
          crossOriginFrameCount++;
        } else {
          // If same-origin iframe has a password field, count its existence without reading values
          const nestedPwd = frameDoc.querySelectorAll('input[type="password"]').length;
          passwordFieldCount += nestedPwd;
        }
      } catch {
        crossOriginFrameCount++;
      }
    }
    if (crossOriginFrameCount > 0) {
      incompleteReasons.push(
        `${crossOriginFrameCount} cross-origin iframe(s) could not be inspected due to browser origin isolation`
      );
    }
  } catch {
    // Ignore iframe enumeration errors
  }

  // 4. Collect a bounded, sanitized excerpt of visible headings/buttons/landmarks
  let visibleTextSample = '';
  try {
    const headingAndButtonNodes = doc.querySelectorAll(
      'h1, h2, h3, button, [role="heading"], label, legend'
    );
    const snippets: string[] = [];
    for (let i = 0; i < Math.min(headingAndButtonNodes.length, 30); i++) {
      const node = headingAndButtonNodes[i];
      const text = (node as HTMLElement)?.innerText || node?.textContent || '';
      const cleaned = text.trim();
      if (cleaned) {
        snippets.push(cleaned.slice(0, 120));
      }
    }
    if (snippets.length === 0 && doc.body) {
      snippets.push((doc.body.innerText || '').slice(0, MAX_VISIBLE_TEXT_LENGTH));
    }
    visibleTextSample = sanitizeVisibleTextExcerpt(snippets.join(' · '));
  } catch {
    incompleteReasons.push('Visible text sample could not be extracted');
  }

  // 5. Count anchor links and external-origin links (bounded)
  let linksCount = 0;
  let externalLinksCount = 0;
  try {
    const anchorList = doc.querySelectorAll('a[href]');
    linksCount = anchorList.length;
    const maxLinks = Math.min(anchorList.length, 200);
    for (let i = 0; i < maxLinks; i++) {
      const a = anchorList[i] as HTMLAnchorElement | undefined;
      const href = a?.getAttribute('href');
      if (!href || href.startsWith('#') || href.toLowerCase().startsWith('javascript:')) {
        continue;
      }
      try {
        const linkUrl = new URL(href, pageUrl);
        if (linkUrl.origin !== pageOrigin) {
          externalLinksCount++;
        }
      } catch {
        // Ignore unparseable href
      }
    }
  } catch {
    // Non-fatal
  }

  return {
    url: pageUrl,
    origin: pageOrigin,
    hostname: pageHostname,
    protocol: pageProtocol,
    documentTitle,
    hasPasswordField: passwordFieldCount > 0,
    passwordFieldCount,
    forms,
    visibleTextSample,
    linksCount,
    externalLinksCount,
    crossOriginFrameCount,
    incompleteInspection: incompleteReasons.length > 0,
    incompleteReasons,
    extractedAt: new Date().toISOString(),
  };
}

/**
 * Executes extraction in the browser content script context and registers
 * an idempotent message handler for explicit service-worker queries.
 */
function initContentScript(): ContentScriptExtractResponse | undefined {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return undefined;
  }

  if (
    typeof chrome !== 'undefined' &&
    chrome.runtime?.onMessage &&
    !window.__PHISHLENS_CONTENT_LISTENER_INSTALLED__
  ) {
    window.__PHISHLENS_CONTENT_LISTENER_INSTALLED__ = true;
    chrome.runtime.onMessage.addListener((message: unknown, _sender, sendResponse) => {
      if (
        message &&
        typeof message === 'object' &&
        (message as { type?: unknown }).type === 'EXTRACT_DOM_SIGNALS'
      ) {
        try {
          const signals = extractPageSignalsFromDocument(document, window.location);
          const response: ContentScriptExtractResponse = { ok: true, signals };
          sendResponse(response);
        } catch (err: unknown) {
          const response: ContentScriptExtractResponse = {
            ok: false,
            error:
              err instanceof Error
                ? err.message
                : 'Unexpected error while reading page DOM signals.',
          };
          sendResponse(response);
        }
        return false;
      }
      return false;
    });
  }

  try {
    const signals = extractPageSignalsFromDocument(document, window.location);
    return { ok: true, signals };
  } catch (err: unknown) {
    return {
      ok: false,
      error:
        err instanceof Error
          ? err.message
          : 'Failed to inspect DOM signals in content script.',
    };
  }
}

initContentScript();
