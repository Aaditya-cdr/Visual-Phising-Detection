/**
 * PhishLens Chrome Extension — Domain Parsing & URL Inspection Readiness
 * Uses tldts to extract registrable domains and public suffixes cleanly,
 * decoupled from UI rendering and DOM extraction.
 */

import { parse } from 'tldts';
import { InspectionError, ParsedDomainInfo } from './types.ts';

const RESTRICTED_PROTOCOLS = new Set([
  'chrome:',
  'chrome-extension:',
  'chrome-search:',
  'chrome-untrusted:',
  'devtools:',
  'edge:',
  'about:',
  'view-source:',
  'moz-extension:',
  'javascript:',
  'data:',
  'file:',
  'blob:',
]);

const RESTRICTED_HOSTS = new Set([
  'chromewebstore.google.com',
  'chrome.google.com',
  'microsoftedge.microsoft.com',
]);

/**
 * Checks if a tab URL is a restricted browser page or unsupported scheme where
 * Chrome forbids content script injection.
 */
export function checkUrlInspectability(rawUrl: string | undefined | null): {
  canInspect: boolean;
  error?: InspectionError;
} {
  if (!rawUrl || !rawUrl.trim()) {
    return {
      canInspect: false,
      error: {
        code: 'MISSING_TAB_URL',
        title: 'Tab URL Unavailable',
        message:
          'The active tab does not expose a readable URL. Open a standard HTTP or HTTPS webpage and try again.',
        recoverable: false,
      },
    };
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(rawUrl);
  } catch {
    return {
      canInspect: false,
      error: {
        code: 'MISSING_TAB_URL',
        title: 'Invalid Tab Address',
        message: 'The active tab address could not be parsed as a valid URL.',
        recoverable: false,
      },
    };
  }

  const protocol = parsedUrl.protocol.toLowerCase();

  if (RESTRICTED_PROTOCOLS.has(protocol)) {
    return {
      canInspect: false,
      error: {
        code: 'RESTRICTED_BROWSER_PAGE',
        title: 'Browser Internal Page',
        message: `Chrome restricts extensions from inspecting internal "${protocol}//" pages. Switch to an HTTP or HTTPS website to run PhishLens.`,
        recoverable: false,
      },
    };
  }

  if (protocol !== 'http:' && protocol !== 'https:') {
    return {
      canInspect: false,
      error: {
        code: 'UNSUPPORTED_PROTOCOL',
        title: 'Unsupported Protocol',
        message: `Only http:// and https:// webpages can be inspected (current scheme: ${protocol}).`,
        recoverable: false,
      },
    };
  }

  const host = parsedUrl.hostname.toLowerCase();
  if (
    RESTRICTED_HOSTS.has(host) &&
    (host !== 'chrome.google.com' || parsedUrl.pathname.startsWith('/webstore'))
  ) {
    return {
      canInspect: false,
      error: {
        code: 'RESTRICTED_BROWSER_PAGE',
        title: 'Restricted Extension Store Page',
        message:
          'Browsers block extensions from running scripts on extension store pages for security reasons.',
        recoverable: false,
      },
    };
  }

  return { canInspect: true };
}

/**
 * Parses a URL or hostname using tldts to extract the registrable domain,
 * public suffix, and structural attributes.
 */
export function parseDomainWithTldts(rawUrl: string): ParsedDomainInfo {
  let urlObj: URL;
  try {
    urlObj = new URL(rawUrl);
  } catch {
    return {
      rawUrl,
      isValidUrl: false,
      protocol: '',
      origin: '',
      hostname: '',
      registrableDomain: null,
      publicSuffix: null,
      subdomain: null,
      subdomainDepth: 0,
      isIp: false,
      isLocalhostOrPrivate: false,
      hasUserInfo: false,
      isPunycode: false,
    };
  }

  const hostname = urlObj.hostname.toLowerCase();
  const tldInfo = parse(hostname, { allowPrivateDomains: true });

  const isIp = Boolean(tldInfo.isIp);
  const isLocalhostOrPrivate =
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '0.0.0.0' ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal');

  const subdomain = tldInfo.subdomain ? tldInfo.subdomain : null;
  const subdomainDepth = subdomain
    ? subdomain.split('.').filter(Boolean).length
    : 0;

  const registrableDomain =
    tldInfo.domain || (isLocalhostOrPrivate || isIp ? hostname : null);

  const isPunycode =
    hostname.startsWith('xn--') || hostname.includes('.xn--');

  const hasUserInfo = Boolean(urlObj.username || urlObj.password);

  return {
    rawUrl,
    isValidUrl: true,
    protocol: urlObj.protocol.toLowerCase(),
    origin: urlObj.origin,
    hostname,
    registrableDomain,
    publicSuffix: tldInfo.publicSuffix || null,
    subdomain,
    subdomainDepth,
    isIp,
    isLocalhostOrPrivate,
    hasUserInfo,
    isPunycode,
  };
}

/**
 * Compares two hostnames or URLs and returns whether they share the same
 * registrable domain according to tldts.
 */
export function hasSameRegistrableDomain(urlOrHostA: string, urlOrHostB: string): boolean {
  const normalizedA = urlOrHostA.includes('://') ? urlOrHostA : `https://${urlOrHostA}`;
  const normalizedB = urlOrHostB.includes('://') ? urlOrHostB : `https://${urlOrHostB}`;

  const parsedA = parseDomainWithTldts(normalizedA);
  const parsedB = parseDomainWithTldts(normalizedB);

  if (!parsedA.hostname || !parsedB.hostname) return false;
  if (parsedA.hostname === parsedB.hostname) return true;

  if (parsedA.registrableDomain && parsedB.registrableDomain) {
    return parsedA.registrableDomain === parsedB.registrableDomain;
  }

  return false;
}
