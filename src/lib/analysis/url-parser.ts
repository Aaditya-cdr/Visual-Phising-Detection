/**
 * URL Parsing, normalization, and structural signal extraction.
 * Uses WHATWG URL API and strict schema verification.
 */

import { UrlInspectionFeatures } from './types.ts';

const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);
const DISALLOWED_DANGEROUS_PROTOCOLS = new Set(['javascript:', 'data:', 'file:', 'vbscript:', 'blob:']);

const SUSPICIOUS_PATH_KEYWORDS = [
  'login', 'signin', 'sign-in', 'log-in',
  'verify', 'verification', 'authenticate',
  'update-billing', 'secure-account', 'banking',
  'recover', 'wallet-connect', 'seed-phrase',
  'reset-password', 'confirm-identity', '2fa'
];

/**
 * Checks if a hostname represents an IP address (IPv4 or IPv6)
 */
export function isIpHostname(hostname: string): { isIp: boolean; version?: 'v4' | 'v6' } {
  // Strip IPv6 brackets if present
  const clean = hostname.replace(/^\[|\]$/g, '');

  // IPv4 regex (standard dot-decimal 0.0.0.0 to 255.255.255.255)
  const ipv4Pattern = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
  if (ipv4Pattern.test(clean)) {
    return { isIp: true, version: 'v4' };
  }

  // IPv6 pattern
  const ipv6Pattern = /^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$|^::1$|^[a-fA-F0-9:]+$/;
  if (clean.includes(':') && ipv6Pattern.test(clean)) {
    return { isIp: true, version: 'v6' };
  }

  // Dword / decimal IP representation check (e.g. 2130706433 = 127.0.0.1)
  if (/^\d{8,10}$/.test(clean)) {
    const num = Number(clean);
    if (!isNaN(num) && num > 0 && num <= 4294967295) {
      return { isIp: true, version: 'v4' };
    }
  }

  return { isIp: false };
}

/**
 * Checks if a string contains mixed scripts (e.g., Cyrillic characters mixed with Latin)
 */
export function detectMixedScript(text: string): boolean {
  const hasLatin = /[a-zA-Z]/.test(text);
  // Cyrillic unicode block: \u0400-\u04FF
  const hasCyrillic = /[\u0400-\u04FF]/.test(text);
  // Greek unicode block: \u0370-\u03FF
  const hasGreek = /[\u0370-\u03FF]/.test(text);

  return (hasLatin && hasCyrillic) || (hasLatin && hasGreek);
}

/**
 * Parses and extracts structural features from an input URL string
 */
export function parseAndInspectUrl(rawUrl: string): {
  features: UrlInspectionFeatures;
  error?: string;
} {
  const trimmed = rawUrl.trim();
  if (!trimmed) {
    return {
      features: {
        originalUrl: rawUrl,
        isValid: false,
        hasUserInfo: false,
        isIpAddress: false,
        isPunycode: false,
        hasMixedScript: false,
        subdomains: [],
        subdomainDepth: 0,
        suspiciousTld: false,
        suspiciousKeywordsInPath: [],
      },
      error: 'URL cannot be empty.',
    };
  }

  // Check dangerous schemes explicitly
  const lowerPrefix = trimmed.toLowerCase();
  for (const proto of DISALLOWED_DANGEROUS_PROTOCOLS) {
    if (lowerPrefix.startsWith(proto)) {
      return {
        features: {
          originalUrl: trimmed,
          isValid: false,
          hasUserInfo: false,
          isIpAddress: false,
          isPunycode: false,
          hasMixedScript: false,
          subdomains: [],
          subdomainDepth: 0,
          suspiciousTld: false,
          suspiciousKeywordsInPath: [],
        },
        error: `Dangerous or unsupported protocol "${proto}". Only http and https URLs are inspected.`,
      };
    }
  }

  // If user entered e.g. "example.com" without scheme, prepend https:// for inspection
  let normalizedUrlString = trimmed;
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed)) {
    normalizedUrlString = `https://${trimmed}`;
  }

  let parsed: URL;
  try {
    parsed = new URL(normalizedUrlString);
  } catch (err: unknown) {
    return {
      features: {
        originalUrl: trimmed,
        isValid: false,
        hasUserInfo: false,
        isIpAddress: false,
        isPunycode: false,
        hasMixedScript: false,
        subdomains: [],
        subdomainDepth: 0,
        suspiciousTld: false,
        suspiciousKeywordsInPath: [],
      },
      error: `Invalid URL format: ${err instanceof Error ? err.message : 'Unable to parse URL'}`,
    };
  }

  if (!ALLOWED_PROTOCOLS.has(parsed.protocol)) {
    return {
      features: {
        originalUrl: trimmed,
        isValid: false,
        protocol: parsed.protocol,
        hasUserInfo: false,
        isIpAddress: false,
        isPunycode: false,
        hasMixedScript: false,
        subdomains: [],
        subdomainDepth: 0,
        suspiciousTld: false,
        suspiciousKeywordsInPath: [],
      },
      error: `Unsupported protocol "${parsed.protocol}". Only HTTP and HTTPS are permitted.`,
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const { isIp, version } = isIpHostname(hostname);

  // Reject single-label hostnames without a TLD (unless IP or localhost)
  if (!isIp && hostname !== 'localhost' && (!hostname.includes('.') || hostname.startsWith('.') || hostname.endsWith('.'))) {
    return {
      features: {
        originalUrl: trimmed,
        isValid: false,
        protocol: parsed.protocol,
        hostname,
        hasUserInfo: false,
        isIpAddress: false,
        isPunycode: false,
        hasMixedScript: false,
        subdomains: [],
        subdomainDepth: 0,
        suspiciousTld: false,
        suspiciousKeywordsInPath: [],
      },
      error: 'Invalid hostname: please enter a complete domain name (e.g., example.com) or IP address.',
    };
  }

  // Check for deceptive userinfo (e.g. user:pass@host or https://google.com@evil.com)
  const hasUserInfo = Boolean(parsed.username || parsed.password);
  const userInfo = hasUserInfo ? `${parsed.username}${parsed.password ? `:${parsed.password}` : ''}` : undefined;

  // Punycode check: starts with xn-- in any hostname segment
  const isPunycode = hostname.split('.').some(seg => seg.startsWith('xn--'));

  // Mixed script detection
  const hasMixedScript = detectMixedScript(hostname);

  // Suspicious path & query keywords
  const fullPathAndQuery = `${parsed.pathname}${parsed.search}`.toLowerCase();
  const matchedKeywords = SUSPICIOUS_PATH_KEYWORDS.filter(kw => fullPathAndQuery.includes(kw));

  return {
    features: {
      originalUrl: trimmed,
      isValid: true,
      protocol: parsed.protocol,
      hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? '443' : '80'),
      pathname: parsed.pathname,
      search: parsed.search,
      hasUserInfo,
      userInfo,
      isIpAddress: isIp,
      ipVersion: version,
      isPunycode,
      hasMixedScript,
      subdomains: [],
      subdomainDepth: 0,
      suspiciousTld: false,
      suspiciousKeywordsInPath: matchedKeywords,
    },
  };
}
