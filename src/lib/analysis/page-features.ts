/**
 * Webpage DOM feature extraction and credential form destination analysis.
 * Used by the Chrome Extension and web page inspection route.
 */

import { parse } from 'tldts';
import { PageInspectionFeatures, Finding } from './types.ts';
import { KNOWN_BRANDS } from './domain-features.ts';

export interface RawPageSignalInput {
  url: string;
  hasPasswordField?: boolean;
  hasLoginForm?: boolean;
  forms?: Array<{
    action?: string;
    method?: string;
    hasPasswordField?: boolean;
    inputCount?: number;
  }>;
  visibleTextSample?: string;
  linksCount?: number;
  externalLinksCount?: number;
}

/**
 * Inspects webpage DOM signals for credential theft and form hijack heuristics
 */
export function inspectPageFeatures(input: RawPageSignalInput): {
  features: PageInspectionFeatures;
  findings: Finding[];
} {
  let pageUrl: URL;
  try {
    pageUrl = new URL(input.url);
  } catch {
    pageUrl = new URL('https://unknown-target.local');
  }

  const pageOrigin = pageUrl.origin;
  const pageHostname = pageUrl.hostname.toLowerCase();
  const pageDomain = parse(pageHostname).domain || pageHostname;

  const rawForms = input.forms || [];
  const formActions: PageInspectionFeatures['formActions'] = [];
  const findings: Finding[] = [];

  let anyExternalCredentialForm = false;
  let anyInsecureSubmission = false;

  for (const form of rawForms) {
    const rawAction = form.action || '';
    let resolvedActionUrl = rawAction;
    let actionDomain = pageDomain;
    let isExternal = false;
    let isHttpOnHttps = false;

    if (rawAction && !rawAction.startsWith('#') && !rawAction.startsWith('javascript:')) {
      try {
        const parsedAction = new URL(rawAction, pageOrigin);
        resolvedActionUrl = parsedAction.href;
        const parsedActionDomain = parse(parsedAction.hostname).domain || parsedAction.hostname.toLowerCase();
        actionDomain = parsedActionDomain;

        if (parsedActionDomain && parsedActionDomain !== pageDomain) {
          isExternal = true;
        }

        if (pageUrl.protocol === 'https:' && parsedAction.protocol === 'http:') {
          isHttpOnHttps = true;
        }
      } catch {
        // Leave defaults if unparseable
      }
    }

    const formHasPassword = Boolean(form.hasPasswordField || input.hasPasswordField);

    formActions.push({
      actionUrl: resolvedActionUrl,
      actionDomain,
      isExternal,
      isHttpOnHttps,
      hasPasswordField: formHasPassword,
    });

    if (isExternal && formHasPassword) {
      anyExternalCredentialForm = true;
    }
    if (isHttpOnHttps && formHasPassword) {
      anyInsecureSubmission = true;
    }
  }

  // Check if page claims a brand name in visible text that differs from page domain
  const visibleText = (input.visibleTextSample || '').toLowerCase();
  const visibleBrandTextMatches: string[] = [];

  for (const brand of KNOWN_BRANDS) {
    const isBrandMentioned = visibleText.includes(brand.name.toLowerCase()) || visibleText.includes(brand.canonicalSlug);
    if (isBrandMentioned) {
      const isDomainAffiliated = brand.legitimateDomains.some(legit => pageDomain === legit || pageHostname.endsWith(`.${legit}`));
      if (!isDomainAffiliated) {
        visibleBrandTextMatches.push(brand.name);
      }
    }
  }

  // Generate specific DOM findings
  if (anyExternalCredentialForm) {
    findings.push({
      code: 'PAGE_FORM_EXTERNAL_CREDENTIAL_POST',
      title: 'Credential Form Destination Mismatch',
      severity: 'high',
      description: 'A password or login form on this page posts credentials to a completely different external domain than the current site.',
      evidence: `Page domain: "${pageDomain}" posts login credentials to external action target domain(s).`,
      source: 'page_dom',
      passed: false,
      safeNextStep: 'Do NOT submit your credentials on this page. Legitimate services authenticate within their own verified domains.',
    });
  }

  if (anyInsecureSubmission) {
    findings.push({
      code: 'PAGE_INSECURE_HTTP_CREDENTIAL_POST',
      title: 'Insecure Login Transmission (Unencrypted HTTP)',
      severity: 'high',
      description: 'A password form transmits data across unencrypted HTTP, exposing credentials to interception.',
      evidence: 'Password form action uses unencrypted http: protocol.',
      source: 'page_dom',
      passed: false,
      safeNextStep: 'Never submit passwords over unencrypted HTTP.',
    });
  }

  if (visibleBrandTextMatches.length > 0 && (input.hasPasswordField || input.hasLoginForm)) {
    findings.push({
      code: 'PAGE_BRAND_DOM_MISMATCH',
      title: 'Brand Impersonation in Login Interface',
      severity: 'high',
      description: `The page content references recognized brand(s) (${visibleBrandTextMatches.join(', ')}), but the site is hosted on unrelated domain "${pageDomain}".`,
      evidence: `Visible text refers to ${visibleBrandTextMatches.join(', ')}, but host is "${pageHostname}".`,
      source: 'page_dom',
      passed: false,
      safeNextStep: 'Exit this page. Visit the official website directly by typing the brand name into your browser bookmarks.',
    });
  }

  return {
    features: {
      url: input.url,
      pageOrigin,
      pageHostname,
      hasPasswordField: Boolean(input.hasPasswordField),
      hasLoginForm: Boolean(input.hasLoginForm),
      formActions,
      visibleBrandTextMatches,
      linksCount: input.linksCount || 0,
      externalLinksCount: input.externalLinksCount || 0,
    },
    findings,
  };
}
