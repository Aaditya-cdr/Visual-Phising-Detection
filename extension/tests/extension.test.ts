import test from 'node:test';
import assert from 'node:assert/strict';
import {
  checkUrlInspectability,
  hasSameRegistrableDomain,
  parseDomainWithTldts,
} from '../src/shared/domain-parser.ts';
import { evaluatePageSignals } from '../src/shared/evaluator.ts';
import {
  inspectFormElement,
  sanitizeVisibleTextExcerpt,
} from '../src/content/inspect-page.ts';
import {
  isValidContentScriptResponse,
  isValidExtensionRequest,
  PageInspectionSignals,
} from '../src/shared/types.ts';

function createBaseSignals(overrides: Partial<PageInspectionSignals> = {}): PageInspectionSignals {
  return {
    url: 'https://app.example.com/login',
    origin: 'https://app.example.com',
    hostname: 'app.example.com',
    protocol: 'https:',
    documentTitle: 'Example Workspace Sign In',
    hasPasswordField: false,
    passwordFieldCount: 0,
    forms: [],
    visibleTextSample: 'Welcome to Example Workspace',
    linksCount: 4,
    externalLinksCount: 0,
    crossOriginFrameCount: 0,
    incompleteInspection: false,
    incompleteReasons: [],
    extractedAt: '2026-10-23T17:00:00.000Z',
    ...overrides,
  };
}

test('tldts domain parser extracts registrable domain, public suffix, and subdomain', () => {
  const parsed = parseDomainWithTldts('https://login.portal.company.co.uk/auth?next=1');
  assert.equal(parsed.isValidUrl, true);
  assert.equal(parsed.hostname, 'login.portal.company.co.uk');
  assert.equal(parsed.registrableDomain, 'company.co.uk');
  assert.equal(parsed.publicSuffix, 'co.uk');
  assert.equal(parsed.subdomain, 'login.portal');
  assert.equal(parsed.subdomainDepth, 2);
  assert.equal(parsed.isIp, false);
});

test('hasSameRegistrableDomain compares subdomains within the same registrable boundary', () => {
  assert.equal(
    hasSameRegistrableDomain('https://app.acme.org', 'https://auth.acme.org'),
    true
  );
  assert.equal(
    hasSameRegistrableDomain('https://app.acme.org', 'https://auth.other-domain.org'),
    false
  );
});

test('checkUrlInspectability rejects restricted browser pages and allows standard http/https', () => {
  assert.equal(checkUrlInspectability('https://example.com/login').canInspect, true);
  assert.equal(checkUrlInspectability('http://intranet.example.com').canInspect, true);

  const chromePage = checkUrlInspectability('chrome://extensions');
  assert.equal(chromePage.canInspect, false);
  assert.equal(chromePage.error?.code, 'RESTRICTED_BROWSER_PAGE');

  const webStore = checkUrlInspectability('https://chromewebstore.google.com/detail/foo');
  assert.equal(webStore.canInspect, false);
  assert.equal(webStore.error?.code, 'RESTRICTED_BROWSER_PAGE');

  const blankPage = checkUrlInspectability('about:blank');
  assert.equal(blankPage.canInspect, false);
  assert.equal(blankPage.error?.code, 'RESTRICTED_BROWSER_PAGE');
});

test('sanitizeVisibleTextExcerpt strips email addresses and long digit sequences', () => {
  const dirty = 'Sign in for alice.smith@company.org or call 4155550199 now';
  const cleaned = sanitizeVisibleTextExcerpt(dirty);
  assert.equal(cleaned.includes('alice.smith@company.org'), false);
  assert.equal(cleaned.includes('4155550199'), false);
  assert.equal(cleaned.includes('[redacted-email]'), true);
});

test('evaluator does NOT flag unfamiliar domains, password fields, long URLs, or external non-password forms as phishing', () => {
  // 1. Unfamiliar domain with a password field + long URL + external search form (no password in external form)
  const searchForm = inspectFormElement(
    'https://www.duckduckgo.com/',
    'GET',
    false,
    'https://unfamiliar-indie-project-2026.io/account/login?session_token_ref=abcdefghijklmnopqrstuvwxyz0123456789',
    'https://unfamiliar-indie-project-2026.io'
  );
  const sameOriginLoginForm = inspectFormElement(
    '/api/login',
    'POST',
    true,
    'https://unfamiliar-indie-project-2026.io/account/login',
    'https://unfamiliar-indie-project-2026.io'
  );

  const signals = createBaseSignals({
    url: 'https://unfamiliar-indie-project-2026.io/account/login?session_token_ref=abcdefghijklmnopqrstuvwxyz0123456789',
    origin: 'https://unfamiliar-indie-project-2026.io',
    hostname: 'unfamiliar-indie-project-2026.io',
    hasPasswordField: true,
    passwordFieldCount: 1,
    forms: [searchForm, sameOriginLoginForm],
    visibleTextSample: 'Indie Project Member Sign In',
  });

  const report = evaluatePageSignals(signals, {
    backendStatus: 'not_connected',
    reputationStatus: 'not_connected',
  });

  assert.equal(report.riskCategory, 'NO_EVIDENCE_FOUND');
  assert.equal(report.findings.length, 0);
  assert.equal(report.observations.some(o => o.id === 'obs-password'), true);
  assert.equal(report.backendStatus, 'not_connected');
  assert.equal(
    report.checksUnavailable.some(c => c.includes('PhishLens backend API not connected')),
    true
  );
});

test('evaluator marks cross-domain password form submission as NEEDS_REVIEW rather than blind false-positive', () => {
  const crossDomainPwdForm = inspectFormElement(
    'https://sso-provider.auth-service.net/oauth/login',
    'POST',
    true,
    'https://portal.customer-site.com/login',
    'https://portal.customer-site.com'
  );

  const signals = createBaseSignals({
    url: 'https://portal.customer-site.com/login',
    origin: 'https://portal.customer-site.com',
    hostname: 'portal.customer-site.com',
    hasPasswordField: true,
    passwordFieldCount: 1,
    forms: [crossDomainPwdForm],
    visibleTextSample: 'Customer Portal Login',
  });

  const report = evaluatePageSignals(signals);
  assert.equal(report.riskCategory, 'NEEDS_REVIEW');
  assert.equal(
    report.findings.some(f => f.code === 'CROSS_DOMAIN_PASSWORD_SUBMISSION'),
    true
  );
});

test('evaluator marks brand impersonation on a password page hosted on an unrelated domain as SUSPICIOUS', () => {
  const signals = createBaseSignals({
    url: 'https://account-verify-session.net/signin',
    origin: 'https://account-verify-session.net',
    hostname: 'account-verify-session.net',
    documentTitle: 'Log in to your PayPal account',
    hasPasswordField: true,
    passwordFieldCount: 1,
    visibleTextSample: 'Log in to your PayPal account · Continue',
  });

  const report = evaluatePageSignals(signals);
  assert.equal(report.riskCategory, 'SUSPICIOUS');
  assert.equal(
    report.findings.some(f => f.code === 'PAGE_BRAND_CREDENTIAL_MISMATCH'),
    true
  );
});

test('message type guards validate extension and content script payloads strictly', () => {
  assert.equal(isValidExtensionRequest({ type: 'GET_ACTIVE_TAB_CONTEXT' }), true);
  assert.equal(isValidExtensionRequest({ type: 'ANALYSE_ACTIVE_TAB' }), true);
  assert.equal(isValidExtensionRequest({ type: 'UNKNOWN_COMMAND' }), false);
  assert.equal(isValidExtensionRequest(null), false);

  const validSignals = createBaseSignals();
  assert.equal(
    isValidContentScriptResponse({ ok: true, signals: validSignals }),
    true
  );
  assert.equal(
    isValidContentScriptResponse({ ok: false, error: 'Blocked by policy' }),
    true
  );
  assert.equal(isValidContentScriptResponse({ ok: true, signals: {} }), false);
});
