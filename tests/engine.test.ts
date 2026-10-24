/**
 * Unit Tests for PhishLens Phishing Detection Engine
 * Uses Node's built-in test runner (node:test and node:assert/strict)
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { parseAndInspectUrl, isIpHostname } from '../src/lib/analysis/url-parser.ts';
import { extractDomainFeatures, calculateLevenshteinDistance } from '../src/lib/analysis/domain-features.ts';
import { inspectTextFeatures, extractUrlsFromText } from '../src/lib/analysis/text-features.ts';
import { inspectPageFeatures } from '../src/lib/analysis/page-features.ts';
import { analyzeUrl, analyzeText, analyzePage } from '../src/lib/analysis/rule-engine.ts';
import { MockReputationProvider } from '../src/lib/analysis/reputation-provider.ts';

test('isIpHostname correctly identifies IPv4 and IPv6 hosts', () => {
  assert.equal(isIpHostname('192.168.1.1').isIp, true);
  assert.equal(isIpHostname('8.8.8.8').isIp, true);
  assert.equal(isIpHostname('256.1.1.1').isIp, false); // invalid octet
  assert.equal(isIpHostname('google.com').isIp, false);
  assert.equal(isIpHostname('127.0.0.1').isIp, true);
  assert.equal(isIpHostname('::1').isIp, true);
});

test('parseAndInspectUrl enforces HTTP/HTTPS and rejects dangerous schemes', () => {
  const dangerousJs = parseAndInspectUrl('javascript:alert("XSS")');
  assert.equal(dangerousJs.features.isValid, false);
  assert.match(dangerousJs.error || '', /Dangerous or unsupported protocol/i);

  const dangerousData = parseAndInspectUrl('data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==');
  assert.equal(dangerousData.features.isValid, false);

  const validHttps = parseAndInspectUrl('https://example.com/test?q=hello');
  assert.equal(validHttps.features.isValid, true);
  assert.equal(validHttps.features.hostname, 'example.com');
  assert.equal(validHttps.features.protocol, 'https:');
});

test('parseAndInspectUrl identifies deceptive userinfo', () => {
  const result = parseAndInspectUrl('https://paypal.com@evil-stealer.com/auth');
  assert.equal(result.features.isValid, true);
  assert.equal(result.features.hasUserInfo, true);
  assert.equal(result.features.hostname, 'evil-stealer.com');
});

test('Levenshtein distance calculation matches expected metric', () => {
  assert.equal(calculateLevenshteinDistance('paypal', 'paypa1'), 1);
  assert.equal(calculateLevenshteinDistance('apple', 'apple'), 0);
  assert.equal(calculateLevenshteinDistance('google', 'g00gle'), 2);
});

test('extractDomainFeatures detects brand impersonation across variants', () => {
  // 1. Typosquat
  const typosquat = extractDomainFeatures(parseAndInspectUrl('https://paypa1.com/login').features);
  assert.ok(typosquat.brandImpersonationMatch);
  assert.equal(typosquat.brandImpersonationMatch?.brandName, 'PayPal');

  // 2. Brand in subdomain
  const subBrand = extractDomainFeatures(parseAndInspectUrl('https://paypal.account-verify.ru/login').features);
  assert.ok(subBrand.brandImpersonationMatch);
  assert.equal(subBrand.brandImpersonationMatch?.detectedIn, 'subdomain');

  // 3. Hyphenated brand token
  const hyphenBrand = extractDomainFeatures(parseAndInspectUrl('https://apple-security-center.com/').features);
  assert.ok(hyphenBrand.brandImpersonationMatch);
  assert.equal(hyphenBrand.brandImpersonationMatch?.detectedIn, 'hyphenated_token');

  // 4. Legitimate domain should not be flagged as an impersonation
  const legit = extractDomainFeatures(parseAndInspectUrl('https://accounts.google.com/signin').features);
  assert.equal(legit.brandImpersonationMatch, undefined);
});

test('extractUrlsFromText correctly isolates embedded URLs from text', () => {
  const text = 'Notice: Your package is waiting. Go to https://parcel-tracker.top/track. Also see www.mycarrier.com/info for details.';
  const urls = extractUrlsFromText(text);
  assert.equal(urls.length, 2);
  assert.equal(urls[0], 'https://parcel-tracker.top/track');
  assert.equal(urls[1], 'https://www.mycarrier.com/info');
});

test('inspectTextFeatures identifies urgency and credential prompts', () => {
  const phishingEmail = 'Urgent Notice: Your account will be suspended within 24 hours. Click here to verify your password immediately.';
  const features = inspectTextFeatures(phishingEmail);
  assert.ok(features.urgencySignals.length > 0);
  assert.ok(features.credentialSignals.length > 0);
});

test('inspectTextFeatures flags sender domain and link destination mismatch', () => {
  const text = 'Please review your transaction: https://update-bank-security.xyz/review';
  const features = inspectTextFeatures(text, 'service@paypal.com');
  assert.ok(features.senderLinkDomainMismatch);
  assert.equal(features.senderLinkDomainMismatch?.senderDomain, 'paypal.com');
});

test('inspectPageFeatures flags external credential form posting', () => {
  const pageDom = inspectPageFeatures({
    url: 'https://login-service.org/login',
    hasPasswordField: true,
    forms: [
      {
        action: 'https://stolen-data-collector.com/receive.php',
        hasPasswordField: true,
      },
    ],
  });

  assert.equal(pageDom.features.formActions[0].isExternal, true);
  const mismatchFinding = pageDom.findings.find(f => f.code === 'PAGE_FORM_EXTERNAL_CREDENTIAL_POST');
  assert.ok(mismatchFinding);
  assert.equal(mismatchFinding?.severity, 'high');
});

test('analyzeUrl produces appropriate RiskCategory based on evidence', async () => {
  // Test 1: Brand impersonation -> SUSPICIOUS
  const suspiciousRes = await analyzeUrl('https://paypa1-security.com/verify');
  assert.equal(suspiciousRes.riskCategory, 'SUSPICIOUS');
  assert.ok(suspiciousRes.findings.length > 0);

  // Test 2: Raw IP host -> SUSPICIOUS
  const ipRes = await analyzeUrl('http://185.220.101.5/login');
  assert.equal(ipRes.riskCategory, 'SUSPICIOUS');

  // Test 3: Legitimate clean domain -> NO_EVIDENCE_FOUND
  const cleanRes = await analyzeUrl('https://example.com/about');
  assert.equal(cleanRes.riskCategory, 'NO_EVIDENCE_FOUND');
  assert.ok(cleanRes.limitations.length > 0);

  // Test 4: Mock Threat Intelligence integration
  const mockProvider = new MockReputationProvider(['https://known-malicious-feed.com/phish']);
  const threatRes = await analyzeUrl('https://known-malicious-feed.com/phish', mockProvider);
  assert.equal(threatRes.riskCategory, 'SUSPICIOUS');
  assert.ok(threatRes.findings.some(f => f.code === 'REPUTATION_FLAGGED_MALICIOUS'));
});

test('analyzeText correctly evaluates benign vs malicious messages', async () => {
  const scamMsg = 'Alert: Your package cannot be delivered due to unpaid shipping fee of $2.99. Pay at https://usps-redelivery.top/pay';
  const scamResult = await analyzeText(scamMsg, 'message');
  assert.equal(scamResult.riskCategory, 'SUSPICIOUS');

  const benignMsg = 'Hey Sam, are we still meeting tomorrow for coffee at 10 AM? Let me know!';
  const benignResult = await analyzeText(benignMsg, 'message');
  assert.equal(benignResult.riskCategory, 'NO_EVIDENCE_FOUND');
});

test('analyzePage flags brand impersonation when page claims brand on unrelated domain', async () => {
  const result = await analyzePage({
    url: 'https://security-verify-365.top/login',
    hasPasswordField: true,
    hasLoginForm: true,
    visibleTextSample: 'Sign in to your Microsoft account. Enter your password to continue.',
  });

  assert.equal(result.riskCategory, 'SUSPICIOUS');
  assert.ok(result.findings.some(f => f.code === 'PAGE_BRAND_DOM_MISMATCH'));
});

test('handles empty, whitespace-only, and invalid single-label inputs without crashing', async () => {
  const urlRes = await analyzeUrl('   ');
  assert.equal(urlRes.riskCategory, 'NOT_ANALYSED');
  assert.equal(urlRes.status, 'failed');

  const invalidHostRes = await analyzeUrl('not-a-valid-domain');
  assert.equal(invalidHostRes.riskCategory, 'NOT_ANALYSED');
  assert.equal(invalidHostRes.status, 'failed');

  const textRes = await analyzeText('   ', 'message');
  assert.equal(textRes.riskCategory, 'NOT_ANALYSED');
  assert.equal(textRes.status, 'failed');
});

test('handles multiple URLs in one message and aggregates findings', async () => {
  const multiUrlMsg = 'Check this update https://paypa1-security.com/fix and also refer to https://185.220.101.5/portal';
  const res = await analyzeText(multiUrlMsg, 'message');
  assert.equal(res.riskCategory, 'SUSPICIOUS');
  assert.ok(res.details?.extractedUrlCount === 2);
  // Both brand impersonation and IP host should be in findings
  assert.ok(res.findings.some(f => f.code === 'URL_BRAND_IMPERSONATION'));
  assert.ok(res.findings.some(f => f.code === 'URL_IP_HOST'));
});

test('handles extremely long inputs safely', async () => {
  const longText = 'Urgent notice! '.repeat(500) + 'https://example.com/login';
  const res = await analyzeText(longText, 'email');
  assert.ok(res.evaluatedAt);
  assert.ok(res.checksPerformed.length > 0);
});

