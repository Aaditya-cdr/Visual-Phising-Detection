/**
 * Core Rule Evaluation Engine for PhishLens
 * Evaluates extracted URL, text, and page signals against deterministic security heuristics.
 */

import {
  AnalysisResult,
  Finding,
  RiskCategory,
  UrlInspectionFeatures,
  TextInspectionFeatures,
  PageInspectionFeatures,
} from './types.ts';
import { parseAndInspectUrl } from './url-parser.ts';
import { extractDomainFeatures } from './domain-features.ts';
import { inspectTextFeatures } from './text-features.ts';
import { inspectPageFeatures, RawPageSignalInput } from './page-features.ts';
import { IReputationProvider, ReputationResult } from './reputation-provider.ts';

const GENERAL_LIMITATIONS =
  'Heuristic analysis inspects structural anomalies, brand lookalikes, linguistic coercion, and form targets. ' +
  'No heuristic tool can guarantee 100% safety. Emerging zero-day campaigns, compromised legitimate servers, ' +
  'or private spear-phishing lures may evade initial detection.';

/**
 * Analyzes a standalone URL string
 */
export async function analyzeUrl(
  rawUrl: string,
  reputationProvider?: IReputationProvider
): Promise<AnalysisResult> {
  const evaluatedAt = new Date().toISOString();
  const checksPerformed: string[] = [];
  const uncompletedChecks: string[] = [];
  const findings: Finding[] = [];

  // 1. URL syntax & scheme validation
  checksPerformed.push('URL syntax & protocol validation');
  const { features: parsedFeatures, error } = parseAndInspectUrl(rawUrl);

  if (error || !parsedFeatures.isValid) {
    findings.push({
      code: 'URL_INVALID_SYNTAX',
      title: 'Invalid or Disallowed URL',
      severity: 'high',
      description: error || 'The provided URL could not be safely parsed.',
      evidence: rawUrl,
      source: 'input_validation',
      passed: false,
      safeNextStep: 'Verify the full address format before interacting with this link.',
    });

    return {
      targetType: 'url',
      targetSummary: rawUrl || '(empty)',
      riskCategory: 'NOT_ANALYSED',
      status: 'failed',
      summary: 'Analysis could not proceed because the input is not a valid HTTP/HTTPS URL.',
      findings,
      checksPerformed,
      uncompletedChecks: [
        'Domain heuristics',
        'Brand impersonation check',
        'Threat intelligence query',
      ],
      recommendedNextStep: 'Check the URL spelling. Never visit URLs with unsupported or scripting protocols.',
      limitations: GENERAL_LIMITATIONS,
      evaluatedAt,
    };
  }

  // 2. Domain & brand extraction
  checksPerformed.push('Domain & public suffix extraction (tldts)');
  checksPerformed.push('IP-address hostname detection');
  checksPerformed.push('Brand impersonation & typosquatting heuristics');
  checksPerformed.push('Deceptive user-info & punycode inspection');

  const features = extractDomainFeatures(parsedFeatures);

  // Heuristic Rule 1: IP address as hostname
  if (features.isIpAddress) {
    findings.push({
      code: 'URL_IP_HOST',
      title: 'Raw IP Address Hostname',
      severity: 'high',
      description: 'The URL uses a raw numerical IP address instead of a registered domain name. Legitimate public services almost universally use domain names.',
      evidence: `Host: ${features.hostname}`,
      source: 'url_structure',
      passed: false,
      safeNextStep: 'Do not access web services hosted directly on unauthenticated IP addresses.',
    });
  }

  // Heuristic Rule 2: Deceptive Userinfo
  if (features.hasUserInfo) {
    findings.push({
      code: 'URL_DECEPTIVE_USERINFO',
      title: 'Deceptive URL Userinfo Field',
      severity: 'high',
      description: 'The URL contains user credentials or an embedded fake domain before the "@" character. Browsers ignore text before the "@" and connect to the actual host after it.',
      evidence: `Userinfo: "${features.userInfo}" pointing to host "${features.hostname}"`,
      source: 'url_structure',
      passed: false,
      safeNextStep: 'Do not trust the domain name appearing before the "@" sign. Check the actual host.',
    });
  }

  // Heuristic Rule 3: Punycode or mixed script homoglyph
  if (features.isPunycode || features.hasMixedScript) {
    findings.push({
      code: 'URL_HOMOGLYPH_PUNYCODE',
      title: 'Internationalized or Mixed-Script Hostname',
      severity: 'medium',
      description: 'The hostname contains punycode ("xn--") or mixed alphabets (e.g., Cyrillic characters resembling Latin letters) often used to spoof legitimate brand spellings.',
      evidence: `Host: "${features.hostname}"`,
      source: 'url_structure',
      passed: false,
      safeNextStep: 'Carefully verify the character set of the domain. Avoid entering account credentials.',
    });
  }

  // Heuristic Rule 4: Brand impersonation / lookalike
  if (features.brandImpersonationMatch) {
    const match = features.brandImpersonationMatch;
    let desc = `The domain exhibits patterns resembling ${match.brandName}`;
    if (match.detectedIn === 'subdomain') {
      desc = `The brand name "${match.brandName}" is placed inside a subdomain of an unrelated host ("${features.registrableDomain}"). Attackers use this to deceive users who only glance at the start of the URL.`;
    } else if (match.detectedIn === 'hyphenated_token') {
      desc = `The domain combines the brand name "${match.brandName}" with hyphens or security keywords ("${features.registrableDomain}"), a common phishing convention.`;
    } else if (match.detectedIn === 'confusable' || match.detectedIn === 'typosquat') {
      desc = `The domain name appears to be a typosquat or visual confusable mimicking "${match.brandName}".`;
    }

    findings.push({
      code: 'URL_BRAND_IMPERSONATION',
      title: `Brand Impersonation Signal (${match.brandName})`,
      severity: 'high',
      description: desc,
      evidence: `Target: "${match.brandName}", Observed host: "${features.hostname}", Registered domain: "${features.registrableDomain}"`,
      source: 'url_structure',
      passed: false,
      safeNextStep: `If you intended to reach ${match.brandName}, navigate directly to their official verified domain rather than following this link.`,
    });
  }

  // Heuristic Rule 5: Suspicious TLD combined with sensitive path
  if (features.suspiciousTld) {
    const hasSensitivePath = features.suspiciousKeywordsInPath.length > 0;
    findings.push({
      code: 'URL_SUSPICIOUS_TLD',
      title: hasSensitivePath ? 'Suspicious TLD with Login Keywords' : 'High-Abuse Disposable TLD',
      severity: hasSensitivePath ? 'high' : 'medium',
      description: `The domain uses a top-level domain frequently associated with throwaway or malicious registrations (.${features.publicSuffix}).${
        hasSensitivePath ? ` The path also requests sensitive actions: ${features.suspiciousKeywordsInPath.join(', ')}.` : ''
      }`,
      evidence: `TLD: .${features.publicSuffix}, Path keywords: ${features.suspiciousKeywordsInPath.join(', ') || 'none'}`,
      source: 'url_structure',
      passed: false,
      safeNextStep: 'Exercise caution with unfamiliar TLDs, particularly when authentication or payments are requested.',
    });
  }

  // Heuristic Rule 6: Deep subdomain structure
  if (features.subdomainDepth > 3) {
    findings.push({
      code: 'URL_EXCESSIVE_SUBDOMAINS',
      title: 'Excessive Subdomain Depth',
      severity: 'low',
      description: `The URL contains ${features.subdomainDepth} subdomain levels, which is frequently used by automated phishing kits to bypass naive domain filters.`,
      evidence: `Subdomains: ${features.subdomains.join('.')}`,
      source: 'url_structure',
      passed: false,
      safeNextStep: 'Inspect the actual primary registered domain on the far right.',
    });
  }

  // 3. Threat intelligence lookup
  let repResult: ReputationResult | undefined;
  if (reputationProvider) {
    checksPerformed.push(`Threat intelligence query (${reputationProvider.name})`);
    repResult = await reputationProvider.lookupUrl(features.originalUrl);

    if (repResult.isAvailable) {
      if (repResult.isMalicious) {
        findings.push({
          code: 'REPUTATION_FLAGGED_MALICIOUS',
          title: `Reported Malicious by ${reputationProvider.name}`,
          severity: 'high',
          description: repResult.details || 'The destination is cataloged in active threat intelligence feeds.',
          evidence: `Threat Type: ${repResult.threatType || 'Social Engineering / Phishing'}`,
          source: 'domain_reputation',
          passed: false,
          safeNextStep: 'Block and do not visit this URL. It has been flagged as malicious by verified security feeds.',
        });
      }
    } else {
      uncompletedChecks.push(`Threat intelligence query: ${repResult.details || 'Service unavailable'}`);
    }
  } else {
    uncompletedChecks.push('External Threat Intelligence lookup (no API provider configured)');
  }

  // Determine Overall Risk Category
  const hasHighSeverity = findings.some(f => f.severity === 'high');
  const hasMediumSeverity = findings.some(f => f.severity === 'medium');

  let riskCategory: RiskCategory = 'NO_EVIDENCE_FOUND';
  let summary = 'No heuristic phishing warning signs were detected in the URL structure.';
  let recommendedNextStep = 'The link did not trigger heuristic alerts, but always verify unfamiliar requests independently.';

  if (hasHighSeverity) {
    riskCategory = 'SUSPICIOUS';
    summary = 'Significant phishing or impersonation indicators were detected in this URL.';
    recommendedNextStep = 'Do NOT visit this link or enter passwords or sensitive personal details.';
  } else if (hasMediumSeverity || findings.length > 0) {
    riskCategory = 'NEEDS_REVIEW';
    summary = 'Anomalies or warning signs were identified that warrant caution before interacting.';
    recommendedNextStep = 'Inspect the destination carefully. Verify the sender through an established communication channel.';
  }

  return {
    targetType: 'url',
    targetSummary: features.hostname || rawUrl,
    riskCategory,
    status: uncompletedChecks.length > 0 ? 'partial' : 'completed',
    summary,
    findings,
    checksPerformed,
    uncompletedChecks,
    recommendedNextStep,
    limitations: GENERAL_LIMITATIONS,
    evaluatedAt,
    details: {
      hostname: features.hostname,
      registrableDomain: features.registrableDomain,
      publicSuffix: features.publicSuffix,
      protocol: features.protocol,
      subdomainDepth: features.subdomainDepth,
      isIp: features.isIpAddress,
      reputationProvider: reputationProvider?.name,
      reputationChecked: repResult?.checked ?? false,
    },
  };
}

/**
 * Analyzes email or message plain text content
 */
export async function analyzeText(
  rawText: string,
  targetType: 'email' | 'message',
  optionalSender?: string,
  reputationProvider?: IReputationProvider
): Promise<AnalysisResult> {
  const evaluatedAt = new Date().toISOString();
  const checksPerformed: string[] = [];
  const uncompletedChecks: string[] = [];
  const findings: Finding[] = [];

  const trimmed = rawText.trim();
  if (!trimmed) {
    return {
      targetType,
      targetSummary: '(empty text)',
      riskCategory: 'NOT_ANALYSED',
      status: 'failed',
      summary: 'Please provide email or message content to inspect.',
      findings: [{
        code: 'TEXT_EMPTY_INPUT',
        title: 'Empty Content',
        severity: 'info',
        description: 'No text was provided for inspection.',
        source: 'input_validation',
        passed: false,
      }],
      checksPerformed: ['Input validation'],
      uncompletedChecks: ['Linguistic urgency heuristics', 'Credential harvesting patterns', 'Link extraction'],
      recommendedNextStep: 'Paste suspicious message or email body text to inspect.',
      limitations: GENERAL_LIMITATIONS,
      evaluatedAt,
    };
  }

  checksPerformed.push('Text parsing and sanitization');
  checksPerformed.push('Linguistic urgency & coercion pattern analysis');
  checksPerformed.push('Credential harvesting prompt detection');
  checksPerformed.push('Financial & parcel delivery scam heuristics');
  checksPerformed.push('Embedded link extraction');

  const textFeatures = inspectTextFeatures(trimmed, optionalSender);

  // Finding 1: Urgency / Coercion
  if (textFeatures.urgencySignals.length > 0) {
    findings.push({
      code: 'TEXT_URGENCY_COERCION',
      title: 'Urgent Coercive Language Detected',
      severity: 'medium',
      description: 'The text employs high-pressure language (e.g. account suspension, immediate deadline) designed to induce panic and bypass critical judgment.',
      evidence: textFeatures.urgencySignals.slice(0, 3).join(' | '),
      source: 'text_heuristics',
      passed: false,
      safeNextStep: 'Take a breath. Legitimate organizations rarely demand immediate action under short countdown deadlines without prior notice.',
    });
  }

  // Finding 2: Credential harvesting prompts
  if (textFeatures.credentialSignals.length > 0) {
    findings.push({
      code: 'TEXT_CREDENTIAL_SOLICITATION',
      title: 'Credential or Security Verification Prompt',
      severity: 'high',
      description: 'The message explicitly prompts you to verify, confirm, or enter sensitive credentials, passwords, or personal identifying information.',
      evidence: textFeatures.credentialSignals.slice(0, 3).join(' | '),
      source: 'text_heuristics',
      passed: false,
      safeNextStep: 'Never provide passwords, 2FA codes, or personal records through links received in unsolicited messages.',
    });
  }

  // Finding 3: Financial or parcel scam pattern
  if (textFeatures.financialScamSignals.length > 0) {
    findings.push({
      code: 'TEXT_FINANCIAL_DELIVERY_LURE',
      title: 'Delivery Fee or Unexpected Windfall Pattern',
      severity: 'medium',
      description: 'The text references common lure pretexts such as unpaid delivery fees, unexpected refunds, prizes, or crypto distributions.',
      evidence: textFeatures.financialScamSignals.slice(0, 3).join(' | '),
      source: 'text_heuristics',
      passed: false,
      safeNextStep: 'If expecting a parcel or invoice, check directly in the carrier’s official app or account dashboard—not via message links.',
    });
  }

  // Finding 4: Threat patterns
  if (textFeatures.threatSignals.length > 0) {
    findings.push({
      code: 'TEXT_PUNITIVE_THREAT',
      title: 'Intimidation or Legal Threat Phrasing',
      severity: 'high',
      description: 'The text uses threatening claims regarding law enforcement, legal action, or sudden punitive penalties to provoke hasty compliance.',
      evidence: textFeatures.threatSignals.slice(0, 2).join(' | '),
      source: 'text_heuristics',
      passed: false,
      safeNextStep: 'Official legal notifications are not served via informal SMS or unsolicited emails with urgent web links.',
    });
  }

  // Finding 5: Sender vs Link Domain Mismatch
  if (textFeatures.senderLinkDomainMismatch) {
    const { senderDomain, linkDomains } = textFeatures.senderLinkDomainMismatch;
    findings.push({
      code: 'EMAIL_SENDER_LINK_MISMATCH',
      title: 'Sender Domain and Link Destination Conflict',
      severity: 'high',
      description: `The message sender claims to be from "${senderDomain}", but links inside the body direct traffic to unrelated domain(s): ${linkDomains.join(', ')}.`,
      evidence: `Sender: ${senderDomain} vs Links: ${linkDomains.join(', ')}`,
      source: 'text_heuristics',
      passed: false,
      safeNextStep: 'Do not follow links in emails where the destination domain conflicts with the purported sender organization.',
    });
  }

  // Analyze extracted URLs inside the text
  const urlResults: AnalysisResult[] = [];
  if (textFeatures.extractedUrls.length > 0) {
    checksPerformed.push(`Embedded URL analysis (${textFeatures.extractedUrls.length} link${textFeatures.extractedUrls.length > 1 ? 's' : ''} found)`);
    for (const url of textFeatures.extractedUrls.slice(0, 3)) {
      const uRes = await analyzeUrl(url, reputationProvider);
      urlResults.push(uRes);
      // Propagate high-severity findings from embedded URLs
      for (const uf of uRes.findings) {
        if (!findings.some(f => f.code === uf.code && f.evidence === uf.evidence)) {
          findings.push(uf);
        }
      }
      for (const uc of uRes.uncompletedChecks) {
        if (!uncompletedChecks.includes(uc)) {
          uncompletedChecks.push(uc);
        }
      }
    }
  } else {
    checksPerformed.push('Embedded link check: No web links detected in message body');
  }

  const hasHighSeverity = findings.some(f => f.severity === 'high');
  const hasMediumSeverity = findings.some(f => f.severity === 'medium');

  let riskCategory: RiskCategory = 'NO_EVIDENCE_FOUND';
  let summary = 'No prominent phishing keywords or deceptive links were identified.';
  let recommendedNextStep = 'The content does not match common phishing templates, but exercise caution if the sender is unknown.';

  if (hasHighSeverity) {
    riskCategory = 'SUSPICIOUS';
    summary = 'Multiple strong warning signals (credential solicitations, sender conflicts, or suspicious links) were identified.';
    recommendedNextStep = 'Do NOT reply, follow links, or provide requested information. Report or delete this message.';
  } else if (hasMediumSeverity) {
    riskCategory = 'NEEDS_REVIEW';
    summary = 'Urgency or lure patterns were detected in the text that warrant independent verification.';
    recommendedNextStep = 'Contact the purported sender organization via their official publicly listed telephone number or portal.';
  }

  return {
    targetType,
    targetSummary: `${trimmed.slice(0, 60)}${trimmed.length > 60 ? '...' : ''}`,
    riskCategory,
    status: uncompletedChecks.length > 0 ? 'partial' : 'completed',
    summary,
    findings,
    checksPerformed,
    uncompletedChecks,
    recommendedNextStep,
    limitations: GENERAL_LIMITATIONS,
    evaluatedAt,
    details: {
      characterCount: textFeatures.characterCount,
      extractedUrlCount: textFeatures.extractedUrls.length,
      extractedUrls: textFeatures.extractedUrls,
      senderEmail: textFeatures.senderEmail,
      senderDomain: textFeatures.senderDomain,
    },
  };
}

/**
 * Analyzes webpage DOM signals (e.g. from Chrome extension or server-side DOM inspector)
 */
export async function analyzePage(
  pageInput: RawPageSignalInput,
  reputationProvider?: IReputationProvider
): Promise<AnalysisResult> {
  const evaluatedAt = new Date().toISOString();
  const checksPerformed: string[] = [
    'Page origin & hostname evaluation',
    'Credential input field inspection',
    'Form submission destination analysis',
    'Visible brand vs domain consistency',
  ];
  const uncompletedChecks: string[] = [];

  // Run DOM feature inspection
  const { features, findings: pageFindings } = inspectPageFeatures(pageInput);
  const findings: Finding[] = [...pageFindings];

  // Also analyze the page URL itself
  const urlAnalysis = await analyzeUrl(pageInput.url, reputationProvider);
  for (const uf of urlAnalysis.findings) {
    if (!findings.some(f => f.code === uf.code)) {
      findings.push(uf);
    }
  }

  for (const check of urlAnalysis.checksPerformed) {
    if (!checksPerformed.includes(check)) checksPerformed.push(check);
  }
  for (const uncheck of urlAnalysis.uncompletedChecks) {
    if (!uncompletedChecks.includes(uncheck)) uncompletedChecks.push(uncheck);
  }

  const hasHighSeverity = findings.some(f => f.severity === 'high');
  const hasMediumSeverity = findings.some(f => f.severity === 'medium');

  let riskCategory: RiskCategory = 'NO_EVIDENCE_FOUND';
  let summary = 'No critical DOM or domain phishing indicators observed on this page.';
  let recommendedNextStep = 'Review browser address bar to ensure you are on the intended site before submitting data.';

  if (hasHighSeverity) {
    riskCategory = 'SUSPICIOUS';
    summary = 'Critical security risks identified (external credential submission or brand impersonation).';
    recommendedNextStep = 'Do NOT enter login credentials or submit forms on this webpage.';
  } else if (hasMediumSeverity || findings.length > 0) {
    riskCategory = 'NEEDS_REVIEW';
    summary = 'Page features present warning signs that deserve manual inspection.';
    recommendedNextStep = 'Verify the authenticity of the site before interacting with form inputs.';
  }

  return {
    targetType: 'page',
    targetSummary: features.pageHostname || pageInput.url,
    riskCategory,
    status: uncompletedChecks.length > 0 ? 'partial' : 'completed',
    summary,
    findings,
    checksPerformed,
    uncompletedChecks,
    recommendedNextStep,
    limitations: GENERAL_LIMITATIONS,
    evaluatedAt,
    details: {
      hasPasswordField: features.hasPasswordField,
      hasLoginForm: features.hasLoginForm,
      formActionsCount: features.formActions.length,
      visibleBrandTextMatches: features.visibleBrandTextMatches,
    },
  };
}
