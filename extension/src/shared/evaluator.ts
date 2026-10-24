/**
 * PhishLens Chrome Extension — Signal Evaluation & Detection Readiness
 *
 * Separates neutral extracted observations from risk conclusions.
 * Does NOT flag a website as phishing solely due to:
 *  - An unfamiliar domain
 *  - A password field
 *  - HTTPS usage
 *  - An external form destination (when not harvesting credentials or spoofing a brand)
 *  - A long URL
 */

import { hasSameRegistrableDomain, parseDomainWithTldts } from './domain-parser.ts';
import {
  BackendConnectionState,
  InspectionFinding,
  InspectionRiskCategory,
  PageAnalysisReport,
  PageInspectionSignals,
  PageObservation,
  ReputationLookupState,
} from './types.ts';

interface BrandProfile {
  name: string;
  keywords: string[];
  officialDomains: string[];
}

const MONITORED_BRANDS: BrandProfile[] = [
  {
    name: 'PayPal',
    keywords: ['paypal', 'paypal inc', 'log in to your paypal'],
    officialDomains: ['paypal.com', 'paypalobjects.com'],
  },
  {
    name: 'Microsoft',
    keywords: ['microsoft', 'office 365', 'microsoft 365', 'outlook', 'onedrive'],
    officialDomains: [
      'microsoft.com',
      'live.com',
      'office.com',
      'office365.com',
      'microsoftonline.com',
      'azure.com',
      'sharepoint.com',
    ],
  },
  {
    name: 'Google',
    keywords: ['google account', 'sign in with google', 'gmail', 'google workspace'],
    officialDomains: ['google.com', 'gmail.com', 'youtube.com', 'googleapis.com'],
  },
  {
    name: 'Apple',
    keywords: ['apple id', 'icloud', 'sign in to apple'],
    officialDomains: ['apple.com', 'icloud.com'],
  },
  {
    name: 'Amazon',
    keywords: ['amazon sign-in', 'amazon.com', 'aws management console'],
    officialDomains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.in', 'aws.amazon.com'],
  },
  {
    name: 'GitHub',
    keywords: ['sign in to github', 'github.com'],
    officialDomains: ['github.com', 'githubusercontent.com'],
  },
];

/**
 * Evaluates extracted page DOM signals and domain structure into neutral
 * observations and evidence-backed findings.
 */
export function evaluatePageSignals(
  signals: PageInspectionSignals,
  options?: {
    backendStatus?: BackendConnectionState;
    reputationStatus?: ReputationLookupState;
    backendFindings?: InspectionFinding[];
    backendUncompletedChecks?: string[];
  }
): PageAnalysisReport {
  const domainInfo = parseDomainWithTldts(signals.url);
  const observations: PageObservation[] = [];
  const findings: InspectionFinding[] = [];
  const checksCompleted: string[] = [
    'Registrable domain parsing (tldts)',
    'Active DOM form & credential field inspection',
    'Cross-origin form target resolution',
    'Visible brand vs. domain consistency check',
  ];
  const checksUnavailable: string[] = [];

  // 1. Record neutral observations (factual attributes of the page)
  observations.push({
    id: 'obs-domain',
    label: 'Registrable domain',
    value: domainInfo.registrableDomain || domainInfo.hostname || 'Unknown',
  });

  observations.push({
    id: 'obs-protocol',
    label: 'Transport protocol',
    value: domainInfo.protocol === 'https:' ? 'HTTPS (encrypted)' : domainInfo.protocol.replace(':', '').toUpperCase(),
  });

  observations.push({
    id: 'obs-password',
    label: 'Password fields',
    value: signals.hasPasswordField
      ? `Present (${signals.passwordFieldCount})`
      : 'None detected',
  });

  const externalForms = signals.forms.filter(
    f => f.submitsToDifferentOrigin && !hasSameRegistrableDomain(signals.origin, f.actionOrigin)
  );
  observations.push({
    id: 'obs-forms',
    label: 'Form elements',
    value:
      signals.forms.length === 0
        ? 'None detected'
        : externalForms.length > 0
        ? `${signals.forms.length} total (${externalForms.length} external destination)`
        : `${signals.forms.length} total (same-domain destination)`,
  });

  if (signals.crossOriginFrameCount > 0) {
    observations.push({
      id: 'obs-frames',
      label: 'Embedded cross-origin frames',
      value: `${signals.crossOriginFrameCount} iframe(s) isolated by browser policy`,
    });
  }

  // 2. Evaluate specific multi-signal risk conditions

  // Rule A: Deceptive UserInfo in URL (e.g. https://paypal.com@evil.example/login)
  if (domainInfo.hasUserInfo) {
    findings.push({
      code: 'URL_DECEPTIVE_USERINFO',
      title: 'Deceptive "@" Userinfo in Page Address',
      severity: 'high',
      description:
        'The URL embeds text before an "@" symbol to disguise the actual destination host.',
      evidence: `Actual host: ${domainInfo.hostname}`,
    });
  }

  // Rule B: Raw IP address hosting a password/credential form
  if (domainInfo.isIp && signals.hasPasswordField && !domainInfo.isLocalhostOrPrivate) {
    findings.push({
      code: 'IP_HOST_CREDENTIAL_FORM',
      title: 'Password Input on Raw IP Host',
      severity: 'high',
      description:
        'This page requests a password while hosted directly on a numerical IP address rather than a registered domain.',
      evidence: `Host IP: ${domainInfo.hostname} (${signals.passwordFieldCount} password field(s))`,
    });
  }

  // Rule C: Password form submitting over unencrypted HTTP
  const insecurePasswordForm = signals.forms.find(
    f =>
      f.hasPasswordField &&
      (f.actionProtocol === 'http:' || domainInfo.protocol === 'http:') &&
      !domainInfo.isLocalhostOrPrivate
  );
  if (insecurePasswordForm || (signals.hasPasswordField && domainInfo.protocol === 'http:' && !domainInfo.isLocalhostOrPrivate)) {
    findings.push({
      code: 'INSECURE_HTTP_PASSWORD_COLLECTION',
      title: 'Unencrypted Password Collection (HTTP)',
      severity: 'medium',
      description:
        'A password field is served or submitted over unencrypted HTTP, exposing entered credentials in transit.',
      evidence: `Origin: ${signals.origin}`,
    });
  }

  // Rule D: Password form submitting to a different registrable domain
  // Note: A general form (search, newsletter) submitting externally is NOT flagged.
  // Even a password form submitting externally is marked NEEDS_REVIEW (could be third-party IdP/SSO)
  // unless combined with brand impersonation or IP host.
  const externalCredentialForms = signals.forms.filter(
    f =>
      f.hasPasswordField &&
      f.submitsToDifferentOrigin &&
      !hasSameRegistrableDomain(signals.origin, f.actionOrigin)
  );

  if (externalCredentialForms.length > 0) {
    const targetHosts = Array.from(
      new Set(externalCredentialForms.map(f => f.actionHostname))
    ).join(', ');
    findings.push({
      code: 'CROSS_DOMAIN_PASSWORD_SUBMISSION',
      title: 'Password Form Submits to Different Domain',
      severity: 'medium',
      description:
        'A form containing a password field sends data to a different registrable domain than the current page. Verify whether this is an expected single sign-on provider.',
      evidence: `Page domain "${domainInfo.registrableDomain || domainInfo.hostname}" -> Form target "${targetHosts}"`,
    });
  }

  // Rule E: Brand impersonation in hostname (subdomain deception or hyphenated brand lure)
  const currentRegDomain = domainInfo.registrableDomain || domainInfo.hostname;
  for (const brand of MONITORED_BRANDS) {
    const isOfficial = brand.officialDomains.some(
      d => currentRegDomain === d || domainInfo.hostname.endsWith(`.${d}`)
    );
    if (isOfficial) continue;

    const brandSlug = brand.name.toLowerCase();
    const inSubdomain = Boolean(
      domainInfo.subdomain && domainInfo.subdomain.toLowerCase().includes(brandSlug)
    );
    const inHyphenatedDomain = Boolean(
      currentRegDomain.includes(`${brandSlug}-`) || currentRegDomain.includes(`-${brandSlug}`)
    );

    if (inSubdomain || inHyphenatedDomain) {
      findings.push({
        code: 'DOMAIN_BRAND_SPOOFING',
        title: `Deceptive Brand Token in Hostname (${brand.name})`,
        severity: 'high',
        description: inSubdomain
          ? `The hostname places "${brand.name}" in a subdomain of an unrelated registrable domain ("${currentRegDomain}").`
          : `The registrable domain ("${currentRegDomain}") combines "${brand.name}" with hyphenated tokens outside official ${brand.name} domains.`,
        evidence: `Hostname: ${domainInfo.hostname} (Registrable domain: ${currentRegDomain})`,
      });
    }
  }

  // Rule F: Visible brand claim on a credential/login page hosted on an unrelated domain
  if (signals.hasPasswordField && !domainInfo.isLocalhostOrPrivate) {
    const textSampleLower = `${signals.documentTitle} ${signals.visibleTextSample}`.toLowerCase();
    const mismatchedBrands: string[] = [];

    for (const brand of MONITORED_BRANDS) {
      const isOfficial = brand.officialDomains.some(
        d => currentRegDomain === d || domainInfo.hostname.endsWith(`.${d}`)
      );
      if (isOfficial) continue;

      const mentionsBrand = brand.keywords.some(kw => textSampleLower.includes(kw));
      if (mentionsBrand) {
        mismatchedBrands.push(brand.name);
      }
    }

    if (mismatchedBrands.length > 0) {
      findings.push({
        code: 'PAGE_BRAND_CREDENTIAL_MISMATCH',
        title: `Brand / Domain Mismatch on Login Page (${mismatchedBrands.join(', ')})`,
        severity: 'high',
        description: `This page contains a password field and references ${mismatchedBrands.join(
          ', '
        )}, but is hosted on unrelated domain "${currentRegDomain}".`,
        evidence: `Referenced brand(s): ${mismatchedBrands.join(', ')} on ${domainInfo.hostname}`,
      });
    }
  }

  // Rule G: Punycode / IDN homograph indicator on a password page
  if (domainInfo.isPunycode && signals.hasPasswordField) {
    findings.push({
      code: 'PUNYCODE_LOGIN_HOST',
      title: 'Internationalized (Punycode) Domain on Login Page',
      severity: 'medium',
      description:
        'The page requests a password on an internationalized "xn--" domain. Confirm the exact character spelling to rule out lookalike characters.',
      evidence: `Hostname: ${domainInfo.hostname}`,
    });
  }

  // Merge any additional findings from the PhishLens backend API if connected
  if (options?.backendFindings && options.backendFindings.length > 0) {
    for (const bf of options.backendFindings) {
      const alreadyExists = findings.some(f => f.code === bf.code || f.title === bf.title);
      if (!alreadyExists) {
        findings.push(bf);
      }
    }
  }

  // Track incomplete inspection or unavailable backend checks transparently
  if (signals.incompleteInspection) {
    for (const reason of signals.incompleteReasons) {
      checksUnavailable.push(reason);
    }
  }

  const backendStatus: BackendConnectionState = options?.backendStatus ?? 'not_connected';
  const reputationStatus: ReputationLookupState = options?.reputationStatus ?? 'not_connected';

  if (backendStatus === 'connected') {
    checksCompleted.push('PhishLens API rule evaluation');
    if (reputationStatus === 'checked') {
      checksCompleted.push('External domain reputation lookup');
    } else {
      checksUnavailable.push(
        'External threat-intelligence feed (not configured on backend server)'
      );
    }
  } else {
    checksUnavailable.push(
      'PhishLens backend API not connected (ran local extension inspection only)'
    );
    checksUnavailable.push('External domain reputation lookup (requires backend API)');
  }

  if (options?.backendUncompletedChecks) {
    for (const item of options.backendUncompletedChecks) {
      if (!checksUnavailable.includes(item)) {
        checksUnavailable.push(item);
      }
    }
  }

  // Determine overall Risk Category
  const hasHigh = findings.some(f => f.severity === 'high');
  const hasMedium = findings.some(f => f.severity === 'medium');

  let riskCategory: InspectionRiskCategory = 'NO_EVIDENCE_FOUND';
  let summary =
    'No phishing indicators were triggered by local domain and DOM inspection.';
  let recommendedAction =
    'Confirm you recognize the domain in the browser address bar before entering sensitive data.';

  if (hasHigh) {
    riskCategory = 'SUSPICIOUS';
    summary =
      'High-severity deception or credential-harvesting indicators were detected on this page.';
    recommendedAction =
      'Do not enter passwords or personal details. Close this tab and navigate to the service via a trusted bookmark.';
  } else if (hasMedium || (signals.incompleteInspection && signals.hasPasswordField)) {
    riskCategory = 'NEEDS_REVIEW';
    summary =
      findings.length > 0
        ? 'Unusual form or transport characteristics were observed that require manual verification.'
        : 'This page contains a password field inside or alongside cross-origin frames that could not be fully inspected.';
    recommendedAction =
      'Verify the domain and form destination carefully before submitting any login credentials.';
  }

  return {
    url: signals.url,
    hostname: domainInfo.hostname || signals.hostname,
    registrableDomain: domainInfo.registrableDomain,
    riskCategory,
    summary,
    recommendedAction,
    observations,
    findings,
    checksCompleted,
    checksUnavailable,
    backendStatus,
    reputationStatus,
    incompleteInspection: signals.incompleteInspection,
    evaluatedAt: new Date().toISOString(),
  };
}
