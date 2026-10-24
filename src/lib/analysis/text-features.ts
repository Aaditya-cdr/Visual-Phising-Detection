/**
 * Email and Message text feature extraction and heuristic signal detection.
 */

import { parse } from 'tldts';
import { TextInspectionFeatures } from './types.ts';

// Common urgency & coercive fear phrasing
const URGENCY_PATTERNS = [
  /account (?:has been|will be|is) (?:suspended|disabled|locked|terminated|restricted)/i,
  /immediate (?:action|verification|attention) (?:is )?required/i,
  /within (?:24|48|12|1|2) hours/i,
  /unauthorized (?:activity|access|log-?in|transaction) detected/i,
  /urgent notice/i,
  /final warning/i,
  /failure to (?:respond|verify|update) will result in/i,
  /your account is at risk/i,
  /security breach detected/i,
];

// Credential & sensitive verification harvesting phrasing
const CREDENTIAL_PATTERNS = [
  /(?:confirm|verify|enter|update|reset) your (?:password|passcode|pin|credentials)/i,
  /(?:click|tap) (?:here|the link below) to (?:verify|unlock|reactivate|restore)/i,
  /update your (?:billing|credit card|payment) (?:details|information)/i,
  /re-?enter your credentials/i,
  /verify your identity/i,
  /provide your (?:social security|ssn|seed phrase|private key)/i,
];

// Financial, parcel delivery, and reward scam patterns
const FINANCIAL_DELIVERY_PATTERNS = [
  /(?:parcel|package|shipment) (?:cannot be delivered|is on hold|pending delivery)/i,
  /(?:unpaid|outstanding) (?:customs|shipping|delivery|redelivery) (?:fee|charge)/i,
  /you have (?:won|been selected for|inherited)/i,
  /claim your (?:reward|prize|refund|cashback|airdrop)/i,
  /invoice (?:overdue|attached|payment required)/i,
  /crypto(?:currency)? (?:giveaway|bonus|deposit)/i,
];

// Threat & punitive coercion patterns
const THREAT_PATTERNS = [
  /legal action (?:will be taken|pending)/i,
  /report(?:ed)? to (?:authorities|law enforcement|police)/i,
  /court order/i,
  /warrant for your arrest/i,
  /penalty fee of/i,
];

/**
 * Safely extracts HTTP and HTTPS URLs from text without arbitrary execution
 */
export function extractUrlsFromText(text: string): string[] {
  // WHATWG regex for URLs inside plain text
  const urlRegex = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`[\]]+/gi;
  const matches = text.match(urlRegex) || [];
  
  // Clean trailing punctuation commonly attached to URLs in prose (e.g. "http://example.com.")
  return Array.from(new Set(matches.map(raw => {
    let clean = raw.replace(/[.,;:!?]+$/, '');
    if (clean.toLowerCase().startsWith('www.')) {
      clean = `https://${clean}`;
    }
    return clean;
  })));
}

/**
 * Extracts sender domain from an email address (e.g. "Security <alerts@company.com>")
 */
export function extractEmailDomain(emailOrHeader: string): { email?: string; domain?: string } {
  const emailRegex = /[\w.-]+@([\w.-]+\.[a-zA-Z]{2,})/;
  const match = emailOrHeader.match(emailRegex);
  if (!match) return {};

  const email = match[0];
  const parsed = parse(match[1]);
  return {
    email,
    domain: parsed.domain || match[1].toLowerCase(),
  };
}

/**
 * Inspects plain text for phishing warning signs
 */
export function inspectTextFeatures(
  rawText: string,
  optionalSender?: string
): TextInspectionFeatures {
  const extractedUrls = extractUrlsFromText(rawText);
  
  const senderInfo = optionalSender ? extractEmailDomain(optionalSender) : undefined;
  const senderDomain = senderInfo?.domain;

  const urgencySignals: string[] = [];
  for (const pattern of URGENCY_PATTERNS) {
    const match = rawText.match(pattern);
    if (match) {
      urgencySignals.push(match[0]);
    }
  }

  const credentialSignals: string[] = [];
  for (const pattern of CREDENTIAL_PATTERNS) {
    const match = rawText.match(pattern);
    if (match) {
      credentialSignals.push(match[0]);
    }
  }

  const financialScamSignals: string[] = [];
  for (const pattern of FINANCIAL_DELIVERY_PATTERNS) {
    const match = rawText.match(pattern);
    if (match) {
      financialScamSignals.push(match[0]);
    }
  }

  const threatSignals: string[] = [];
  for (const pattern of THREAT_PATTERNS) {
    const match = rawText.match(pattern);
    if (match) {
      threatSignals.push(match[0]);
    }
  }

  // Check if sender domain conflicts with extracted link domains
  let senderLinkDomainMismatch: TextInspectionFeatures['senderLinkDomainMismatch'] | undefined;
  if (senderDomain && extractedUrls.length > 0) {
    const linkDomains: string[] = [];
    for (const link of extractedUrls) {
      try {
        const u = new URL(link);
        const parsedDomain = parse(u.hostname).domain || u.hostname;
        if (parsedDomain && parsedDomain !== senderDomain && !linkDomains.includes(parsedDomain)) {
          linkDomains.push(parsedDomain);
        }
      } catch {
        // Ignore unparseable extracted link
      }
    }

    if (linkDomains.length > 0) {
      senderLinkDomainMismatch = {
        senderDomain,
        linkDomains,
      };
    }
  }

  return {
    rawText,
    characterCount: rawText.length,
    extractedUrls,
    senderEmail: senderInfo?.email,
    senderDomain,
    urgencySignals,
    credentialSignals,
    threatSignals,
    financialScamSignals,
    senderLinkDomainMismatch,
  };
}
