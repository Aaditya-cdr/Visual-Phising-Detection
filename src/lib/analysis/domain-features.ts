/**
 * Domain feature extraction, brand impersonation detection, and typosquatting heuristics.
 * Uses tldts for robust public suffix & registrable domain parsing.
 */

import { parse } from 'tldts';
import { UrlInspectionFeatures } from './types.ts';

// High-value targeted brands commonly impersonated in credential harvesting
export const KNOWN_BRANDS: Array<{
  name: string;
  legitimateDomains: string[];
  canonicalSlug: string;
}> = [
  { name: 'PayPal', legitimateDomains: ['paypal.com', 'paypal.me'], canonicalSlug: 'paypal' },
  { name: 'Microsoft', legitimateDomains: ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'office365.com', 'azure.com', 'microsoftonline.com'], canonicalSlug: 'microsoft' },
  { name: 'Google', legitimateDomains: ['google.com', 'accounts.google.com', 'gmail.com', 'youtube.com'], canonicalSlug: 'google' },
  { name: 'Apple', legitimateDomains: ['apple.com', 'icloud.com'], canonicalSlug: 'apple' },
  { name: 'Amazon', legitimateDomains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.ca', 'amazon.co.jp', 'aws.amazon.com'], canonicalSlug: 'amazon' },
  { name: 'Netflix', legitimateDomains: ['netflix.com'], canonicalSlug: 'netflix' },
  { name: 'Chase Bank', legitimateDomains: ['chase.com', 'jpmorganchase.com'], canonicalSlug: 'chase' },
  { name: 'Wells Fargo', legitimateDomains: ['wellsfargo.com'], canonicalSlug: 'wellsfargo' },
  { name: 'Bank of America', legitimateDomains: ['bankofamerica.com', 'bofa.com'], canonicalSlug: 'bankofamerica' },
  { name: 'DHL Express', legitimateDomains: ['dhl.com', 'dhl.de'], canonicalSlug: 'dhl' },
  { name: 'FedEx', legitimateDomains: ['fedex.com'], canonicalSlug: 'fedex' },
  { name: 'USPS', legitimateDomains: ['usps.com'], canonicalSlug: 'usps' },
  { name: 'Meta / Facebook / Instagram', legitimateDomains: ['facebook.com', 'fb.com', 'instagram.com', 'meta.com'], canonicalSlug: 'facebook' },
  { name: 'Coinbase', legitimateDomains: ['coinbase.com'], canonicalSlug: 'coinbase' },
  { name: 'Binance', legitimateDomains: ['binance.com'], canonicalSlug: 'binance' },
  { name: 'Dropbox', legitimateDomains: ['dropbox.com'], canonicalSlug: 'dropbox' },
  { name: 'Steam', legitimateDomains: ['steampowered.com', 'steamcommunity.com'], canonicalSlug: 'steam' }
];

// TLDs frequently abused in ephemeral, disposable phishing campaigns
export const SUSPICIOUS_HIGH_ABUSE_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq',
  'top', 'xyz', 'buzz', 'work', 'icu',
  'rest', 'cam', 'sbs', 'cfd', 'click'
]);

/**
 * Standard Levenshtein Distance calculation
 */
export function calculateLevenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;

  const d: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) d[i][0] = i;
  for (let j = 0; j <= n; j++) d[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(
        d[i - 1][j] + 1,      // deletion
        d[i][j - 1] + 1,      // insertion
        d[i - 1][j - 1] + cost // substitution
      );
    }
  }

  return d[m][n];
}

/**
 * Normalizes visual confusables (homoglyphs and typical character swaps)
 */
export function normalizeConfusables(str: string): string {
  return str
    .toLowerCase()
    .replace(/0/g, 'o')
    .replace(/1|\||!/g, 'l')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/5/g, 's')
    .replace(/3/g, 'e')
    .replace(/8/g, 'b');
}

/**
 * Enriches URL features with domain and brand impersonation heuristics
 */
export function extractDomainFeatures(features: UrlInspectionFeatures): UrlInspectionFeatures {
  if (!features.isValid || !features.hostname || features.isIpAddress) {
    return features;
  }

  const parsed = parse(features.hostname);
  const registrableDomain = parsed.domain || undefined;
  const publicSuffix = parsed.publicSuffix || undefined;
  const subdomain = parsed.subdomain || '';
  
  const subdomains = subdomain ? subdomain.split('.').filter(Boolean) : [];
  const subdomainDepth = subdomains.length;

  const tld = publicSuffix ? publicSuffix.toLowerCase().split('.').pop() || '' : '';
  const suspiciousTld = SUSPICIOUS_HIGH_ABUSE_TLDS.has(tld);

  // Extract base domain without TLD (e.g. "paypal" from "paypal.com" or "paypa1" from "paypa1.com")
  const baseDomainName = registrableDomain && publicSuffix 
    ? registrableDomain.slice(0, -(publicSuffix.length + 1))
    : features.hostname;

  let brandImpersonationMatch: UrlInspectionFeatures['brandImpersonationMatch'] | undefined;

  for (const brand of KNOWN_BRANDS) {
    // 1. Check if the current domain is legitimately owned by the brand
    const isLegit = registrableDomain && brand.legitimateDomains.some(legit => registrableDomain === legit);
    if (isLegit) {
      continue;
    }

    // 2. Check for Brand Name embedded in Subdomain (e.g., paypal.com.attacker.com or apple-id.secure.cc)
    if (subdomain) {
      const lowerSub = subdomain.toLowerCase();
      if (
        lowerSub === brand.canonicalSlug ||
        lowerSub.startsWith(`${brand.canonicalSlug}.`) ||
        lowerSub.endsWith(`.${brand.canonicalSlug}`) ||
        lowerSub.includes(`.${brand.canonicalSlug}.`) ||
        lowerSub.includes(`-${brand.canonicalSlug}`) ||
        lowerSub.includes(`${brand.canonicalSlug}-`)
      ) {
        brandImpersonationMatch = {
          brandName: brand.name,
          detectedIn: 'subdomain',
          similarityScore: 1.0,
        };
        break;
      }
    }

    // 3. Check for Hyphenated brand token in registrable domain (e.g., "paypal-support.com", "apple-login-security.com", "paypa1-security.com")
    if (baseDomainName) {
      const lowerBase = baseDomainName.toLowerCase();
      const tokens = lowerBase.split(/[-_.]/);
      
      // Direct token match (e.g. paypal-security.com)
      if (tokens.includes(brand.canonicalSlug)) {
        brandImpersonationMatch = {
          brandName: brand.name,
          detectedIn: 'hyphenated_token',
          similarityScore: 0.95,
        };
        break;
      }

      // Token confusable / typosquat check (e.g. paypa1-security.com)
      let foundInToken = false;
      for (const tok of tokens) {
        const normTok = normalizeConfusables(tok);
        if (normTok === brand.canonicalSlug && tok !== brand.canonicalSlug) {
          brandImpersonationMatch = {
            brandName: brand.name,
            detectedIn: 'confusable',
            similarityScore: 0.92,
          };
          foundInToken = true;
          break;
        }
        if (brand.canonicalSlug.length >= 4 && calculateLevenshteinDistance(tok, brand.canonicalSlug) === 1 && tok !== brand.canonicalSlug) {
          brandImpersonationMatch = {
            brandName: brand.name,
            detectedIn: 'typosquat',
            similarityScore: 0.88,
          };
          foundInToken = true;
          break;
        }
      }
      if (foundInToken) {
        break;
      }

      // 4. Check whole base domain for Confusables / Homoglyphs (e.g. "paypa1.com" or "arnazon.com")
      const normalizedBase = normalizeConfusables(lowerBase);
      if (normalizedBase === brand.canonicalSlug && lowerBase !== brand.canonicalSlug) {
        brandImpersonationMatch = {
          brandName: brand.name,
          detectedIn: 'confusable',
          similarityScore: 0.9,
        };
        break;
      }

      // 5. Check whole base domain for Typosquatting (Levenshtein distance 1 for brands with length >= 4)
      if (brand.canonicalSlug.length >= 4) {
        const dist = calculateLevenshteinDistance(lowerBase, brand.canonicalSlug);
        if (dist === 1 && lowerBase !== brand.canonicalSlug) {
          brandImpersonationMatch = {
            brandName: brand.name,
            detectedIn: 'typosquat',
            similarityScore: 0.85,
          };
          break;
        }
      }
    }
  }

  return {
    ...features,
    registrableDomain,
    publicSuffix,
    subdomains,
    subdomainDepth,
    suspiciousTld,
    brandImpersonationMatch,
  };
}
