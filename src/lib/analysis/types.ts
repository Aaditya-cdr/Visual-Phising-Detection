/**
 * Core type definitions for PhishLens Phishing Detection Engine
 */

export type RiskCategory = 'SUSPICIOUS' | 'NEEDS_REVIEW' | 'NO_EVIDENCE_FOUND' | 'NOT_ANALYSED';

export type FindingSeverity = 'high' | 'medium' | 'low' | 'info';

export type AnalysisStatus = 'completed' | 'partial' | 'failed';

export type TargetType = 'url' | 'email' | 'message' | 'page';

export interface Finding {
  code: string;
  title: string;
  severity: FindingSeverity;
  description: string;
  evidence?: string;
  source: 'url_structure' | 'domain_reputation' | 'text_heuristics' | 'page_dom' | 'input_validation';
  passed: boolean;
  safeNextStep?: string;
}

export interface AnalysisResult {
  targetType: TargetType;
  targetSummary: string;
  riskCategory: RiskCategory;
  status: AnalysisStatus;
  summary: string;
  findings: Finding[];
  checksPerformed: string[];
  uncompletedChecks: string[];
  recommendedNextStep: string;
  limitations: string;
  evaluatedAt: string;
  details?: Record<string, unknown>;
}

export interface UrlInspectionFeatures {
  originalUrl: string;
  isValid: boolean;
  protocol?: string;
  hostname?: string;
  port?: string;
  pathname?: string;
  search?: string;
  hasUserInfo: boolean;
  userInfo?: string;
  isIpAddress: boolean;
  ipVersion?: 'v4' | 'v6';
  isPunycode: boolean;
  unicodeHostname?: string;
  hasMixedScript: boolean;
  registrableDomain?: string;
  publicSuffix?: string;
  subdomains: string[];
  subdomainDepth: number;
  suspiciousTld: boolean;
  brandImpersonationMatch?: {
    brandName: string;
    detectedIn: 'subdomain' | 'typosquat' | 'hyphenated_token' | 'confusable';
    similarityScore?: number;
  };
  suspiciousKeywordsInPath: string[];
}

export interface TextInspectionFeatures {
  rawText: string;
  characterCount: number;
  extractedUrls: string[];
  senderEmail?: string;
  senderDomain?: string;
  urgencySignals: string[];
  credentialSignals: string[];
  threatSignals: string[];
  financialScamSignals: string[];
  senderLinkDomainMismatch?: {
    senderDomain: string;
    linkDomains: string[];
  };
}

export interface PageInspectionFeatures {
  url: string;
  pageOrigin: string;
  pageHostname: string;
  hasPasswordField: boolean;
  hasLoginForm: boolean;
  formActions: Array<{
    actionUrl: string;
    actionDomain: string;
    isExternal: boolean;
    isHttpOnHttps: boolean;
    hasPasswordField: boolean;
  }>;
  visibleBrandTextMatches: string[];
  linksCount: number;
  externalLinksCount: number;
}
