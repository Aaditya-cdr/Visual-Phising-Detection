# PhishLens Architecture Documentation
**Problem Statement PS 089: Visual Phishing Detection**

## 1. System Overview

PhishLens is a privacy-first, explainable phishing detection system with two interfaces:
1. **Web Application**: Accessible SPA dashboard for deep inspection of URLs, email content, and SMS/chat messages.
2. **Chrome Browser Extension (Manifest V3)**: Compact, user-activated page inspector that evaluates DOM signals (login form targets, credential inputs, brand name discrepancies).

Both interfaces share deterministic heuristic rules and risk evaluation models.

---

## 2. Component Architecture

```
[ Web User ] ────► [ Next/React Dashboard ] ────► [ Express / API Endpoints ]
                          │                                │
[ Browser User ] ──► [ Chrome Ext MV3 ] ──────────► [ Shared Detection Engine ]
                      (ActiveTab DOM)                      │
                                             ┌─────────────┴─────────────┐
                                             ▼                           ▼
                                    [ Heuristic Rules ]        [ Threat Intelligence ]
                                    - WHATWG URL Parsing       - Safe Browsing v4
                                    - Domain & Typosquats      - Graceful Fallback
                                    - Linguistic Coercion
                                    - DOM Form Actions
```

---

## 3. Data Flow

1. **Submission**: User submits a URL or pastes text into the web app, or triggers "Analyse This Page" in the extension popup.
2. **Sanitization & Parsing**:
   - URLs are parsed using standard WHATWG URL APIs (blocking unsupported `javascript:` or `data:` schemes).
   - Domains are extracted using `tldts` for accurate registrable domain and public suffix boundaries.
   - Text is parsed for embedded links and linguistic warning triggers.
3. **Feature Extraction**:
   - `url-parser.ts`: Detects bare IP hosts, deceptive userinfo fields, punycode/IDN homoglyphs, non-standard ports.
   - `domain-features.ts`: Evaluates Levenshtein typosquatting distances, confusable homoglyphs, brand tokens in subdomains, disposable TLDs.
   - `text-features.ts`: Evaluates urgency/coercion language, credential solicitation, delivery fee scams, and sender domain vs link domain mismatches.
   - `page-features.ts`: Inspects credential form destinations (e.g., cross-origin post targets) and visible brand text vs registered domain alignment.
4. **Rule Evaluation**:
   - Structured findings with rule codes (`URL_BRAND_IMPERSONATION`, `PAGE_FORM_EXTERNAL_CREDENTIAL_POST`, etc.) are generated with exact observed evidence.
   - Overall risk category assigned: `SUSPICIOUS`, `NEEDS_REVIEW`, `NO_EVIDENCE_FOUND`, or `NOT_ANALYSED`.
5. **Guidance**: Actionable next step generated for the end-user.

---

## 4. API Endpoints

- `POST /api/analyze/url`: Analyzes standalone URLs with SSRF protection.
- `POST /api/analyze/text`: Inspects email or message plain text.
- `POST /api/analyze/page`: Inspects page DOM signals received from the extension.
- `GET /api/health`: Health status and provider configuration state.
