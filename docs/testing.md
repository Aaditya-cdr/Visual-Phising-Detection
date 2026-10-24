# PhishLens Testing & Evaluation Guide
**PS 089: Verification Protocol**

## 1. Running Automated Unit Tests

The test suite runs using Node's built-in test runner (`node:test` and `node:assert/strict`) via `tsx`:

```bash
npm run test
# or directly:
npx --yes tsx --test tests/engine.test.ts
```

### Test Coverage Highlights:
- **URL Parsing**: Scheme safety, IP host identification, deceptive userinfo detection, malformed URL rejection.
- **Domain Heuristics**: Normalized Levenshtein distance, confusable homoglyph translation, brand token matching in subdomains and hyphenated tokens.
- **Text Signals**: Linguistic urgency and credential prompt extraction, sender domain vs link domain conflict.
- **Page DOM**: External credential form posting, unencrypted HTTP submissions.
- **Synthetic Test Presets**: End-to-end evaluation of benign and malicious fixtures.
- **Edge Cases**: Empty and whitespace inputs, extremely long texts (&gt;50k characters), multiple embedded URLs in single messages.

---

## 2. In-App Synthetic Test Fixtures

The web interface includes built-in test fixtures accessible via the "Quick Test Scenarios" drawer:
- **Brand Lookalike URL**: Tests typosquatting heuristics against `https://paypa1-security.com/verify-account`
- **Direct IP Host**: Tests bare IP host detection on `http://185.220.101.5/banking-login`
- **Disposable TLD**: Tests high-abuse .xyz domain heuristic
- **Legitimate Official Domain**: Tests false-positive control on `https://accounts.google.com/signin`
- **Urgent Account Suspension Email**: Tests multi-signal linguistic and domain conflict
- **Parcel Delivery Scam SMS**: Tests financial/shipping lure detection
- **Benign Business Message**: Tests false-positive control on ordinary neutral text
