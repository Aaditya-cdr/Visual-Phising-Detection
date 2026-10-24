# PhishLens Detection Methodology
**PS 089: Explainable Phishing Analysis**

## 1. Core Detection Philosophy

Traditional phishing detection tools often present an uncalibrated "Risk Score: 87%" without explaining what caused the assessment. PhishLens replaces opaque scores with **explainable evidence**:
- Every warning maps to a stable rule code (e.g., `PAGE_FORM_EXTERNAL_CREDENTIAL_POST`).
- Human-readable explanation describes the mechanism of the attack.
- Exact observed value is cited as proof (e.g., "Page domain 'service.org' posts credentials to 'attacker.ru'").
- Actionable safe advice provides an immediate next step.

---

## 2. Risk Categories

- **`SUSPICIOUS`**: Strong indicators present (verified malicious threat reputation, verified brand impersonation/typosquat, external form credential submission, or bare IP host with authentication path).
- **`NEEDS_REVIEW`**: Warning signs without definitive proof (linguistic urgency paired with unfamiliar link, disposable high-abuse TLD, or deceptive userinfo).
- **`NO_EVIDENCE_FOUND`**: Standard heuristic checks did not identify known warning patterns. Explicitly qualified that this does NOT guarantee 100% safety.
- **`NOT_ANALYSED`**: Input was invalid, empty, or unparseable.

---

## 3. Explanations of Core Heuristics

### A. Typosquatting and Confusables
Attackers register domains visually resembling trusted services (`paypa1.com`, `micros0ft.com`, `arnazon.com`). PhishLens normalizes visual confusables (e.g. `0` to `o`, `1` to `l`, `rn` to `m`) and calculates Levenshtein edit distances against high-value target brand databases.

### B. Subdomain Impersonation
Attackers place trusted brand names inside subdomains of unrelated registered domains (e.g. `paypal.com.account-verify.ru`). The engine isolates the true registrable domain via public suffix rules to uncover the trick.

### C. External Form Action Hijack
Phishing kits frequently host login forms whose HTML `<form action="...">` target transmits user inputs to an unrelated third-party collection server. The engine flags any credential input whose action destination differs from the host origin.

### D. Linguistic Coercion
Phishing messages leverage artificial deadlines ("within 24 hours") and legal/account threats ("account suspended", "warrant") to induce panic.
