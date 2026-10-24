# Privacy & Least-Privilege Permissions
**PhishLens (PS 089)**

## 1. Zero-Credential Storage Policy
- **No Password Collection**: The system never reads, stores, logs, or transmits user passwords or credential values.
- **No Cookie Access**: No browser session cookies or authentication tokens are inspected or exported.
- **No Account Integration**: Users do not need to link personal email, SMS, or messaging accounts to analyze text.
- **In-Memory Analysis**: Submitted text and URLs are evaluated strictly in transient memory.

---

## 2. SSRF (Server-Side Request Forgery) Prevention
The backend NEVER navigates to or fetches arbitrary user-submitted URLs. Analysis is performed through:
1. Syntactic WHATWG URL inspection
2. Mathematical domain entropy and edit-distance heuristics
3. Domain reputational queries against allowlisted threat intelligence providers

---

## 3. Chrome Extension Least-Privilege Model
The extension uses Manifest V3 with minimal permissions:
- `activeTab`: Grants access to the active webpage only when the user explicitly clicks "Analyse This Page".
- `scripting`: Executes a lightweight signal extractor on the current document.

### Explicit Prohibitions in Extension:
- No background web browsing tracking.
- No history inspection.
- No remote code execution (eval, new Function, external scripts).
- No form submission on behalf of user.
