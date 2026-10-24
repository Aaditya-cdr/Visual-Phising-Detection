# PhishLens Chrome Extension (Manifest V3)

Minimal, privacy-first Chrome Extension for **PhishLens — Visual Phishing Detection**. Built with Manifest V3, TypeScript, React, Vite, `tldts`, and `lucide-react`.

---

## 1. Directory Structure

```text
extension/
├── package.json
├── tsconfig.json
├── vite.config.ts
├── index.html
├── public/
│   └── icons/
│       ├── icon-16.png
│       ├── icon-48.png
│       └── icon-128.png
├── src/
│   ├── manifest.json
│   ├── popup/
│   │   ├── index.html
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   └── popup.css
│   ├── background/
│   │   └── service-worker.ts
│   ├── content/
│   │   └── inspect-page.ts
│   └── shared/
│       ├── types.ts
│       ├── domain-parser.ts
│       └── evaluator.ts
├── tests/
│   └── extension.test.ts
└── README.md
```

---

## 2. Build & Verification Commands

Run the following commands inside `/extension`:

```bash
# 1. Install extension dependencies
npm install

# 2. Run strict TypeScript checks
npm run typecheck

# 3. Run unit tests (domain parsing, DOM signal extraction, evaluation rules)
npm test

# 4. Build the production unpacked Chrome extension into /extension/dist
npm run build
```

After `npm run build`, the compiled extension is written to `/extension/dist`:

- `dist/manifest.json` — Manifest V3 file referencing verified built asset paths
- `dist/popup/index.html` & `dist/assets/*` — Bundled React popup UI and styles
- `dist/background/service-worker.js` — Self-contained MV3 background service worker
- `dist/content/inspect-page.js` — Self-contained IIFE content script injected on demand
- `dist/icons/*` — Extension toolbar and store icons (`16`, `48`, `128`)

---

## 3. How to Load the Unpacked Extension in Google Chrome

1. Open Google Chrome (or any Chromium-based browser) and navigate to `chrome://extensions`.
2. Enable **Developer mode** using the toggle in the top-right corner.
3. Click **Load unpacked** in the top-left action bar.
4. Select the generated `extension/dist` directory.
5. Pin the **PhishLens** shield icon in the browser toolbar, open any `http://` or `https://` website, click the icon, and click **Analyse this page**.

---

## 4. Permissions & Least-Privilege Architecture

The extension requests only two permissions in `manifest.json`:

- **`activeTab`**: Grants temporary access to the currently active tab **only** when the user explicitly interacts with the extension.
- **`scripting`**: Allows the background service worker to execute `content/inspect-page.js` on the active tab when the user clicks **Analyse this page**.

**What is intentionally NOT requested:**
- No broad `<all_urls>` host permissions are requested by default.
- No `tabs`, `history`, `cookies`, or `webNavigation` permissions are requested.
- The extension never runs background surveillance or automatic inspection on tab navigation.

---

## 5. Security Guarantees & Known Limitations

### Security & Privacy Rules
- **No credential or cookie access**: `inspect-page.ts` checks only whether `input[type="password"]` elements exist (`querySelectorAll('input[type="password"]').length`). It never reads `.value`, `document.cookie`, `localStorage`, or `sessionStorage`.
- **No DOM mutation or full HTML upload**: The content script never modifies the webpage DOM, never blocks navigation, and never reads `innerHTML` or `outerHTML`.
- **Observations vs. Risk Conclusions**: Neutral observations (such as registrable domain via `tldts`, HTTPS usage, presence of a password field, or non-credential external forms) are displayed distinctly from risk findings. A site is never labeled as phishing based solely on an unfamiliar domain, a password field, HTTPS usage, a long URL, or an external form target.

### Known Limitations
- **Restricted browser pages**: Chrome prevents all extensions from injecting scripts into `chrome://`, `edge://`, `about:`, `chrome-extension://`, and Chrome Web Store pages. On these tabs, the popup displays a clear **Not Analysed · Inspection Unavailable** state.
- **Cross-origin iframes**: Browser Same-Origin Policy isolates third-origin `<iframe>` documents. When cross-origin iframes are present on a page, the inspector records them as an incomplete-inspection scope note rather than silently ignoring them.
- **Backend API connectivity**: If the local PhishLens backend server (`http://localhost:3000/api/analyze/page`) is running, the service worker merges backend rule evaluation. When running standalone without the backend server, the popup explicitly states that the backend API and external domain reputation lookups were not connected rather than fabricating reputation results.
