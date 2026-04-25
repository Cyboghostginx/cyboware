# Cyboware Privacy Policy

Last updated: April 2026

## What Cyboware Does
Cyboware is a browser-based bug bounty toolkit that runs entirely in your browser. All analysis is performed locally — no data is sent to any external server owned by Cyboware.

## Data Collection
Cyboware does **NOT** collect, store, or transmit any personal data. We have no servers, no databases, no analytics. Your browsing data stays on your device.

## Data Storage
- User settings (scope domains, notes, scratchpad content) are stored locally in `chrome.storage.local` on your device only
- No data is synced to the cloud
- No analytics or telemetry of any kind
- Clearing extension data removes all stored settings

## External Requests
Cyboware makes requests to these third-party services **only** when you explicitly trigger a specific tool:

| Service | Tool | Data Sent |
|---|---|---|
| crt.sh | Subdomain Enumeration | Target domain name |
| api.hackertarget.com | Subdomain Enumeration (fallback) | Target domain name |
| dns.google | DNS Lookup | Target domain name |
| web.archive.org | Wayback Machine | Target URL |
| rdap.org | WHOIS Lookup | Target domain name |

No cookies, authentication tokens, personal data, or browsing history is sent to any of these services.

## Permissions Explained
- **tabs / activeTab** — Read the current page URL to provide context-aware analysis
- **cookies** — Inspect cookie security flags (HttpOnly, Secure, SameSite) for the Cookie Inspector tool
- **webRequest** — Capture HTTP response headers for the Security Headers Audit
- **storage** — Save your scope settings, notes, and preferences locally
- **scripting** — Inject page analysis scripts to detect technologies, hidden elements, and vulnerabilities
- **host_permissions (`<all_urls>`)** — Security analysis must work on any website the user chooses to test
- **clipboardWrite** — Enable copy-to-clipboard functionality for all tool results

## Children's Privacy
Cyboware is not directed at children under 13. We do not knowingly collect data from children.

## Changes
We may update this privacy policy. Changes will be posted at this URL.

## Contact
- GitHub: [https://github.com/Cyboghostginx](https://github.com/Cyboghostginx)
- For privacy inquiries, open an issue on the GitHub repository
