# @bomhort/elements

Framework-independent web components built from the BOMHort Angular UI with `@angular/elements`.
Build: `npx ng run ui:build-elements` → `dist/browser/main.js` + `styles.css` (theme variables).

| Tag | Inputs |
|-----|--------|
| `bomhort-donut-chart` | `segments` (property), `center-label`, `size`, `stroke-width` |
| `bomhort-bar-chart` | `bars` (property) |
| `bomhort-scope-badge` | `scope`, `depth`, `size` |
| `bomhort-scope-matrix` | `breakdown` (property) |
| `bomhort-vuln-aliases` | `vuln` (property), `max` |
| `bomhort-page` | `route` — any app route (`/`, `/fleet`, `/projects`, `/projects/:name`, `/sboms`, `/sboms/:id`, `/vulnerabilities`, `/cve-impact?vuln=`, `/license-compliance`, `/licenses`, `/package-search`, `/version-skew`, `/dependency-stats`, `/archived-packages`, `/search?q=`). Emits `navigate` (detail = new URL) when a link inside it is followed; the browser URL is never touched. Needs a height. **One per document.** |

Links only work inside `<bomhort-page>`; standalone elements render data, not navigation.

Set `window.BOMHORT_API_URL` before loading `main.js` (default `/api/v1`). Routes are lazy-loaded chunks next to `main.js`, so ship the whole `dist/browser/` directory. Dark mode: `<html data-theme="dark">`.
`demo.html` is the host page used by `e2e/elements-demo.spec.ts`.
