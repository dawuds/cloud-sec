# LEARNINGS.md — Cloud Security Framework

Lessons from building this repository. Synthesised from patterns across the OT-Security, NACSA, RMIT, and PDPA-MY compliance repos. Read before generating any new content.

---

## Repo-Specific Lessons

### 1. SPA Pattern — Zero-Dependency Hash-Routed Architecture

The cloud-sec and OT-Security repos share the same SPA pattern:
- **Hash routing:** `#view/sub` parsed by `parseHash()`, dispatched by `render()` switch
- **Lazy loading:** JSON fetched via `load(path)` and cached in a `Map` — no re-fetching
- **No build step:** Single `app.js` + `style.css` + `index.html` — deployed as-is to GitHub Pages
- **Render functions:** One `async function renderXxx()` per view, calling `setMain(html)` with template literals

**Key constraint:** All rendering is string concatenation in template literals. No virtual DOM, no reactive state. This means:
- Every `onclick` must reference a globally-exported function (via `window.navigate = navigate`)
- Dynamic filtering (tabs, search) must use DOM manipulation after `setMain()` or re-render the entire view
- Nested data (e.g., clause detail with risk areas + CSP guidance) requires careful HTML nesting in template literals

### 2. Data-Code Field Name Mismatches — The #1 Bug Source

Inherited from OT-Security. When JSON data files are generated separately from app.js render functions, field names diverge:

| Pattern | Example | Impact |
|---|---|---|
| Plural vs singular | `controls` vs `control` | Empty list (silent) |
| Nested key path | `data.domains` vs `data.controlDomains` | Empty view (silent) |
| Array vs object | `slToNacsaMapping: {}` vs expected `[]` | Hard crash: `.map is not a function` |
| Array vs string | `vulnerabilities: "text"` vs expected `["text"]` | Hard crash: `.join is not a function` |
| Object field name | `c.name` vs actual `c.type` | Renders `[object Object]` or raw JSON |

**Prevention:** After generating any new JSON file, open app.js and trace the exact field path the renderer uses. Test with the browser console open.

### 3. CSP-Specific Data Asymmetry

Not all CSPs have the same data depth. Current state:

| CSP | Index | Services | CIS Benchmark | Well-Architected |
|---|---|---|---|---|
| AWS | Yes | Yes | Yes (62 controls) | Yes |
| Azure | Yes | Yes | Yes (52 controls) | No |
| GCP | Yes | Yes | Yes (46 controls) | No |
| Alibaba | Yes | Yes | No | No |
| Huawei | Yes | Yes | No | No |
| Oracle | Yes | Yes | No | No |

**Lesson:** The render functions must handle missing data files gracefully. Use `try/catch` around `load()` calls for optional files, or check for file existence before rendering sections.

### 4. RMiT Clause Structure — Polymorphic Fields

RMiT clauses (10.50-10.52, 17.1-17.5) have different structures depending on clause type:
- 10.50 has `riskAreas[]` — rendered as cards
- 10.51 has `appendix10Domains[]` — rendered as domain cards with key controls
- 10.52 has `requirements[]` + `cspRegionOptions[]` — rendered as list + table
- 17.1 has `prerequisites[]` — rendered as step cards
- 17.2 has `preconditions[]` — rendered as simple list
- 17.3 has `keyConsideration` — rendered as callout
- 17.4 has `implication` — rendered as callout

**Lesson:** The `renderRMiTClauseDetail()` function checks for each optional field and renders the appropriate section. This is the right approach for polymorphic data — don't force all clauses into a single structure.

### 5. Data Residency Table — CSP Region Accuracy

Malaysia data residency is a critical compliance requirement (RMiT 10.52). The CSP region table must be accurate:
- **Alibaba Cloud:** ap-southeast-3 (Kuala Lumpur) — **confirmed Malaysia region**
- **Huawei Cloud:** ap-southeast-3 (Kuala Lumpur) — **confirmed Malaysia region**
- **AWS/Azure/GCP:** No dedicated Malaysia region as of 2026-03 — nearest is Singapore

**Lesson:** This data changes. CSPs launch new regions. The table must include a last-verified date and be rechecked periodically. AWS has had a Malaysia Local Zone "pending" for over a year.

### 6. GitHub Actions Deployment — Outage Resilience

During initial deployment (2026-03-05), GitHub Actions experienced a major outage lasting several hours. Workflow runs returned HTTP 500, manual triggers failed, and queued runs were delayed.

**Lesson:** Have a fallback deployment method. The `gh-pages` branch approach (push built files to a branch, configure Pages to serve from it) works even when Actions is down. For this repo, since the files are static (no build step), you can also deploy manually via `git push` to a `gh-pages` branch.

---

## Common Patterns Inherited from NACSA, RMIT, PDPA-MY, OT-Security

### Pattern 1: AI Confabulation of Identifiers

Format-plausible but fabricated identifiers are the hardest to detect:
- CCM control IDs (e.g., `GRC-08` — does it exist?)
- CIS Benchmark control numbers (e.g., `2.1.4` — is it real?)
- MITRE technique IDs (e.g., `T1234` — enterprise, not cloud?)
- BNM RMiT clause numbers (e.g., `10.53` — exists but is Access Control, not Cloud)

**For Cloud Security:** Every CCM control ID, CIS control number, MITRE technique ID, and RMiT clause reference must be verified against the authoritative source. The dawuds/RMIT repo is the verified source for RMiT clause data.

### Pattern 2: Cascading Errors from Wrong Base Layer

If a CCM domain ID is wrong in `control-domains.json`, every cross-reference, control mapping, and requirement that references it will be wrong. Fix the base before building derivatives.

### Pattern 3: Status Misrepresentation

- NACSA codes of practice under Act 854: **not gazetted** as of 2026-03
- AWS Malaysia region: **pending**, not launched
- BNM RMiT Appendix 10: content is **indicative** — exact text not publicly available

Mark all unverified content with appropriate `sourceType`.

### Pattern 4: Audit Package Pattern

Reusable across all compliance repos (OT-Security, cloud-sec, NACSA, RMIT, PDPA-MY):

```
Control (slug)
  └─ controlSlugs[] on artifacts → direct semantic mapping
       ├─ artifacts/inventory.json → full artifact objects
       └─ evidence/index.json[domain] → evidenceItems[]
```

Direct `controlSlugs[]` mapping chosen over domain-based joins to prevent broad domains from flooding results. See OT-Security `LEARNINGS.md` for full implementation details.

---

## Verification Checklist

Before publishing any new content in this repo:

- [ ] All CCM domain IDs are from the 17 official domains (A&A, AIS, BCR, CCC, CEK, DCS, DSP, GRC, HRS, IAM, IPY, IVS, LOG, SEF, STA, TVM, UEM)
- [ ] All CCM control IDs follow the format `XXX-nn` and exist in the CCM v4 spreadsheet
- [ ] All MITRE ATT&CK Cloud technique IDs verified against attack.mitre.org/matrices/enterprise/cloud
- [ ] All CIS Benchmark control numbers verified against the published benchmark PDF
- [ ] All RMiT clause numbers verified against dawuds/RMIT repo or BNM document
- [ ] All NACSA section references are s17-s26
- [ ] `sourceType` field present on every JSON file
- [ ] Field names in new JSON files cross-referenced against the app.js renderer for that view
- [ ] CSP region data verified against current CSP documentation
- [ ] Domain IDs consistent across requirements, controls, evidence, artifacts, and cross-references
- [ ] All cross-references resolvable in both directions
- [ ] Browser console shows no errors on every view after changes

---

## Bugs Found and Fixed (2026-03-06)

### Rendering Bug 1: CCM Domains View Empty
`renderCCMDomains()` and `renderOverview()` used `Array.isArray(domains)` to check if the loaded data was iterable. But `control-domains.json` returns `{controlDomains: [...]}`, not a bare array. The `Array.isArray` check returned false, and the fallback `[]` rendered an empty list.

**Fix:** Changed to `Array.isArray(domains) ? domains : (domains.controlDomains || [])` in `renderCCMDomains()`, `renderOverview()`, and `renderFramework()`.

### Rendering Bug 2: Evidence View Empty
`renderEvidence()` used `data.domains` to access the evidence array. But `evidence/index.json` uses the key `evidenceByDomain`, not `domains`.

**Fix:** Changed to `data.evidenceByDomain || data.domains || data || []`.

### Rendering Bug 3: Checklist Items Render as JSON
`renderRiskChecklist()` used `c.check || c.title` to display checklist item text. But `checklist.json` uses the field name `item`, not `check` or `title`.

**Fix:** Changed to `c.item || c.check || c.title`.

### Rendering Bug 4: Sector Detail Title Shows Raw ID
`renderSectorDetail()` used `sector.name` for the page title. But `data.sector` is a string (e.g., `"healthcare"`), not an object. The friendly name is in `data.sectorName`.

**Fix:** Changed to `data.sectorName || sector.name || sectorId`.

### Root Cause
All four bugs are instances of Pattern 2 from the Data-Code Field Name Mismatches lesson above. JSON data files were generated with different field names than the app.js render functions expected. The SPA renders silently empty content instead of throwing errors, making these bugs invisible without browser dev tools.
