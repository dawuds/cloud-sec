# Cloud Security Framework — TODO

Tracking all planned enhancements. Grouped by phase. Check off items as completed.

---

## Phase 1 — Core Framework (Complete)

- [x] SPA scaffold — index.html, app.js, style.css with hash routing and lazy-loaded JSON
- [x] CSA CCM v4 overview + 17 control domains with example controls
- [x] MITRE ATT&CK Cloud — 35 techniques across cloud tactics
- [x] NIST Cloud Security — SP 800-144 and SP 800-210 overview
- [x] Architecture views — shared responsibility, reference architecture, service models, asset types, CSP comparison
- [x] Cloud Providers — AWS, Azure, GCP, Alibaba, Huawei, Oracle with service inventories
- [x] CIS Benchmarks — AWS v3.0 (62), Azure v2.1 (52), GCP v3.0 (46) with control summaries
- [x] Requirements — 12 security domains with per-domain requirement files
- [x] Controls library — 49 controls with maturity levels, CCM/NACSA/NIST CSF/MITRE mappings, CSP implementation
- [x] Evidence — audit evidence items per domain
- [x] Artifacts — 29 security artifacts inventory (26 + 3 serverless-security)
- [x] Threats — 8 cloud incidents + 6 threat actors with control mappings
- [x] Risk management — methodology, 5x5 matrix, 15-risk register, assessment checklist, treatment options
- [x] Sectors — financial services, healthcare, government, e-commerce, education, telecommunications with Malaysia-specific obligations
- [x] Cross-references — 7 mapping files (CCM ↔ NACSA, NIST CSF, ISO 27017, MITRE, AWS, Azure, GCP)
- [x] Framework matrix view — CCM × Controls × NACSA × NIST CSF × MITRE
- [x] Search — cross-view search with type badges
- [x] GitHub Pages deployment via Actions workflow

---

## Phase 2 — RMiT Cloud Integration (Complete)

- [x] RMiT Cloud overview — index.json with sections, key principles, appendix 10 areas
- [x] RMiT Cloud clauses — 8 clauses (10.50-10.52, 17.1-17.5) with risk areas, Appendix 10 domains, data residency table, prerequisites, evidence
- [x] RMiT to CCM mapping — 6 RMiT areas mapped to CCM v4 control domains with compliance approach
- [x] RMiT Cloud nav link and render functions (renderRMiT, renderRMiTClauses, renderRMiTClauseDetail, renderRMiTCCMMapping)

---

## Phase 3 — Data Enrichment (Mostly Complete)

- [x] Add CIS Benchmark data for Alibaba (v1.0, 34 checks) — `standards/csp/alibaba/cis-benchmark.json`
- [x] Add CIS Benchmark data for Oracle (v2.0, 42 checks) — `standards/csp/oracle/cis-benchmark.json`
- [x] Add Huawei Cloud Security Best Practices (23 checks) — `standards/csp/huawei/cis-benchmark.json` (no official CIS benchmark exists)
- [x] Add Well-Architected framework data for Azure (5 principles, 6 areas) — `standards/csp/azure/well-architected.json`
- [x] Add Well-Architected framework data for GCP (6 principles, 6 areas) — `standards/csp/gcp/well-architected.json`
- [x] Add missing sector files: education.json, telecommunications.json — all 6 sectors now have detail files
- [x] Expand threat actors — now 6 (added Muddled Libra); FIN7, APT41 pending
- [ ] Expand evidence items from 6 domains to all 12 domains
- [ ] Add cloud-specific MITRE ATT&CK sub-techniques where relevant

---

## Phase 4 — Mapping Enhancements (Pending)

- [ ] Add CCM ↔ Alibaba Cloud service mapping — `cross-references/ccm-to-alibaba.json`
- [ ] Add CCM ↔ Huawei Cloud service mapping — `cross-references/ccm-to-huawei.json`
- [ ] Add CCM ↔ Oracle Cloud service mapping — `cross-references/ccm-to-oracle.json`
- [ ] Add RMiT ↔ NACSA cross-reference (financial institution NCII obligations)
- [ ] Add ISO 27017 control detail expansion (currently indicative mapping only)
- [ ] Add bidirectional lookup to all cross-references (reverse mapping views)

---

## Phase 5 — Quality & Validation (Mostly Complete)

- [x] Add validation script (validate.js) — 8 checks: JSON parsing, controlSlug resolution, domain file matching, evidence domain matching, risk math, CCM domain consistency, sector file matching, duplicate slug detection
- [x] Verify all CCM domain IDs match across control-domains.json, controls library, and cross-references (fixed A&A/AAC mismatch)
- [ ] Verify all CIS Benchmark control IDs against published benchmarks
- [x] Add `sourceType` and `verificationNote` to all 19 files that were missing them
- [x] Fix renderEvidence() data key mismatch (`data.domains` → `data.evidenceByDomain`)
- [x] Fix renderCCMDomains() to handle `controlDomains` key in JSON
- [x] Fix renderRiskChecklist() field name (`c.item` not `c.check`)
- [x] Fix renderSectorDetail() title (`data.sectorName` not `sector.name`)
- [x] Add RMiT clauses to search function
- [x] Replace hardcoded counts with dynamic values in overview and CCM views
- [x] Ensure all domain IDs are consistent across requirements, controls, evidence, and artifacts (validated by validate.js)
- [x] Add controlSlugs to all artifacts (Audit Package pattern — artifacts ↔ controls mapping)
- [x] Audit Package UI in control detail view — shows related artifacts (by controlSlugs) and evidence (by domain)
- [x] Well-Architected framework rendering in CSP detail pages — design principles + expandable best practice areas (AWS, Azure, GCP)

---

## Phase 6 — UI Enhancements (Pending)

- [ ] Add CSP filtering/toggle on Controls view (show/hide AWS/Azure/GCP implementation columns)
- [x] Add print-friendly CSS for compliance report generation
- [x] Add dark mode via `prefers-color-scheme: dark` (automatic, no toggle needed)
- [ ] Add export to CSV/PDF for controls and requirements tables
- [ ] Add compliance dashboard showing coverage percentage per standard

---

## Known Accuracy Notes

- CSA CCM v4 content is paraphrased — `sourceType: "paraphrased-from-standard"` on CCM files. Obtain normative text from cloudsecurityalliance.org.
- CIS Benchmark content is indicative — control descriptions summarised, not verbatim. Obtain full benchmarks from cisecurity.org.
- BNM RMiT content is paraphrased from the November 2025 policy document — `sourceType: "paraphrased-from-regulation"`. Obtain authoritative text from BNM. Appendix 10 content is indicative.
- NACSA Act 854 codes of practice **not yet gazetted** as of 2026-03 — sector-specific content marked `constructed-indicative`.
- MITRE ATT&CK Cloud technique IDs are public domain from attack.mitre.org.
- Alibaba and Huawei data residency regions (ap-southeast-3, Kuala Lumpur) verified against CSP documentation.
- AWS/Azure/GCP have no dedicated Malaysia region as of 2026-03.
