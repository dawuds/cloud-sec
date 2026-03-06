# Cloud Security Framework

A structured, open-access knowledge base for cloud cybersecurity — covering CSA CCM v4, CIS Benchmarks (AWS/Azure/GCP/Alibaba/Huawei/OCI), MITRE ATT&CK Cloud, NIST Cloud Security, and Malaysia regulatory compliance (NACSA Act 854, BNM RMiT).

**Primary Standard:** CSA Cloud Controls Matrix v4
**Malaysia Focus:** BNM RMiT cloud requirements + NACSA Act 854 cross-referenced throughout
**Audience:** Cloud security engineers, GRC practitioners, auditors, Malaysian financial institutions

---

## Important Notice

> This resource is for educational and indicative purposes only. It does not constitute legal or technical advice. CSA CCM v4 content is paraphrased — obtain normative text from [cloudsecurityalliance.org](https://cloudsecurityalliance.org). BNM RMiT content is paraphrased from the November 2025 policy document — obtain authoritative text from BNM. NACSA Act 854 references are indicative — verify against official Gazette text. CIS Benchmark content is indicative — obtain full benchmarks from [cisecurity.org](https://cisecurity.org). All content marked `sourceType: "constructed-indicative"` has not been verified against official sources.

---

## What This Repository Covers

| Layer | Content |
|---|---|
| **Standards** | CSA CCM v4 (17 domains), MITRE ATT&CK Cloud (35 techniques), NIST SP 800-144/800-210 |
| **RMiT Cloud** | BNM RMiT cloud-specific clauses (10.50-10.52, 17.1-17.5), Appendix 10 domains, CCM v4 mapping |
| **Architecture** | Shared responsibility model, reference architecture, service models (IaaS/PaaS/SaaS), asset types, CSP comparison |
| **Cloud Providers** | AWS, Azure, GCP, Alibaba, Huawei, Oracle — services inventory, CIS Benchmarks, Well-Architected guidance |
| **Requirements** | 12 security domains with detailed requirements, CCM/NACSA/NIST CSF/MITRE mappings |
| **Controls** | 49 controls with maturity levels, CSP-specific implementation guidance |
| **Evidence** | Audit evidence items per domain — what auditors look for |
| **Artifacts** | 29 security artifacts — policies, procedures, reports, configurations |
| **Threats** | 8 cloud incidents (Capital One, SolarWinds, Log4Shell, Storm-0558, Snowflake, etc.) + 6 threat actors |
| **Risk Management** | Cloud risk methodology, 5x5 matrix, 15-risk register, assessment checklist, treatment options |
| **Sectors** | Financial services, healthcare, government, e-commerce, education, telecommunications — with Malaysia-specific obligations |
| **Cross-References** | CCM ↔ NACSA Act 854, NIST CSF 2.0, ISO 27017, MITRE ATT&CK, AWS/Azure/GCP service mappings |

---

## BNM RMiT Cloud Integration

For Malaysian financial institutions adopting cloud:

| RMiT Clause | Requirement | Framework Response |
|---|---|---|
| **10.50** | Comprehensive cloud risk assessment | 10 risk areas mapped to CCM controls |
| **10.51** | Appendix 10 key risks and controls | 8 control domains with CCM mapping |
| **10.52** | Data residency in Malaysia | CSP region comparison table (Alibaba/Huawei have KL regions) |
| **17.1** | First-time BNM consultation | Prerequisites with CCM control evidence |
| **17.2** | Subsequent cloud notification | Preconditions and assurance requirements |
| **17.5** | Annual cloud roadmap | Governance programme alignment |

See full mapping: [`standards/rmit-cloud/ccm-mapping.json`](standards/rmit-cloud/ccm-mapping.json)

---

## NACSA Act 854 Integration

For Malaysian NCII-designated cloud operators:

| Act 854 Obligation | Cloud Security Framework Response |
|---|---|
| **s17** — NCII designation | Cloud asset inventory scope definition |
| **s18** — Security measures | CCM v4 control implementation at appropriate maturity |
| **s21** — Risk assessment | Cloud risk methodology with 15-risk register |
| **s22** — Code of practice | Sector-specific cloud requirements |
| **s23** — Security audit | Evidence items and artifact inventory per domain |
| **s26** — Incident notification | 6-hour NACSA + 24-hour BNM notification procedures |

See full mapping: [`cross-references/ccm-to-nacsa.json`](cross-references/ccm-to-nacsa.json)

---

## Quick Reference: Cloud Providers

| CSP | CIS Benchmark | Malaysia Region | Data Residency |
|---|---|---|---|
| AWS | CIS AWS v3.0 (35 checks) | No (nearest: ap-southeast-1 Singapore) | SCP region restriction |
| Azure | CIS Azure v2.1 (48 checks) | No (nearest: Southeast Asia Singapore) | Azure Policy allowedLocations |
| GCP | CIS GCP v3.0 (41 checks) | No (nearest: asia-southeast1 Singapore) | Org Policy resourceLocations |
| Alibaba | CIS Alibaba v1.0 (34 controls) | **Yes** — ap-southeast-3 (Kuala Lumpur) | Deploy in KL region |
| Huawei | Best Practices (23 checks) | **Yes** — ap-southeast-3 (Kuala Lumpur) | Deploy in KL region |
| Oracle | CIS OCI v2.0 (42 controls) | No (nearest: ap-singapore-1) | Compartment policies |

---

## Key Incidents Referenced

| Incident | Year | Impact | Key Lesson |
|---|---|---|---|
| Capital One | 2019 | 100M records exposed | SSRF via misconfigured WAF; least privilege on IAM roles |
| SolarWinds | 2020 | 18,000 organisations compromised | Supply chain integrity; build pipeline security |
| Log4Shell | 2021 | Critical RCE in ubiquitous library | Dependency scanning; WAF virtual patching |
| Storm-0558 | 2023 | US government email compromise | Token signing key protection; key rotation |
| Snowflake | 2024 | 165+ customer breaches | MFA enforcement; credential hygiene |

---

## Repository Structure

```
cloud-sec/
├── index.html                          # SPA entry point
├── app.js                              # All rendering logic (1,575 lines)
├── style.css                           # Full CSS with CSP-specific colours (484 lines)
├── favicon.svg                         # SVG shield with "CS" branding
├── LICENSE                             # CC BY 4.0
├── .github/workflows/pages.yml         # GitHub Pages deployment
├── standards/
│   ├── csa-ccm/                        # CCM v4 overview + 17 control domains
│   ├── mitre-attack-cloud/             # 35 cloud ATT&CK techniques
│   ├── nist-cloud/                     # NIST SP 800-144/800-210
│   ├── rmit-cloud/                     # BNM RMiT cloud clauses + CCM mapping
│   └── csp/
│       ├── aws/                        # Index, services, CIS benchmark (35), Well-Architected
│       ├── azure/                      # Index, services, CIS benchmark (48), Well-Architected
│       ├── gcp/                        # Index, services, CIS benchmark (41), Well-Architected
│       ├── alibaba/                    # Index, services, CIS benchmark (34)
│       ├── huawei/                     # Index, services, best practices (23)
│       └── oracle/                     # Index, services, CIS benchmark (42)
├── architecture/                       # Shared responsibility, reference arch, service models
├── controls/                           # 12 domains + 49 controls library
├── requirements/
│   ├── index.json                      # 12 domain overview
│   └── by-domain/                      # Per-domain requirement files (12 files)
├── evidence/                           # Audit evidence items
├── artifacts/                          # 29 security artifacts inventory
├── threats/                            # 8 incidents + 6 threat actors
├── risk-management/                    # Methodology, matrix, register, checklist
├── sectors/
│   ├── index.json                      # 6 sectors overview
│   └── requirements/                   # Per-sector requirement files (6 files)
└── cross-references/                   # 7 cross-reference mappings
```

**Total:** 72 JSON data files, 14 views, zero dependencies

---

## Technical Architecture

Static single-page application (SPA):

- **Zero dependencies** — no build step, no framework, no npm
- **Hash-routed** — `#view/sub` pattern, pushState for clean navigation
- **Lazy-loaded JSON** — data fetched on demand and cached in `Map`
- **GitHub Pages** — deployed via Actions workflow on push to `main`
- **CSP-specific colours** — AWS (#FF9900), Azure (#0078D4), GCP (#4285F4), Alibaba (#FF6A00), Huawei (#CF0A2C), Oracle (#F80000)
- **Dark mode** — automatic via `prefers-color-scheme: dark` with WCAG AA contrast
- **Print styles** — clean output for compliance report generation
- **Favicon** — SVG shield with "CS" branding
- **License** — CC BY 4.0 (Creative Commons Attribution)

---

## Standards Referenced

- **CSA CCM v4** — Cloud Controls Matrix (paraphrased; obtain from cloudsecurityalliance.org)
- **CIS Benchmarks** — AWS v3.0 (35 checks), Azure v2.1 (48 checks), GCP v3.0 (41 checks), Alibaba v1.0 (34 checks), OCI v2.0 (42 checks), Huawei best practices (23 checks) (indicative; obtain from cisecurity.org)
- **MITRE ATT&CK Cloud** — Cloud adversary tactics and techniques (public; attack.mitre.org/matrices/enterprise/cloud)
- **NIST SP 800-144** — Guidelines on Security and Privacy in Public Cloud Computing (public; nvlpubs.nist.gov)
- **NIST SP 800-210** — General Access Control Guidance for Cloud Systems (public; nvlpubs.nist.gov)
- **NIST CSF 2.0** — Cybersecurity Framework (public; nist.gov/cyberframework)
- **ISO/IEC 27017** — Cloud-specific information security controls (indicative; obtain from iso.org)
- **BNM RMiT** — Risk Management in Technology, November 2025 (paraphrased; obtain from bnm.gov.my)
- **NACSA Act 854** — Cyber Security Act 2024, Malaysia (public Gazette)

---

## Related Repositories

- [dawuds/OT-Security](https://github.com/dawuds/OT-Security) — OT/ICS cybersecurity framework (IEC 62443, MITRE ATT&CK for ICS)
- [dawuds/nacsa](https://github.com/dawuds/nacsa) — NACSA Act 854 structured compliance database
- [dawuds/RMIT](https://github.com/dawuds/RMIT) — BNM RMiT full compliance database (121 clauses, 11 sections, 365 artifacts, 93 controls)
- [dawuds/pdpa-my](https://github.com/dawuds/pdpa-my) — Malaysia PDPA Act 709 + Amendment A1727
