# Security Advisories

Independent vulnerability research by **anon87111**. Every advisory here is reproduced with a working
proof-of-concept before publication. Disclosure is coordinated with the vendor where a security channel exists;
where the project is archived/abandoned, the advisory is self-published and a CVE ID is requested from MITRE.

## Index

| ID | Title | Product (affected) | Class | Severity | Status | CVE |
|----|-------|--------------------|-------|----------|--------|-----|
| [2026-001](advisories/2026-001-pimcore-cmf-segment-assignment-bac.md) | Broken access control — `SegmentAssignmentController` (read + write) | Pimcore CMF ≤ 4.2.4 | CWE-862 | Medium | Draft | — |
| [2026-002](advisories/2026-002-pimcore-cmf-helper-bac.md) | Broken access control — `HelperController` (information disclosure) | Pimcore CMF ≤ 4.2.4 | CWE-862 | Medium | Draft | — |
| [2026-003](advisories/2026-003-pimcore-cmf-templates-bac.md) | Broken access control — `TemplatesController` (unauthorized export) | Pimcore CMF ≤ 4.2.4 | CWE-862 | Medium | Draft | — |
| [2026-004](advisories/2026-004-pimcore-cmf-termsegmentbuilder-bac.md) | Broken access control — `TermSegmentBuilderController` (information disclosure) | Pimcore CMF ≤ 4.2.4 | CWE-862 | Medium | Draft | — |
| [2026-005](advisories/2026-005-pimcore-cmf-newsletter-rce.md) | OS command injection — newsletter queue (unescaped customer email) | Pimcore CMF ≤ 4.2.4 | CWE-78 | High&dagger; | Draft | — |
| [2026-006](advisories/2026-006-sentrifugo-hrms-grid-sqli.md) | SQL injection — grid `sort`/`by`/`searchData` (systemic, ~110 endpoints) | Sentrifugo HRMS 3.2 & `master` | CWE-89 | High | Draft | ⧗ MITRE |
| [2026-007](advisories/2026-007-talelin-lin-cms-koa-hardcoded-jwt-secret.md) | Use of hard-coded JWT signing secret (auth bypass) | lin-cms-koa ≤ 0.3.11 | CWE-321 | Critical | CVE-Requested | ⧗ MITRE |

*(`Status`: Draft → Published → CVE-Requested → CVE-Assigned. Shared reproduction for the CMF set:
[`advisories/_reproduction.md`](advisories/_reproduction.md).)*

&dagger; *2026-005: command-injection impact is High/Critical, but conditional on the newsletter-sync feature being
enabled (off by default; on for installs that use the MailChimp/newsletter integration).*

## How this repo is organised
- One self-contained Markdown file per advisory under `advisories/`, named `YYYY-NNN-vendor-product-shortclass.md`.
- `NNN` is a per-year sequence — bump it for each new finding so IDs are stable and citable.
- The table above is the source of truth for status + assigned CVE IDs.
- `TEMPLATE.md` is the starting point for any new advisory.

## Disclosure policy
Good-faith research. Vendors/maintainers are given a private report first where a channel exists; if a project is
archived/abandoned with no security contact, details are published here and a CVE is requested from MITRE so
operators of the (still-deployed) software can identify and mitigate the issue. No exploitation beyond a local lab.
Contact: via GitHub.
