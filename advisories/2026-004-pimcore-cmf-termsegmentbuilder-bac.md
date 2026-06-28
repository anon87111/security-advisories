# Broken Access Control — CMF `TermSegmentBuilderController` missing authorization (information disclosure)

**Component:** `pimcore/customer-management-framework-bundle` **≤ 4.2.4** (GPL, EOL). **CWE-862** Missing
Authorization. **Severity:** Medium — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (~4.3). **Credit:** anon87111.

## Issue
`src/Controller/Report/TermSegmentBuilderController.php` (`extends UserAwareController`) defines **no**
`onKernelControllerEvent` / `checkPermission('plugin_cmf_perm_*')`, unlike the sibling CMF controllers. Routed
under `/admin/customermanagementframework/report` (login firewall), so **any authenticated backend user without
CMF permissions** can reach it.

## Endpoint
- `GET /admin/customermanagementframework/report/term-segment-builder/get-segment-builder-definitions`
  (`getSegmentBuilderDefinitionsAction`) — enumerates the configured term-segment-builder definitions.

## PoC (live; full transcript in `_reproduction.md`)
Actor `lowpriv` (`admin=false`, no `plugin_cmf_perm_*`):
- `GET /report/term-segment-builder/get-segment-builder-definitions` → **200**
- `GET /customers/list` *(permission-gated control)* → **403**

## Impact
Information disclosure of segmentation-rule (term-segment-builder) definitions to an unauthorized backend user —
reveals customer-segmentation logic/strategy.

## Remediation
Add the `checkPermission('plugin_cmf_perm_*')` gate in `onKernelControllerEvent`. EOL — no vendor patch.

## Dedup / disclosure
Novel — not among the 9 published CMF advisories. GitHub private advisory on `pimcore/customer-data-framework`
(archived) → **MITRE** CVE request.
