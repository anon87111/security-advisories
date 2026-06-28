# Broken Access Control — CMF `SegmentAssignmentController` missing authorization (read + write)

**Component:** `pimcore/customer-management-framework-bundle` **≤ 4.2.4** (GPL, EOL). **CWE-862** Missing
Authorization. **Severity:** Medium — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` (~5.4). **Credit:** anon87111.

## Issue
`src/Controller/Admin/SegmentAssignmentController.php` (`extends UserAwareController`) defines **no**
`onKernelControllerEvent` / `checkPermission('plugin_cmf_perm_*')`, unlike the sibling CMF controllers
(`Customers`/`Activities`/`Duplicates`/`GDPR`/`Rules`, which all call `checkPermission(...)`). Its routes are under
the `/admin/customermanagementframework` login firewall, so **any authenticated backend user without CMF
permissions** can read and modify segment assignments.

## Endpoints (prefix `/admin/customermanagementframework`)
- `POST /segment-assignment/assign` — **write**: `assignById($id, $type, $breaksInheritance, $segmentIds)`
- `GET /segment-assignment/{assigned-segments,inheritable-segments,breaks-inheritance}` — read assignments

## PoC (live; full transcript in `_reproduction.md`)
Pimcore 11 + CMF 4.2.4; actor `lowpriv` (`admin=false`, no `plugin_cmf_perm_*`):
- `POST /segment-assignment/assign` → **HTTP 200**, body `true` (write executed)
- `GET /customers/list` *(permission-gated control)* → **403**

Same session, 200 on the ungated write vs 403 on the gated control ⇒ missing authorization.

## Impact
Integrity: a non-CMF user reassigns any element to arbitrary segments, corrupting segmentation / personalization /
marketing-automation targeting; plus read of assignment data.

## Remediation
Add `checkPermission('plugin_cmf_perm_customerview')` in `onKernelControllerEvent`, as the sibling controllers do.
(EOL — no vendor patch; mitigate by restricting CMF-permissioned backend accounts or migrate to the Enterprise
Edition.)

## Dedup / disclosure
Novel — not among the 9 published CMF advisories (Rules = CVE-2023-3574, GDPR, duplicates list, segment-assignment
**SQLi** = GHSA-25fx-3c2q-cq46 are all distinct). Report via GitHub private advisory on
`pimcore/customer-data-framework` (archived — may not engage) → **MITRE** CVE request as fallback.
