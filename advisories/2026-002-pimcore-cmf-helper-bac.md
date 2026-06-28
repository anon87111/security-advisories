# Broken Access Control — CMF `HelperController` missing authorization (information disclosure)

**Component:** `pimcore/customer-management-framework-bundle` **≤ 4.2.4** (GPL, EOL). **CWE-862** Missing
Authorization. **Severity:** Medium — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N` (~4.3). **Credit:** anon87111.

## Issue
`src/Controller/Admin/HelperController.php` (`extends UserAwareController`) defines **no** `onKernelControllerEvent`
/ `checkPermission('plugin_cmf_perm_*')`, unlike the sibling CMF controllers. Routed under the
`/admin/customermanagementframework` login firewall, so **any authenticated backend user without CMF permissions**
can read CMF/customer configuration.

## Endpoints (prefix `/admin/customermanagementframework`)
- `GET /helper/settings-json` — CMF settings + customer class name + segment-assignment config
- `GET /helper/grouped-segments` — full segment taxonomy (id, name, group)
- `GET /helper/customer-field-list` — customer class field schema
- `GET /helper/activity-types` — configured activity types

## PoC (live; full transcript in `_reproduction.md`)
Actor `lowpriv` (`admin=false`, no `plugin_cmf_perm_*`):
- `GET /helper/settings-json` → **200**, returns e.g.
  `pimcore.settings.cmf = {"newsletterSyncEnabled":false,...,"customerClassName":"Customer","segmentAssignment":{...}}`
- `GET /helper/grouped-segments` → **200**
- `GET /customers/list` *(permission-gated control)* → **403**

200 on the helper endpoints vs 403 on the gated control, same session ⇒ missing authorization.

## Impact
Information disclosure: the customer data model (class + field schema), the complete segment taxonomy, and CMF
configuration — useful for mapping the deployment and staging further attacks.

## Remediation
Add `checkPermission('plugin_cmf_perm_customerview')` in `onKernelControllerEvent` (as siblings do). EOL — no
vendor patch.

## Dedup / disclosure
Novel — not among the 9 published CMF advisories. GitHub private advisory on `pimcore/customer-data-framework`
(archived) → **MITRE** CVE request.
