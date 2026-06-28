# Broken Access Control — CMF `TemplatesController` missing authorization (unauthorized export)

**Component:** `pimcore/customer-management-framework-bundle` **≤ 4.2.4** (GPL, EOL). **CWE-862** Missing
Authorization. **Severity:** Medium — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N` (~5.4). **Credit:** anon87111.

## Issue
`src/Controller/Admin/TemplatesController.php` (`extends UserAwareController`) defines **no**
`onKernelControllerEvent` / `checkPermission('plugin_cmf_perm_*')`, unlike the sibling CMF controllers. Under the
`/admin/customermanagementframework` login firewall, so **any authenticated backend user without CMF permissions**
can invoke it.

## Endpoint
- `POST /admin/customermanagementframework/templates/export` — `exportAction()`:
  `$document = PageSnippet::getById($request->request->getInt('document_id')); $templateExporter->exportTemplate($document);`
  Triggers export of an arbitrary PageSnippet (by `document_id`) to the configured external provider (e.g. Mailchimp).

## PoC
Reachable by `lowpriv` (`admin=false`, no `plugin_cmf_perm_*`) — same login as `_reproduction.md`; the controller has no
permission gate (contrast `/customers/list` → 403 for the same user). Supply a valid `document_id` to trigger an
export as a non-CMF user.

## Impact
Unauthorized action / integrity: a non-CMF user triggers template exports to an external newsletter provider
(unexpected outbound data flow + state change), plus error-based existence probing of PageSnippet ids.

## Remediation
Add the `checkPermission('plugin_cmf_perm_*')` gate in `onKernelControllerEvent`. EOL — no vendor patch.

## Dedup / disclosure
Novel — not among the 9 published CMF advisories. GitHub private advisory on `pimcore/customer-data-framework`
(archived) → **MITRE** CVE request.
