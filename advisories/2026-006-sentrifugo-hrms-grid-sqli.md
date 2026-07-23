# SQL Injection — Sentrifugo HRMS grid `sort` / `by` / `searchData` (systemic, ~110 endpoints)

**Advisory ID:** 2026-006 · **Researcher:** anon87111 · **Status:** Draft
**Product:** Sentrifugo HRMS **3.2 and current `master` (`0ddb8c14`)** (Sapplica; project dormant since 2017)
**Class:** CWE-89 SQL Injection · **Severity:** High — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (8.1)

## Summary
Any authenticated Sentrifugo user — including a low-privilege employee — can inject arbitrary SQL through the `sort`, `by`, and `searchData` parameters that every "grid"/list screen accepts. The values are concatenated unvalidated into the `ORDER BY` and `WHERE` clauses, giving full read access to the database, including administrator password hashes. Roughly 110 endpoints share the flaw.

## Affected component
Representative: `application/modules/default/models/Accountclasstype.php` (`getAccountClassTypeData`), reached from `AccountclasstypeController.php`. The same `getGrid()` / `get<X>Data()` pattern backs ~110 grid controllers.
```php
// controller — raw request input, no allowlist:
$sort = $this->_getParam('sort') ?: 'DESC';
$by   = $this->_getParam('by')   ?: 'modifieddate';
$searchData = $this->_getParam('searchData');
// model:
$where .= " AND ".$searchQuery;                 // (2) searchData -> WHERE (raw)
$this->select()->setIntegrityCheck(false)
     ->where($where)
     ->order("$by $sort");                       // (1) sort/by -> ORDER BY (raw)
```

## Details — why `Zend_Db_Select::order()` does not save it
Zend Framework 1's `order()` splits a trailing `ASC|DESC`, then:
```php
if (preg_match('/\(.*\)/', $val)) { $val = new Zend_Db_Expr($val); }
```
Any value containing parentheses becomes a `Zend_Db_Expr`, which `_renderOrder()` emits **verbatim** (`quoteIdentifier()` returns a `Zend_Db_Expr` unchanged). So a parenthesised subquery or function in `by` (or `sort`) is placed raw into `ORDER BY`. Only `models/Requisition.php` allowlists its sort column; every other grid model is unguarded.

## Proof of Concept
Authenticated session; any grid endpoint. Time-based:
```
GET /index.php/accountclasstype/index?sort=ASC&by=(SELECT(SLEEP(5)))
```
The query becomes `... ORDER BY (SELECT(SLEEP(5))) ASC LIMIT ...` — a ≥5s delay confirms injection. Boolean- and error-based extraction, and `UNION`-based extraction via `searchData`, follow the same path. A self-contained harness that drives the real ZF1 `order()` render path and fires three oracles (raw payload in `ORDER BY`, boolean order-flip, SQL parser error) accompanies this advisory. External corroboration: the same class was exploitable in Sentrifugo 3.2 (Exploit-DB 45266).

## Impact
Full database read as any authenticated user — employee PII, payroll, stored card records (`main_creditcarddetails`), and the `main_users` credential table (password hashes).

## Affected / patched
Affected: 3.2 and all earlier releases, and current `master` (`0ddb8c14`). Patched: none — project dormant since 2017.

## Remediation
Allowlist the sort column and constrain the direction to `ASC|DESC` in every grid model (as `Requisition.php` already does); parameterise or validate `searchData`. A shared sanitising helper across all `getGrid()` call sites is the durable fix.

## Dedup / disclosure
Distinct from the 2018–2020 Sentrifugo 3.2 CVEs (report endpoints `deptid` / `sortby` / `sort_name`); this is the systemic `getGrid` class across ~110 other endpoints, unfixed on `master`. Vendor dormant → self-published + MITRE CVE request (CNA-LR).

## References
- Advisory: (this file's public URL once pushed)
- https://github.com/Sentrifugo/sentrifugo
- https://www.exploit-db.com/exploits/45266

## Credit
anon87111
