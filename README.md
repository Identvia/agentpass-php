# identvia/agentpass-php

AgentPass v0.1 **Service** SDK for PHP 8.1+. It lets AI agents act for your users at your site, with the
user's explicit approval at a trusted Authority such as [Identvia](https://identvia.com). Each AgentPass is
**single-use**, **holder-bound** (proof of possession) and **task-scoped**. Delegations are re-checked
continuously, so a revocation at the Authority stops the agent.

> AgentPass v0.1 is a draft specification (pinned at `clerk/agentpass@937efe3`) and this SDK has not had an
> independent security audit. Don't put irreversible or high-value actions behind it yet.

No framework is needed and it works on shared hosting: plain PHP, `openssl`, `curl`, `pdo_sqlite` or `pdo_mysql`.
The only dependency is `firebase/php-jwt`.

## Install

```sh
composer require identvia/agentpass-php
```

Without Composer (cPanel), download `agentpass-php-<version>.zip` from `https://<identvia>/sdk/agentpass-php/`.
It includes `vendor/`. Upload it outside `public_html` and `require 'agentpass-php/vendor/autoload.php';`.

## 1. Key and DNS

```sh
php vendor/bin/agentpass-keygen /home/you/agentpass-key.pem    # keep it outside public_html
```

Publish one TXT record so Authorities can find your configuration. `$service->config()->dnsRecord()` prints it.

```
_agentpass-service.todo.example.com.  TXT  "https://todo.example.com/agentpass-service/config.json"
```

## 2. Wire it up

```php
use AgentPass\Service\{Service, ServiceConfig, AgentPassError};
use AgentPass\Service\Store\PdoStore;

$service = new Service(new ServiceConfig(
    origin: 'https://todo.example.com',
    signingKeyPem: file_get_contents('/home/you/agentpass-key.pem'),
    trustedAuthorities: [ServiceConfig::authority('https://identvia.com')],
    scopes: [
        ['name' => 'todos:read',  'description' => 'See your todo items'],
        ['name' => 'todos:write', 'description' => 'Add and complete todo items'],
    ],                                    // or a callable(array $ctx): array, per user/agent
    store: PdoStore::sqlite('/home/you/data/agentpass.sqlite'),   // or new PdoStore($pdo) for MySQL
    name: 'Todo',
));

// Front controller: serves /agentpass-service/* (config, JWKS, resolve-authorities, scopes, redeem-*)
if ($service->handleGlobals()) { exit; }
```

### Bearer tokens (API)

```php
try {
    $d = $service->authenticateBearer($_SERVER['HTTP_AUTHORIZATION'] ?? '');
    if (!$d->can('todos:write')) { http_response_code(403); exit; }
    // act as $d->userEmail, attributed to $d->agentId
} catch (AgentPassError $e) {
    http_response_code($e->status);            // 401 revoked/unknown, 503 Authority unreachable (fail closed)
    echo json_encode($e->toArray());
}
```

### Browser sessions

Redemption returns a one-time `initialization_url` (`/agentpass-service/agentpass/session/{token}`, 60 s).
On that route:

```php
$d = $service->consumeInitialization($token);   // single use: 410 when reused, 404 when unknown
session_regenerate_id(true);
$_SESSION['agent'] = $d->authorizationId;        // mark the session as "via agent"
header('Location: ' . $service->safeRedirect($d)); // same-origin only
```

On every later request, call `$service->checkDelegation($_SESSION['agent'])`. It re-checks with the Authority
at most every `checkCacheSeconds` (≤ 60).

## What the SDK enforces

- Authority resolution with enterprise precedence (`_agentpass.<domain>`: a URL means that Authority only;
  `none` means 403).
- Validation with the Authority using a short-lived ES256 assertion signed by your key (single use is
  enforced by the Authority; replay → `409 agentpass_replayed`).
- **Holder binding:** when the validation carries `cnf`, a `harness_proof` is required (aud = your origin, iss,
  ≤ 5 min, single-use `jti`).
- The redeem body's `user.email` must match the validated user, the type must match, and scopes are intersected
  with what you offer and what was requested. `*` is never honoured beyond your own list.
- `available_scopes` only answers Authorities that resolution allows for that user, with a verified assertion
  (aud, lifetime, `jti` replay).
- Bearer tokens (`apt_…`) are stored as SHA-256 hashes. Revocation invalidates them locally.
- Fail closed: if the Authority can't be reached, requests get `503`, never access.

## Demo

`examples/todo` is a complete todo service that accepts both redemption types. See `config.example.php`.

```sh
TODO_CONFIG=/path/to/config.php php -S 127.0.0.1:8091 -t examples/todo/public examples/todo/router.php
```

## Tests

`vendor/bin/phpunit` runs an in-process fake Authority with real ES256 keys (14 tests). The Identvia repo
also runs this SDK end to end against Identvia and against Clerk's reference Authority.

MIT licensed.
