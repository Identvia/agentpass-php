<?php
/**
 * Demo: a todo list that AI agents can use for a person via AgentPass.
 *  - Agents get an API bearer token (bearer_token) or a browser session (browser_session).
 *  - Every request re-checks the delegation with the Authority (cached ≤ 60 s), so revoking in Identvia stops the agent.
 * There is deliberately no human password login in this demo.
 */
declare(strict_types=1);

require __DIR__ . '/../../../vendor/autoload.php';

use AgentPass\Service\AgentPassError;
use AgentPass\Service\Dns\StaticDnsResolver;
use AgentPass\Service\Dns\SystemDnsResolver;
use AgentPass\Service\Http\CurlHttpClient;
use AgentPass\Service\Response;
use AgentPass\Service\Service;
use AgentPass\Service\ServiceConfig;
use AgentPass\Service\Store\PdoStore;

$cfgFile = getenv('TODO_CONFIG') ?: __DIR__ . '/../config.php';
$cfg = require (is_file($cfgFile) ? $cfgFile : __DIR__ . '/../config.example.php');

$SCOPES = [
    ['name' => 'todos:read', 'description' => 'See your todo items'],
    ['name' => 'todos:write', 'description' => 'Add and complete todo items'],
    ['name' => 'todos:delete', 'description' => 'Delete todo items'],
];
$store = PdoStore::sqlite($cfg['db_file']);
$pdo = new PDO('sqlite:' . $cfg['db_file']);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->exec('PRAGMA busy_timeout=5000');
$pdo->exec('CREATE TABLE IF NOT EXISTS todos (id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT NOT NULL, title TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0, created_by_agent TEXT NULL, created_at INTEGER NOT NULL)');
$pdo->exec('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL)');

$service = new Service(new ServiceConfig(
    origin: $cfg['origin'],
    signingKeyPem: (string) file_get_contents($cfg['key_file']),
    // 'extra_authorities' => [['https://other-authority.example', 'https://other-authority.example/.../ap'], ...] (optional)
    trustedAuthorities: array_merge([ServiceConfig::authority($cfg['authority'])], array_map(fn (array $a) => ServiceConfig::authority($a[0], $a[1] ?? null), $cfg['extra_authorities'] ?? [])),
    scopes: $SCOPES,
    store: $store,
    name: $cfg['name'],
    checkCacheSeconds: (int) ($cfg['check_cache_seconds'] ?? 60),
    logger: function (string $event, array $ctx) use ($pdo) {
        $pdo->prepare('INSERT INTO events (at, event, detail) VALUES (?,?,?)')->execute([time(), $event, json_encode($ctx)]);
    },
    http: new CurlHttpClient($cfg['ca_bundle'] ?? null),
    dns: $cfg['dns'] ? new StaticDnsResolver($cfg['dns'], new SystemDnsResolver()) : new SystemDnsResolver(),
));

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = (string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);

if ($path === '/style.css') { header('Content-Type: text/css'); readfile(__DIR__ . '/style.css'); exit; }

// 1. AgentPass protocol endpoints (config, JWKS, resolve-authorities, scopes, redeem-*)
if ($service->handleGlobals()) { exit; }

$json = function (mixed $data, int $status = 200): never {
    Response::json($data, $status)->send();
    exit;
};
$h = fn ($s) => htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');

// 2. Browser session initialization (single-use link from redeem-browser-session)
if ($method === 'GET' && preg_match('#^/agentpass-service/agentpass/session/([0-9a-f]{64})$#', $path, $m)) {
    header('Cache-Control: no-store');
    try {
        $d = $service->consumeInitialization($m[1]);
    } catch (AgentPassError $e) {
        http_response_code($e->status);
        echo '<!doctype html><title>Link not valid</title><link rel="stylesheet" href="/style.css"><main><h1>This sign-in link can\'t be used</h1><p>' . $h($e->getMessage()) . '</p></main>';
        exit;
    }
    session_name('todo_sid');
    session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
    session_start();
    session_regenerate_id(true);
    $_SESSION = ['authz' => $d->authorizationId, 'csrf' => bin2hex(random_bytes(16))];
    header('Location: ' . $service->safeRedirect($d, '/'), true, 303);
    exit;
}

// 3. JSON API for bearer tokens
if (str_starts_with($path, '/api/')) {
    try {
        $d = $service->authenticateBearer($_SERVER['HTTP_AUTHORIZATION'] ?? '');
    } catch (AgentPassError $e) {
        header('WWW-Authenticate: Bearer error="invalid_token"');
        $json($e->toArray(), $e->status);
    }
    $need = fn (string $s) => $d->can($s) ?: $json(['error' => ['code' => 'insufficient_scope', 'message' => "Requires $s"]], 403);
    if ($method === 'GET' && $path === '/api/me') { $json(['user' => $d->userEmail, 'agent' => $d->agentId, 'scope' => $d->scope]); }
    if ($method === 'GET' && $path === '/api/todos') {
        $need('todos:read');
        $st = $pdo->prepare('SELECT id, title, done, created_by_agent FROM todos WHERE owner = ? ORDER BY id');
        $st->execute([$d->userEmail]);
        $json(['todos' => array_map(fn ($r) => ['id' => (int) $r['id'], 'title' => $r['title'], 'done' => (bool) $r['done'], 'created_by_agent' => $r['created_by_agent']], $st->fetchAll(PDO::FETCH_ASSOC))]);
    }
    if ($method === 'POST' && $path === '/api/todos') {
        $need('todos:write');
        $b = json_decode((string) file_get_contents('php://input'), true);
        $title = is_array($b) && is_string($b['title'] ?? null) ? trim(mb_substr($b['title'], 0, 200)) : '';
        if ($title === '') { $json(['error' => ['code' => 'invalid_request', 'message' => 'title is required']], 400); }
        $pdo->prepare('INSERT INTO todos (owner, title, created_by_agent, created_at) VALUES (?,?,?,?)')->execute([$d->userEmail, $title, $d->agentId, time()]);
        $json(['id' => (int) $pdo->lastInsertId(), 'title' => $title, 'done' => false], 201);
    }
    if ($method === 'DELETE' && preg_match('#^/api/todos/(\d+)$#', $path, $m)) {
        $need('todos:delete');
        $st = $pdo->prepare('DELETE FROM todos WHERE id = ? AND owner = ?');
        $st->execute([(int) $m[1], $d->userEmail]);
        $st->rowCount() ? $json(['deleted' => true]) : $json(['error' => ['code' => 'not_found', 'message' => 'No such todo']], 404);
    }
    $json(['error' => ['code' => 'not_found', 'message' => 'No such endpoint']], 404);
}

// 4. Browser UI (agent-attributed session)
session_name('todo_sid');
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
session_start();
$d = null; $notice = null;
if (isset($_SESSION['authz'])) {
    try {
        $d = $service->checkDelegation($_SESSION['authz']);
    } catch (AgentPassError $e) {
        $notice = $e->status === 401 ? 'Your access was revoked, so this session has ended.' : 'We could not confirm your access right now. Try again shortly.';
        if ($e->status === 401) { $_SESSION = []; session_destroy(); }
    }
}
if ($method === 'POST' && $d) {
    if (!hash_equals($_SESSION['csrf'] ?? '', (string) ($_POST['csrf'] ?? ''))) { http_response_code(400); exit('Bad CSRF token'); }
    if ($path === '/todos' && $d->can('todos:write')) {
        $title = trim(mb_substr((string) ($_POST['title'] ?? ''), 0, 200));
        if ($title !== '') { $pdo->prepare('INSERT INTO todos (owner, title, created_by_agent, created_at) VALUES (?,?,?,?)')->execute([$d->userEmail, $title, $d->agentId, time()]); }
    } elseif (preg_match('#^/todos/(\d+)/done$#', $path, $m) && $d->can('todos:write')) {
        $pdo->prepare('UPDATE todos SET done = 1 WHERE id = ? AND owner = ?')->execute([(int) $m[1], $d->userEmail]);
    } else {
        http_response_code(403); exit('Not allowed with the access you approved');
    }
    header('Location: /', true, 303);
    exit;
}
if ($path !== '/') { http_response_code(404); exit('Not found'); }

header('Cache-Control: no-store');
?><!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title><?= $h($cfg['name']) ?></title><link rel="stylesheet" href="/style.css"></head>
<body><main>
<h1><?= $h($cfg['name']) ?></h1>
<?php if ($notice): ?><p class="notice" role="alert"><?= $h($notice) ?></p><?php endif; ?>
<?php if (!$d): ?>
  <p>This demo has no password login: an AI agent opens it for you with an <strong>AgentPass</strong> you approve in your Authority (for example Identvia).</p>
<?php else:
  $st = $pdo->prepare('SELECT * FROM todos WHERE owner = ? ORDER BY id'); $st->execute([$d->userEmail]); $todos = $st->fetchAll(PDO::FETCH_ASSOC); ?>
  <p class="who">Signed in as <strong data-user><?= $h($d->userEmail) ?></strong> through agent <code data-agent><?= $h($d->agentId) ?></code> · access: <code data-scope><?= $h(implode(' ', $d->scope)) ?></code></p>
  <?php if ($d->can('todos:read')): ?>
  <ul data-todos><?php foreach ($todos as $t): ?>
    <li><?= $t['done'] ? '<s>' . $h($t['title']) . '</s>' : $h($t['title']) ?>
      <?php if (!$t['done'] && $d->can('todos:write')): ?><form method="post" action="/todos/<?= (int) $t['id'] ?>/done"><input type="hidden" name="csrf" value="<?= $h($_SESSION['csrf']) ?>"><button>Done</button></form><?php endif; ?></li>
  <?php endforeach; ?></ul>
  <?php endif; ?>
  <?php if ($d->can('todos:write')): ?>
  <form method="post" action="/todos"><input type="hidden" name="csrf" value="<?= $h($_SESSION['csrf']) ?>"><label for="t">New todo</label> <input id="t" name="title" maxlength="200" required> <button>Add</button></form>
  <?php endif; ?>
<?php endif; ?>
</main></body></html>
