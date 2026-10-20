<?php
declare(strict_types=1);

namespace AgentPass\Service;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

/**
 * AgentPass v0.1 Service (spec §4). Mount handle() at your origin for the protocol endpoints, then use
 * authenticateBearer() on your API and consumeInitialization() + checkDelegation() for browser sessions.
 */
final class Service
{
    public const VERSION = '0.1';
    private const SKEW = 60;

    public function __construct(private ServiceConfig $c) {}

    public function config(): ServiceConfig { return $this->c; }

    // ───────────────────────── HTTP routing ─────────────────────────

    /** Route a request. Returns null when the path is not an AgentPass endpoint. */
    public function handle(string $method, string $path, string $body = '', array $headers = []): ?Response
    {
        $h = array_change_key_case($headers, CASE_LOWER);
        $base = rtrim($this->c->basePath, '/');
        try {
            return match (true) {
                $method === 'GET' && $path === "$base/config.json" => Response::json($this->configuration(), 200, ['Cache-Control' => 'public, max-age=300']),
                $method === 'GET' && $path === "$base/jwks.json" => Response::json($this->jwks(), 200, ['Cache-Control' => 'public, max-age=3600']),
                $method === 'POST' && $path === "$base/agentpass/resolve-authorities" => Response::json($this->resolveAuthorities(self::body($body))),
                $method === 'POST' && $path === "$base/agentpass/scopes" => Response::json($this->availableScopes(self::body($body), (string) ($h['authorization'] ?? ''))),
                $method === 'POST' && $path === "$base/agentpass/redeem-browser-session" => Response::json($this->redeemBrowserSession(self::body($body))),
                $method === 'POST' && $path === "$base/agentpass/redeem-bearer-token" => Response::json($this->redeemBearerToken(self::body($body))),
                default => null,
            };
        } catch (AgentPassError $e) {
            return Response::error($e);
        }
    }

    /** Convenience for plain PHP front controllers. Returns true if it handled the request. */
    public function handleGlobals(): bool
    {
        $path = (string) parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
        $headers = ['authorization' => $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? ''];
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $body = $method === 'POST' ? (string) file_get_contents('php://input', false, null, 0, 65537) : '';
        $r = $this->handle($method, $path, $body, $headers);
        if ($r === null) { return false; }
        $r->send();
        return true;
    }

    private static function body(string $raw): array
    {
        if (strlen($raw) > 65536) { throw new AgentPassError(400, 'invalid_request', 'Body too large'); }
        $b = json_decode($raw, true);
        if (!is_array($b) || array_is_list($b)) { throw new AgentPassError(400, 'invalid_request', 'Body must be a JSON object'); }
        // Accept the schema's descriptive {"request": {...}} wrapper too.
        if (isset($b['request']) && is_array($b['request']) && count($b) === 1) { $b = $b['request']; }
        return $b;
    }

    // ───────────────────────── Configuration (§4.1) ─────────────────────────

    public function configuration(): array
    {
        $trust = [];
        if ($this->c->trustedAuthorities) { $trust['trusted_federated_authorities'] = array_values(array_map(fn ($a) => ['authority' => $a['authority'], 'authority_configuration_url' => $a['authority_configuration_url']], $this->c->trustedAuthorities)); }
        if ($this->c->serviceAuthority) { $trust['service_authority'] = $this->c->serviceAuthority; }
        $doc = [
            'version' => self::VERSION,
            'kind' => 'service',
            'service' => ['origin' => $this->c->origin] + ($this->c->name ? ['name' => $this->c->name] : []),
            'jwks_uri' => $this->c->url('/jwks.json'),
            'trust' => $trust ?: new \stdClass(),
            'endpoints' => [
                'resolve_authorities' => $this->c->url('/agentpass/resolve-authorities'),
                'redeem_browser_session' => $this->c->url('/agentpass/redeem-browser-session'),
                'redeem_bearer_token' => $this->c->url('/agentpass/redeem-bearer-token'),
                'available_scopes' => $this->c->url('/agentpass/scopes'),
            ],
        ];
        return $doc;
    }

    public function jwks(): array
    {
        return ['keys' => [$this->c->publicJwk]];
    }

    // ───────────────────────── Authority resolution (§4.2) ─────────────────────────

    public function resolveAuthorities(array $b): array
    {
        $email = self::email($b['user']['email'] ?? null);
        $r = $this->resolve($email);
        return [$r['field'] => $r['field'] === 'trusted_federated_authorities' ? $r['authorities'] : $r['authorities'][0]];
    }

    /** @return array{field:string, authorities:list<array>} */
    private function resolve(string $email): array
    {
        $domain = strtolower(substr($email, strrpos($email, '@') + 1));
        $txt = $this->c->dns->txt('_agentpass.' . $domain);
        if ($txt === null) { throw new AgentPassError(502, 'enterprise_discovery_failed', 'Enterprise discovery DNS lookup failed'); }
        $vals = array_values(array_filter(array_map(fn ($v) => trim(trim($v), '"'), $txt), fn ($v) => $v !== ''));
        if ($vals) {
            $parsed = array_values(array_filter($vals, fn ($v) => $v === 'none' || (str_starts_with($v, 'https://') && filter_var($v, FILTER_VALIDATE_URL))));
            if (count($parsed) !== 1) { throw new AgentPassError(502, 'enterprise_discovery_failed', 'Enterprise discovery record is ambiguous or invalid'); }
            if ($parsed[0] === 'none') { throw new AgentPassError(403, 'enterprise_precedence', 'The user\'s domain disables AgentPass delegation'); }
            try {
                $cfg = $this->authorityConfig($parsed[0]);
            } catch (\Throwable) {
                throw new AgentPassError(502, 'enterprise_discovery_failed', 'Could not fetch or validate the Enterprise Authority configuration');
            }
            $ent = ['authority' => $cfg['authority'], 'authority_configuration_url' => $parsed[0]];
            if ($this->c->serviceAuthority && ($cfg['policy']['allow_service_authorities'] ?? true) !== false && $this->c->preferServiceAuthority) {
                return ['field' => 'service_authority', 'authorities' => [$this->c->serviceAuthority]];
            }
            return ['field' => 'enterprise_authority', 'authorities' => [$ent]];
        }
        if ($this->c->serviceAuthority && $this->c->preferServiceAuthority) { return ['field' => 'service_authority', 'authorities' => [$this->c->serviceAuthority]]; }
        if ($this->c->trustedAuthorities) { return ['field' => 'trusted_federated_authorities', 'authorities' => array_values($this->c->trustedAuthorities)]; }
        throw new AgentPassError(404, 'no_authority', 'No Authority is available for this user');
    }

    private static function email(mixed $v): string
    {
        if (!is_string($v) || strlen($v) > 254 || !filter_var($v, FILTER_VALIDATE_EMAIL)) { throw new AgentPassError(400, 'invalid_email', 'user.email is missing or invalid'); }
        return strtolower($v);
    }

    // ───────────────────────── Scope discovery (§4.3) ─────────────────────────

    public function availableScopes(array $b, string $authorization): array
    {
        if (!preg_match('/^Bearer\s+(\S+)$/', trim($authorization), $m)) { throw new AgentPassError(401, 'invalid_assertion', 'Authority assertion required'); }
        $email = self::email($b['user']['email'] ?? null);
        if (!is_string($b['agent']['id'] ?? null) || $b['agent']['id'] === '') { throw new AgentPassError(400, 'invalid_request', 'agent.id is required'); }
        // The asking Authority must be one that resolution offers for this user (enterprise precedence applies here too).
        $claims = $this->verifyAuthorityAssertion($m[1], $this->resolve($email)['authorities']);
        return ['scopes' => array_values($this->scopeList(['user_email' => $email, 'agent_id' => $b['agent']['id'], 'task_id' => $b['task']['id'] ?? null, 'task_description' => $b['task']['description'] ?? null, 'authority' => $claims['iss']]))];
    }

    private function scopeList(array $ctx = []): array
    {
        $s = is_callable($this->c->scopes) ? ($this->c->scopes)($ctx) : $this->c->scopes;
        return array_values(array_filter((array) $s, fn ($x) => is_array($x) && is_string($x['name'] ?? null) && $x['name'] !== '*'));
    }

    /** @param list<array{authority:string, authority_configuration_url:string}> $allowed */
    private function verifyAuthorityAssertion(string $jwt, array $allowed): array
    {
        $parts = explode('.', $jwt);
        $payload = count($parts) === 3 ? json_decode((string) JWT::urlsafeB64Decode($parts[1]), true) : null;
        $iss = is_array($payload) ? ($payload['iss'] ?? null) : null;
        $trusted = null;
        foreach ($allowed as $a) { if ($a['authority'] === $iss) { $trusted = $a; } }
        if ($trusted === null) { throw new AgentPassError(403, 'untrusted_authority', 'This Authority may not delegate for this user'); }
        try {
            $cfg = $this->authorityConfig($trusted['authority_configuration_url']);
            if ($cfg['authority'] !== $trusted['authority']) { throw new \RuntimeException('authority mismatch'); }
            JWT::$leeway = self::SKEW;
            $claims = (array) JWT::decode($jwt, JWK::parseKeySet($this->fetchJson($cfg['jwks_uri'], 300), 'ES256'));
        } catch (\Throwable) {
            throw new AgentPassError(401, 'invalid_assertion', 'Authority assertion verification failed');
        }
        $now = time();
        if (($claims['aud'] ?? null) !== $this->c->origin && !(is_array($claims['aud'] ?? null) && in_array($this->c->origin, $claims['aud'], true))) {
            throw new AgentPassError(401, 'invalid_assertion', 'Assertion audience must be this Service origin');
        }
        if (!isset($claims['exp'], $claims['iat']) || (int) $claims['exp'] > $now + 300 + self::SKEW) { throw new AgentPassError(401, 'invalid_assertion', 'Assertion must be short-lived (iat/exp)'); }
        if (isset($claims['jti']) && !$this->c->store->claimOnce('assert|' . $claims['iss'] . '|' . $claims['jti'], (int) $claims['exp'] + self::SKEW)) {
            throw new AgentPassError(401, 'invalid_assertion', 'Assertion replayed');
        }
        return $claims;
    }

    // ───────────────────────── Redemption (§4.4–4.6) ─────────────────────────

    public function redeemBearerToken(array $b): array
    {
        [$v, $authority, $scope] = $this->redeemCommon($b, 'bearer_token');
        $token = 'apt_' . bin2hex(random_bytes(32));
        $exp = time() + $this->c->bearerTokenTtl;
        $this->c->store->saveToken(hash('sha256', $token), $v['authorization_id'], $exp);
        $this->log('agentpass.redeem.bearer_token', $v, $authority, 'success');
        return ['bearer_token' => $token, 'scope' => $scope, 'expires_in' => $this->c->bearerTokenTtl];
    }

    public function redeemBrowserSession(array $b): array
    {
        [$v, $authority, $scope] = $this->redeemCommon($b, 'browser_session', function (array $v) {
            $dest = $v['destination_url'] ?? null;
            if ($dest !== null && !$this->destinationAllowed((string) $dest, $v)) { throw new AgentPassError(403, 'destination_not_allowed', 'destination_url is not allowed by this Service'); }
        });
        $token = bin2hex(random_bytes(32));
        $exp = time() + $this->c->initializationTtl;
        $this->c->store->saveInit(hash('sha256', $token), $v['authorization_id'], $v['destination_url'] ?? null, $exp);
        $this->log('agentpass.redeem.browser_session', $v, $authority, 'success');
        $initPath = $this->c->initializationPath ?? rtrim($this->c->basePath, '/') . '/agentpass/session';
        return ['initialization_url' => $this->c->origin . $initPath . '/' . $token, 'expires_at' => gmdate('Y-m-d\TH:i:s\Z', $exp), 'one_time' => true];
    }

    /** @return array{0:array, 1:array, 2:list<string>} [validation, authority entry, effective scope] */
    private function redeemCommon(array $b, string $type, ?callable $extra = null): array
    {
        // 1. protocol validation
        $ap = $b['agentpass'] ?? null;
        if (!is_array($ap) || !is_string($ap['type'] ?? null) || !is_string($ap['value'] ?? null) || $ap['value'] === '' || strlen($ap['value']) > 512) {
            throw new AgentPassError(400, 'invalid_request', 'agentpass.type and agentpass.value are required');
        }
        if ($ap['type'] !== $type) { throw new AgentPassError(400, 'invalid_type', "agentpass.type must be $type"); }
        if (!is_string($b['authority'] ?? null)) { throw new AgentPassError(400, 'invalid_request', 'authority is required'); }
        $email = self::email($b['user']['email'] ?? null);
        $requested = $b['requested_scope'] ?? null;
        if ($requested !== null && (!is_array($requested) || array_filter($requested, fn ($s) => !is_string($s)))) { throw new AgentPassError(400, 'invalid_request', 'requested_scope must be a list of strings'); }
        $proof = $b['harness_proof']['jwt'] ?? null;
        if (isset($b['harness_proof']) && !is_string($proof)) { throw new AgentPassError(400, 'invalid_request', 'harness_proof.jwt must be a string'); }

        // 2–3. trust + precedence: the authority must be one resolution would offer for this user
        $authority = null;
        foreach ($this->resolve($email)['authorities'] as $a) { if ($a['authority'] === $b['authority']) { $authority = $a; } }
        if ($authority === null) { throw new AgentPassError(403, 'untrusted_authority', 'This Authority is not trusted for this user'); }

        // 4. validate with the Authority (single use is enforced there)
        $v = $this->callAuthority($authority, 'validate', ['agentpass' => ['value' => $ap['value']]]);
        if (!is_string($v['authorization_id'] ?? null) || !is_array($v['scope'] ?? null) || !is_string($v['agent']['id'] ?? null) || !is_string($v['user']['email'] ?? null)) {
            throw new AgentPassError(502, 'authority_error', 'Malformed validation response from the Authority');
        }
        if (strtolower($v['user']['email']) !== $email) { throw new AgentPassError(403, 'user_mismatch', 'The AgentPass was issued for a different user'); }
        if (($v['type'] ?? $type) !== $type) { throw new AgentPassError(422, 'invalid_agentpass', 'The AgentPass is for a different redemption type'); }

        // 5–6. scope
        $supported = array_column($this->scopeList(['user_email' => $email, 'agent_id' => $v['agent']['id'], 'authority' => $authority['authority']]), 'name');
        $approved = in_array('*', $v['scope'], true) ? $supported : array_values(array_intersect($v['scope'], $supported));
        $scope = $requested !== null ? array_values(array_intersect($approved, $requested)) : $approved;
        if (!$scope) { throw new AgentPassError(403, 'scope_mismatch', 'No usable scope after intersection'); }

        // 7. holder binding: when cnf is present, a valid proof is REQUIRED (spec §3.1.1 step 3)
        if (isset($v['cnf'])) {
            if (!is_string($proof)) { throw new AgentPassError(401, 'invalid_proof', 'harness_proof is required for this AgentPass'); }
            $this->verifyHarnessProof($proof, $v['cnf']['jwk'] ?? null);
        }
        if ($extra) { $extra($v); }

        $this->c->store->saveDelegation([
            'authorization_id' => $v['authorization_id'], 'authority' => $authority['authority'], 'user_email' => $email, 'agent_id' => $v['agent']['id'],
            'scope' => $scope, 'type' => $type, 'task_id' => $v['task']['id'] ?? null, 'task_description' => isset($v['task']['description']) ? mb_substr((string) $v['task']['description'], 0, 2000) : null,
            'destination_url' => $v['destination_url'] ?? null,
        ]);
        return [$v, $authority, $scope];
    }

    private function verifyHarnessProof(string $jwt, mixed $jwk): void
    {
        if (!is_array($jwk) || isset($jwk['d'])) { throw new AgentPassError(401, 'invalid_proof', 'Authority returned an unusable cnf key'); }
        try {
            $alg = $jwk['alg'] ?? match ($jwk['kty'] ?? '') { 'EC' => ($jwk['crv'] ?? '') === 'P-384' ? 'ES384' : 'ES256', 'OKP' => 'EdDSA', default => 'RS256' };
            JWT::$leeway = self::SKEW;
            $claims = (array) JWT::decode($jwt, JWK::parseKey($jwk, $alg));
        } catch (\Throwable) {
            throw new AgentPassError(401, 'invalid_proof', 'Harness proof signature is invalid');
        }
        $now = time();
        if (($claims['aud'] ?? null) !== $this->c->origin) { throw new AgentPassError(401, 'invalid_proof', 'Harness proof audience must be this Service origin'); }
        if (!is_string($claims['iss'] ?? null) || $claims['iss'] === '') { throw new AgentPassError(401, 'invalid_proof', 'Harness proof iss is required'); }
        if (!isset($claims['exp'], $claims['iat']) || (int) $claims['exp'] > $now + 300 + self::SKEW || (int) $claims['iat'] > $now + self::SKEW) { throw new AgentPassError(401, 'invalid_proof', 'Harness proof must be short-lived'); }
        if (!is_string($claims['jti'] ?? null) || !$this->c->store->claimOnce('proof|' . $claims['jti'], (int) $claims['exp'] + self::SKEW)) {
            throw new AgentPassError(409, 'proof_replayed', 'Harness proof jti missing or already used');
        }
    }

    private function destinationAllowed(string $url, array $v): bool
    {
        $p = parse_url($url);
        if (!$p || ($p['scheme'] ?? '') !== 'https' || isset($p['user']) || isset($p['pass'])) { return false; }
        $o = 'https://' . strtolower((string) ($p['host'] ?? '')) . (isset($p['port']) && (int) $p['port'] !== 443 ? ':' . $p['port'] : '');
        if ($o !== $this->c->origin) { return false; }
        return $this->c->destinationPolicy === null || (bool) ($this->c->destinationPolicy)($url, $v);
    }

    // ───────────────────────── Using a delegation ─────────────────────────

    /** Verify an API bearer token (from redeemBearerToken) and confirm the delegation is still active. */
    public function authenticateBearer(string $authorizationHeaderOrToken): Delegation
    {
        $t = preg_replace('/^Bearer\s+/i', '', trim($authorizationHeaderOrToken));
        if (!is_string($t) || !preg_match('/^apt_[0-9a-f]{64}$/', $t)) { throw new AgentPassError(401, 'invalid_token', 'Missing or malformed AgentPass bearer token'); }
        $row = $this->c->store->token(hash('sha256', $t));
        if (!$row || (int) $row['expires_at'] < time()) { throw new AgentPassError(401, 'invalid_token', 'Unknown, expired or revoked token'); }
        return $this->checkDelegation($row['authorization_id'], (int) $row['expires_at']);
    }

    /**
     * Consume a browser initialization token (single use). Returns the delegation; your app then starts an
     * agent-attributed session and redirects to safeRedirect($delegation).
     */
    public function consumeInitialization(string $token): Delegation
    {
        if (!preg_match('/^[0-9a-f]{64}$/', $token)) { throw new AgentPassError(400, 'invalid_token', 'Malformed initialization token'); }
        $h = hash('sha256', $token);
        $row = $this->c->store->consumeInit($h);
        if ($row === null) {
            $seen = $this->c->store->init($h);
            throw $seen ? new AgentPassError(410, 'initialization_consumed', 'This sign-in link was already used') : new AgentPassError(404, 'unknown_initialization', 'Unknown sign-in link');
        }
        if ((int) $row['expires_at'] < time()) { throw new AgentPassError(410, 'initialization_expired', 'This sign-in link expired'); }
        $d = $this->checkDelegation($row['authorization_id'], null, true);
        $this->log('agentpass.session.initialized', ['authorization_id' => $d->authorizationId, 'user' => ['email' => $d->userEmail], 'agent' => ['id' => $d->agentId], 'task' => ['id' => $d->taskId]], ['authority' => $d->authority], 'success');
        return $d;
    }

    /** Same-origin destination to redirect to after initialization (never an open redirect). */
    public function safeRedirect(Delegation $d, string $default = '/'): string
    {
        $u = $d->destinationUrl;
        if ($u !== null && $this->destinationAllowed($u, [])) {
            $p = parse_url($u);
            return ($p['path'] ?? '/') . (isset($p['query']) ? '?' . $p['query'] : '');
        }
        return $default;
    }

    /**
     * Continuous validation (§4.4, §5.5): authorization-check at the Authority, cached ≤ checkCacheSeconds.
     * Revoked → local tokens invalidated + 401. Authority unreachable → rejected (503), never fail-open.
     */
    public function checkDelegation(string $authorizationId, ?int $expiresAt = null, bool $force = false): Delegation
    {
        $row = $this->c->store->delegation($authorizationId);
        if (!$row || $row['revoked_at'] !== null) { throw new AgentPassError(401, 'delegation_revoked', 'This delegation was revoked'); }
        if ($force || time() - (int) $row['checked_at'] >= $this->c->checkCacheSeconds) {
            $authority = null;
            foreach (array_merge($this->c->trustedAuthorities, $this->c->serviceAuthority ? [$this->c->serviceAuthority] : []) as $a) {
                if ($a['authority'] === $row['authority']) { $authority = $a; }
            }
            if ($authority === null) {
                // Enterprise Authority: re-resolve for this user
                foreach ($this->resolve($row['user_email'])['authorities'] as $a) { if ($a['authority'] === $row['authority']) { $authority = $a; } }
            }
            if ($authority === null) { $this->c->store->revokeDelegation($authorizationId); throw new AgentPassError(401, 'delegation_revoked', 'The Authority is no longer trusted'); }
            try {
                $r = $this->callAuthority($authority, 'authorization_check', ['authorization_id' => $authorizationId]);
            } catch (AgentPassError $e) {
                if ($e->status === 404 || $e->errorCode === 'delegation_revoked') {
                    $this->c->store->revokeDelegation($authorizationId);
                    $this->log('agentpass.delegation.revoked', ['authorization_id' => $authorizationId, 'user' => ['email' => $row['user_email']], 'agent' => ['id' => $row['agent_id']]], $authority, 'revoked');
                    throw new AgentPassError(401, 'delegation_revoked', 'The user revoked this agent\'s access');
                }
                throw new AgentPassError(503, 'authority_unavailable', 'Could not confirm the delegation with the Authority; try again');
            }
            $now = is_array($r['scope'] ?? null) ? $r['scope'] : [];
            $current = json_decode((string) $row['scope'], true) ?: [];
            $scope = in_array('*', $now, true) ? $current : array_values(array_intersect($current, $now));
            $this->c->store->markChecked($authorizationId, $scope);
            $row['scope'] = json_encode($scope);
        }
        $row['expires_at'] = $expiresAt;
        return Delegation::fromRow($row);
    }

    // ───────────────────────── Authority calls ─────────────────────────

    private function authorityConfig(string $url): array
    {
        $cfg = $this->fetchJson($url, 300);
        if (!is_string($cfg['authority'] ?? null) || !is_string($cfg['jwks_uri'] ?? null) || !is_array($cfg['endpoints'] ?? null) || !str_starts_with((string) ($cfg['version'] ?? ''), '0.')) {
            throw new \RuntimeException('Invalid Authority configuration');
        }
        return $cfg;
    }

    private function fetchJson(string $url, int $ttl): array
    {
        $key = 'json|' . $url;
        $hit = $this->c->store->cacheGet($key);
        if (is_array($hit)) { return $hit; }
        $r = $this->c->http->request('GET', $url, ['Accept' => 'application/json']);
        $j = json_decode($r['body'], true);
        if ($r['status'] !== 200 || !is_array($j)) { throw new \RuntimeException('Fetch failed: ' . $url . ' (' . $r['status'] . ')'); }
        if (preg_match('/max-age=(\d+)/', $r['headers']['cache-control'] ?? '', $m)) { $ttl = max(30, min($ttl, (int) $m[1])); }
        $this->c->store->cachePut($key, $j, $ttl);
        return $j;
    }

    private function assertion(string $aud): string
    {
        $now = time();
        return JWT::encode(['iss' => $this->c->origin, 'aud' => $aud, 'iat' => $now, 'exp' => $now + 60, 'jti' => bin2hex(random_bytes(16))], $this->c->signingKeyPem, 'ES256', $this->c->publicJwk['kid']);
    }

    private function callAuthority(array $authority, string $endpoint, array $payload): array
    {
        try {
            $cfg = $this->authorityConfig($authority['authority_configuration_url']);
        } catch (\Throwable) {
            throw new AgentPassError(502, 'authority_unavailable', 'Could not load the Authority configuration');
        }
        if ($cfg['authority'] !== $authority['authority']) { throw new AgentPassError(502, 'authority_error', 'Authority configuration does not match the trusted identifier'); }
        $url = $cfg['endpoints'][$endpoint] ?? null;
        if (!is_string($url) || !str_starts_with($url, 'https://')) { throw new AgentPassError(502, 'authority_error', "Authority has no $endpoint endpoint"); }
        try {
            $r = $this->c->http->request('POST', $url, ['Content-Type' => 'application/json', 'Accept' => 'application/json', 'Authorization' => 'Bearer ' . $this->assertion($authority['authority'])], (string) json_encode($payload, JSON_UNESCAPED_SLASHES));
        } catch (\Throwable) {
            throw new AgentPassError(502, 'authority_unavailable', 'The Authority could not be reached');
        }
        $j = json_decode($r['body'], true);
        if ($r['status'] === 200 && is_array($j)) {
            return isset($j['response']) && is_array($j['response']) && count($j) === 1 ? $j['response'] : $j;
        }
        $msg = is_array($j) ? (string) ($j['error']['message'] ?? 'Authority rejected the request') : 'Authority rejected the request';
        $code = is_array($j) ? (string) ($j['error']['code'] ?? 'authority_rejected') : 'authority_rejected';
        if ($endpoint === 'authorization_check' && $r['status'] === 404) { throw new AgentPassError(404, 'delegation_revoked', $msg); }
        if ($r['status'] >= 500 || $r['status'] === 429) { throw new AgentPassError(502, 'authority_unavailable', $msg); }
        if ($r['status'] === 401 && $endpoint !== 'validate') { throw new AgentPassError(502, 'authority_rejected_service', $msg); }
        // validate: replay/consumed → 409, everything else → 422 invalid AgentPass
        throw new AgentPassError($r['status'] === 409 ? 409 : 422, $r['status'] === 409 ? 'agentpass_replayed' : 'invalid_agentpass', $msg . ' (' . $code . ')');
    }

    private function log(string $event, array $v, array $authority, string $outcome): void
    {
        if (!is_callable($this->c->logger)) { return; }
        ($this->c->logger)($event, [
            'outcome' => $outcome, 'authority' => $authority['authority'] ?? null, 'authorization_id' => $v['authorization_id'] ?? null,
            'user_email' => $v['user']['email'] ?? null, 'agent_id' => $v['agent']['id'] ?? null, 'task_id' => $v['task']['id'] ?? null,
        ]);
    }
}
