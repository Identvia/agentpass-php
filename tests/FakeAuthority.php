<?php
declare(strict_types=1);

namespace AgentPass\Service\Tests;

use AgentPass\Service\Http\HttpClient;
use AgentPass\Service\Keys;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

/** In-process AgentPass Authority behind the SDK's HttpClient seam: config, JWKS, validate, authorization-check. */
final class FakeAuthority implements HttpClient
{
    public const ID = 'https://authority.test';
    public array $key;
    /** pass value => validation response */
    public array $passes = [];
    public array $consumed = [];
    public array $revoked = [];
    public int $checks = 0;
    public bool $down = false;
    public ?array $serviceJwk = null;
    public array $log = [];

    public function __construct() { $this->key = Keys::generate(); }

    public function issue(array $validation): string
    {
        $v = 'ap_' . bin2hex(random_bytes(16));
        $this->passes[$v] = $validation + ['authorization_id' => 'authz_' . bin2hex(random_bytes(8))];
        return $v;
    }

    public function assertion(string $aud, array $over = []): string
    {
        $now = time();
        return JWT::encode($over + ['iss' => self::ID, 'aud' => $aud, 'iat' => $now, 'exp' => $now + 60, 'jti' => bin2hex(random_bytes(8))], $this->key['private_pem'], 'ES256', $this->key['kid']);
    }

    public function request(string $method, string $url, array $headers = [], ?string $body = null): array
    {
        $this->log[] = "$method $url";
        if ($this->down) { throw new \RuntimeException('connection refused'); }
        $json = fn ($d, int $s = 200) => ['status' => $s, 'headers' => ['content-type' => 'application/json'], 'body' => json_encode($d)];
        switch ($url) {
            case self::ID . '/agentpass/ap':
                return $json(['version' => '0.1', 'authority' => self::ID, 'trust_mode' => 'federated', 'jwks_uri' => self::ID . '/jwks.json',
                    'endpoints' => ['issuance' => self::ID . '/r', 'issuance_status' => self::ID . '/r/{id}', 'validate' => self::ID . '/validate', 'authorization_check' => self::ID . '/check']]);
            case self::ID . '/jwks.json':
                return $json(['keys' => [$this->key['public_jwk']]]);
            case self::ID . '/validate':
            case self::ID . '/check':
                $auth = $headers['Authorization'] ?? $headers['authorization'] ?? '';
                try {
                    $c = (array) JWT::decode(substr($auth, 7), JWK::parseKey($this->serviceJwk + ['alg' => 'ES256'], 'ES256'));
                    if ($c['aud'] !== self::ID) { throw new \RuntimeException('aud'); }
                } catch (\Throwable) {
                    return $json(['error' => ['code' => 'invalid_assertion', 'message' => 'bad']], 401);
                }
                $b = json_decode((string) $body, true);
                if ($url === self::ID . '/check') {
                    $this->checks++;
                    foreach ($this->passes as $p) {
                        if ($p['authorization_id'] === $b['authorization_id'] && !in_array($b['authorization_id'], $this->revoked, true)) { return $json(['scope' => $p['scope']]); }
                    }
                    return $json(['error' => ['code' => 'not_found', 'message' => 'gone']], 404);
                }
                $v = $b['agentpass']['value'] ?? '';
                if (!isset($this->passes[$v])) { return $json(['error' => ['code' => 'unknown_agentpass', 'message' => 'unknown']], 404); }
                if (isset($this->consumed[$v])) { return $json(['error' => ['code' => 'agentpass_consumed', 'message' => 'used']], 409); }
                $this->consumed[$v] = true;
                return $json($this->passes[$v]);
        }
        return $json(['error' => ['code' => 'not_found', 'message' => $url]], 404);
    }
}
