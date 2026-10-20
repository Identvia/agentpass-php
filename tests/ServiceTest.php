<?php
declare(strict_types=1);

namespace AgentPass\Service\Tests;

use AgentPass\Service\AgentPassError;
use AgentPass\Service\Dns\StaticDnsResolver;
use AgentPass\Service\Keys;
use AgentPass\Service\Service;
use AgentPass\Service\ServiceConfig;
use AgentPass\Service\Store\PdoStore;
use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;

final class ServiceTest extends TestCase
{
    private const ORIGIN = 'https://todo.example';
    private FakeAuthority $auth;
    private Service $svc;
    private PdoStore $store;
    private array $holder; // harness key

    protected function setUp(): void
    {
        $this->auth = new FakeAuthority();
        $this->svc = $this->make();
        $this->auth->serviceJwk = $this->svc->config()->publicJwk;
        $this->holder = Keys::generate();
    }

    private function make(array $dns = ['_agentpass.example.com' => []], array $over = []): Service
    {
        $key = Keys::generate();
        $this->store = PdoStore::sqlite(':memory:');
        return new Service(new ServiceConfig(...$over + [
            'origin' => self::ORIGIN, 'signingKeyPem' => $key['private_pem'],
            'trustedAuthorities' => [ServiceConfig::authority(FakeAuthority::ID)],
            'scopes' => [['name' => 'todos:read'], ['name' => 'todos:write']],
            'store' => $this->store, 'checkCacheSeconds' => 0, 'http' => $this->auth, 'dns' => new StaticDnsResolver($dns),
        ]));
    }

    private function pass(array $over = []): string
    {
        return $this->auth->issue($over + ['user' => ['email' => 'alex@example.com'], 'agent' => ['id' => 'bot-1'], 'scope' => ['todos:read'], 'type' => 'bearer_token',
            'cnf' => ['jwk' => array_diff_key($this->holder['public_jwk'], ['kid' => 1, 'alg' => 1, 'use' => 1])], 'task' => ['id' => 't1', 'description' => 'read todos', 'attested' => true]]);
    }

    private function proof(array $over = []): string
    {
        $now = time();
        return JWT::encode($over + ['iss' => 'bot-1', 'aud' => self::ORIGIN, 'iat' => $now, 'exp' => $now + 60, 'jti' => bin2hex(random_bytes(8))], $this->holder['private_pem'], 'ES256');
    }

    private function body(string $value, array $over = []): array
    {
        return $over + ['agentpass' => ['type' => 'bearer_token', 'value' => $value], 'authority' => FakeAuthority::ID, 'user' => ['email' => 'alex@example.com'], 'harness_proof' => ['jwt' => $this->proof()]];
    }

    private function expectError(int $status, string $code, callable $fn): void
    {
        try { $fn(); $this->fail("expected $status $code"); }
        catch (AgentPassError $e) { $this->assertSame([$status, $code], [$e->status, $e->errorCode], $e->getMessage()); }
    }

    public function testConfigurationAndDnsRecord(): void
    {
        $c = $this->svc->configuration();
        $this->assertSame('service', $c['kind']);
        $this->assertSame(self::ORIGIN, $c['service']['origin']);
        $this->assertSame(FakeAuthority::ID, $c['trust']['trusted_federated_authorities'][0]['authority']);
        $this->assertSame(self::ORIGIN . '/agentpass-service/agentpass/redeem-bearer-token', $c['endpoints']['redeem_bearer_token']);
        $jwk = $this->svc->jwks()['keys'][0];
        $this->assertSame(Keys::thumbprint($jwk), $jwk['kid']);
        $this->assertArrayNotHasKey('d', $jwk);
        $rec = $this->svc->config()->dnsRecord();
        $this->assertSame('_agentpass-service.todo.example', $rec['name']);
        $this->assertSame(self::ORIGIN . '/agentpass-service/config.json', $rec['value']);
    }

    public function testOriginMustBeHttps(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->make([], ['origin' => 'http://todo.example']);
    }

    public function testRedeemBearerHappyPathAndApi(): void
    {
        $r = $this->svc->redeemBearerToken($this->body($this->pass()));
        $this->assertMatchesRegularExpression('/^apt_[0-9a-f]{64}$/', $r['bearer_token']);
        $this->assertSame(['todos:read'], $r['scope']);
        $d = $this->svc->authenticateBearer('Bearer ' . $r['bearer_token']);
        $this->assertTrue($d->can('todos:read'));
        $this->assertFalse($d->can('todos:write'));
        $this->assertSame('bot-1', $d->agentId);
    }

    public function testReplayRejected(): void
    {
        $v = $this->pass();
        $this->svc->redeemBearerToken($this->body($v));
        $this->expectError(409, 'agentpass_replayed', fn () => $this->svc->redeemBearerToken($this->body($v)));
    }

    public function testHarnessProofRequiredWhenCnfPresent(): void
    {
        $b = $this->body($this->pass()); unset($b['harness_proof']);
        $this->expectError(401, 'invalid_proof', fn () => $this->svc->redeemBearerToken($b));
    }

    public function testHarnessProofChecks(): void
    {
        $this->expectError(401, 'invalid_proof', fn () => $this->svc->redeemBearerToken($this->body($this->pass(), ['harness_proof' => ['jwt' => $this->proof(['aud' => 'https://other.example'])]])));
        $this->expectError(401, 'invalid_proof', fn () => $this->svc->redeemBearerToken($this->body($this->pass(), ['harness_proof' => ['jwt' => $this->proof(['exp' => time() + 3600])]])));
        $other = Keys::generate();
        $forged = JWT::encode(['iss' => 'bot-1', 'aud' => self::ORIGIN, 'iat' => time(), 'exp' => time() + 60, 'jti' => 'x1'], $other['private_pem'], 'ES256');
        $this->expectError(401, 'invalid_proof', fn () => $this->svc->redeemBearerToken($this->body($this->pass(), ['harness_proof' => ['jwt' => $forged]])));
        $p = $this->proof(['jti' => 'same']);
        $this->svc->redeemBearerToken($this->body($this->pass(), ['harness_proof' => ['jwt' => $p]]));
        $this->expectError(409, 'proof_replayed', fn () => $this->svc->redeemBearerToken($this->body($this->pass(), ['harness_proof' => ['jwt' => $p]])));
    }

    public function testNoCnfNoProofNeeded(): void
    {
        $v = $this->auth->issue(['user' => ['email' => 'alex@example.com'], 'agent' => ['id' => 'b'], 'scope' => ['todos:read'], 'type' => 'bearer_token']);
        $b = $this->body($v); unset($b['harness_proof']);
        $this->assertArrayHasKey('bearer_token', $this->svc->redeemBearerToken($b));
    }

    public function testUserMismatchTypeMismatchAndUntrustedAuthority(): void
    {
        $this->expectError(403, 'user_mismatch', fn () => $this->svc->redeemBearerToken($this->body($this->pass(), ['user' => ['email' => 'eve@example.com']])));
        $this->expectError(422, 'invalid_agentpass', fn () => $this->svc->redeemBearerToken($this->body($this->pass(['type' => 'browser_session']))));
        $this->expectError(403, 'untrusted_authority', fn () => $this->svc->redeemBearerToken($this->body($this->pass(), ['authority' => 'https://evil.test'])));
        $this->expectError(400, 'invalid_type', fn () => $this->svc->redeemBearerToken($this->body($this->pass(), ['agentpass' => ['type' => 'browser_session', 'value' => 'x']])));
    }

    public function testScopeIntersection(): void
    {
        $v = $this->pass(['scope' => ['todos:read', 'todos:write', 'admin:everything']]);
        $r = $this->svc->redeemBearerToken($this->body($v, ['requested_scope' => ['todos:write']]));
        $this->assertSame(['todos:write'], $r['scope']);
        $this->expectError(403, 'scope_mismatch', fn () => $this->svc->redeemBearerToken($this->body($this->pass(), ['requested_scope' => ['todos:write']])));
    }

    public function testRevocationEnforcedAndFailClosed(): void
    {
        $r = $this->svc->redeemBearerToken($this->body($this->pass()));
        $d = $this->svc->authenticateBearer($r['bearer_token']);
        $this->auth->down = true;
        $this->expectError(503, 'authority_unavailable', fn () => $this->svc->authenticateBearer($r['bearer_token']));
        $this->auth->down = false;
        $this->auth->revoked[] = $d->authorizationId;
        $this->expectError(401, 'delegation_revoked', fn () => $this->svc->authenticateBearer($r['bearer_token']));
        $n = $this->auth->checks;
        $this->expectError(401, 'invalid_token', fn () => $this->svc->authenticateBearer($r['bearer_token']));
        $this->assertSame($n, $this->auth->checks, 'revoked locally: no further Authority calls');
    }

    public function testBrowserSessionSingleUseAndSafeRedirect(): void
    {
        $v = $this->pass(['type' => 'browser_session', 'destination_url' => self::ORIGIN . '/list?x=1']);
        $r = $this->svc->redeemBrowserSession($this->body($v, ['agentpass' => ['type' => 'browser_session', 'value' => $v]]));
        $this->assertTrue($r['one_time']);
        $tok = substr($r['initialization_url'], strrpos($r['initialization_url'], '/') + 1);
        $d = $this->svc->consumeInitialization($tok);
        $this->assertSame('/list?x=1', $this->svc->safeRedirect($d));
        $this->expectError(410, 'initialization_consumed', fn () => $this->svc->consumeInitialization($tok));
        $this->expectError(404, 'unknown_initialization', fn () => $this->svc->consumeInitialization(str_repeat('a', 64)));
        $bad = $this->pass(['type' => 'browser_session', 'destination_url' => 'https://evil.test/']);
        $this->expectError(403, 'destination_not_allowed', fn () => $this->svc->redeemBrowserSession($this->body($bad, ['agentpass' => ['type' => 'browser_session', 'value' => $bad]])));
    }

    public function testAvailableScopesRequiresAuthorityAssertion(): void
    {
        $b = ['user' => ['email' => 'alex@example.com'], 'agent' => ['id' => 'bot-1'], 'task' => ['id' => 't', 'description' => 'd']];
        $this->expectError(401, 'invalid_assertion', fn () => $this->svc->availableScopes($b, ''));
        $this->expectError(401, 'invalid_assertion', fn () => $this->svc->availableScopes($b, 'Bearer ' . $this->auth->assertion('https://other.example')));
        $this->expectError(403, 'untrusted_authority', fn () => $this->svc->availableScopes($b, 'Bearer ' . $this->auth->assertion(self::ORIGIN, ['iss' => 'https://evil.test'])));
        $a = $this->auth->assertion(self::ORIGIN);
        $this->assertSame(['todos:read', 'todos:write'], array_column($this->svc->availableScopes($b, 'Bearer ' . $a)['scopes'], 'name'));
        $this->expectError(401, 'invalid_assertion', fn () => $this->svc->availableScopes($b, 'Bearer ' . $a));
    }

    public function testAuthorityResolutionPrecedence(): void
    {
        $this->assertArrayHasKey('trusted_federated_authorities', $this->svc->resolveAuthorities(['user' => ['email' => 'a@example.com']]));
        $svc = $this->make(['_agentpass.locked.test' => ['none']]);
        $this->expectError(403, 'enterprise_precedence', fn () => $svc->resolveAuthorities(['user' => ['email' => 'a@locked.test']]));
        $svc = $this->make(['_agentpass.broken.test' => ['https://a.test/1', 'https://b.test/2']]);
        $this->expectError(502, 'enterprise_discovery_failed', fn () => $svc->resolveAuthorities(['user' => ['email' => 'a@broken.test']]));
    }

    public function testHandleRoutesAndErrorsAsJson(): void
    {
        $r = $this->svc->handle('GET', '/agentpass-service/config.json');
        $this->assertSame(200, $r->status);
        $r = $this->svc->handle('POST', '/agentpass-service/agentpass/redeem-bearer-token', '{bad', ['Content-Type' => 'application/json']);
        $this->assertSame(400, $r->status);
        $this->assertArrayHasKey('error', json_decode($r->body, true));
        $this->assertNull($this->svc->handle('GET', '/somewhere-else'));
    }
}
