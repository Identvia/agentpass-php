<?php
declare(strict_types=1);

namespace AgentPass\Service;

use AgentPass\Service\Dns\DnsResolver;
use AgentPass\Service\Dns\SystemDnsResolver;
use AgentPass\Service\Http\CurlHttpClient;
use AgentPass\Service\Http\HttpClient;
use AgentPass\Service\Store\Store;

/**
 * Everything a Service needs. Minimal example:
 *
 *   new ServiceConfig(
 *       origin: 'https://todo.example.com',
 *       name: 'Example Todo',
 *       signingKeyPem: file_get_contents('/home/me/agentpass-key.pem'),
 *       trustedAuthorities: [ServiceConfig::authority('https://identvia.com')],
 *       scopes: [['name' => 'todos:read', 'description' => 'Read your todos']],
 *       store: PdoStore::sqlite('/home/me/agentpass.sqlite'),
 *   );
 */
final class ServiceConfig
{
    public readonly string $origin;
    public readonly array $publicJwk;
    public readonly HttpClient $http;
    public readonly DnsResolver $dns;

    /**
     * @param list<array{authority:string, authority_configuration_url:string}> $trustedAuthorities trusted Federated Authorities
     * @param array{authority:string, authority_configuration_url:string}|null $serviceAuthority your own Service Authority, if any
     * @param list<array{name:string, description?:string}>|callable(array):list<array{name:string, description?:string}> $scopes
     * @param null|callable(string $destinationUrl, Delegation $d):bool $destinationPolicy extra allow-policy for browser destinations (same-origin is always enforced)
     * @param null|callable(string $event, array $context):void $logger audit hook (user, agent, task, authority, outcome)
     */
    public function __construct(
        string $origin,
        public readonly string $signingKeyPem,
        public readonly array $trustedAuthorities,
        public readonly mixed $scopes,
        public readonly Store $store,
        public readonly ?string $name = null,
        public readonly ?array $serviceAuthority = null,
        public readonly string $basePath = '/agentpass-service',
        public readonly ?string $initializationPath = null,
        public readonly int $bearerTokenTtl = 3600,
        public readonly int $initializationTtl = 60,
        public readonly int $checkCacheSeconds = 60,
        public readonly bool $preferServiceAuthority = true,
        public readonly mixed $destinationPolicy = null,
        public readonly mixed $logger = null,
        ?HttpClient $http = null,
        ?DnsResolver $dns = null,
    ) {
        $o = strtolower(rtrim($origin, '/'));
        if (!preg_match('#^https://[a-z0-9.\-]+(:\d{1,5})?$#', $o)) { throw new \InvalidArgumentException('origin must be a bare https origin like https://app.example.com'); }
        $this->origin = preg_replace('#:443$#', '', $o);
        if ($checkCacheSeconds > 60) { throw new \InvalidArgumentException('checkCacheSeconds must be at most 60'); }
        foreach (array_merge($trustedAuthorities, $serviceAuthority ? [$serviceAuthority] : []) as $a) {
            if (!is_string($a['authority'] ?? null) || !str_starts_with($a['authority'], 'https://') || !is_string($a['authority_configuration_url'] ?? null) || !str_starts_with($a['authority_configuration_url'], 'https://')) {
                throw new \InvalidArgumentException('Each authority needs https authority and authority_configuration_url');
            }
        }
        $this->publicJwk = Keys::publicJwk($signingKeyPem);
        $this->http = $http ?? new CurlHttpClient();
        $this->dns = $dns ?? new SystemDnsResolver();
    }

    /** Trust entry for a Federated Authority such as Identvia (configuration at {authority}/agentpass/ap). */
    public static function authority(string $authority, ?string $configurationUrl = null): array
    {
        $a = rtrim($authority, '/');
        return ['authority' => $a, 'authority_configuration_url' => $configurationUrl ?? $a . '/agentpass/ap'];
    }

    public function url(string $path): string
    {
        return $this->origin . rtrim($this->basePath, '/') . $path;
    }

    public function host(): string
    {
        return (string) parse_url($this->origin, PHP_URL_HOST);
    }

    /** The DNS TXT record to publish (spec §4.1). */
    public function dnsRecord(): array
    {
        return ['name' => '_agentpass-service.' . $this->host(), 'type' => 'TXT', 'value' => $this->url('/config.json')];
    }
}
