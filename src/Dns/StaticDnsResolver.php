<?php
declare(strict_types=1);

namespace AgentPass\Service\Dns;

/** Fixed answers (tests, or to pin known domains). Names not in the map fall through to $fallback (or "no record"). */
final class StaticDnsResolver implements DnsResolver
{
    /** @param array<string, list<string>|null> $records */
    public function __construct(private array $records, private ?DnsResolver $fallback = null) {}

    public function txt(string $name): ?array
    {
        $name = strtolower(rtrim($name, '.'));
        if (array_key_exists($name, $this->records)) { return $this->records[$name]; }
        return $this->fallback?->txt($name) ?? ($this->fallback ? null : []);
    }
}
