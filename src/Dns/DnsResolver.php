<?php
declare(strict_types=1);

namespace AgentPass\Service\Dns;

interface DnsResolver
{
    /** @return list<string>|null TXT values; [] when there is no record; null when the lookup failed */
    public function txt(string $name): ?array;
}
