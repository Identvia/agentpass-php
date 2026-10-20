<?php
declare(strict_types=1);

namespace AgentPass\Service\Dns;

/** Uses the host's resolver (dns_get_record). */
final class SystemDnsResolver implements DnsResolver
{
    public function txt(string $name): ?array
    {
        if (!function_exists('dns_get_record')) { return null; }
        $recs = @dns_get_record($name, DNS_TXT);
        if ($recs === false) { return null; }
        $out = [];
        foreach ($recs as $r) {
            if (($r['type'] ?? '') !== 'TXT') { continue; }
            $out[] = isset($r['entries']) && is_array($r['entries']) ? implode('', $r['entries']) : (string) ($r['txt'] ?? '');
        }
        return $out;
    }
}
