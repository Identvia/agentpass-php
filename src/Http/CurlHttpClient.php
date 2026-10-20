<?php
declare(strict_types=1);

namespace AgentPass\Service\Http;

/** https-only curl client: no redirects, short timeouts, response size cap, TLS verification always on. */
final class CurlHttpClient implements HttpClient
{
    public function __construct(
        private ?string $caBundle = null,
        private int $timeout = 5,
        private int $maxBytes = 262144,
    ) {}

    public function request(string $method, string $url, array $headers = [], ?string $body = null): array
    {
        if (!str_starts_with($url, 'https://')) { throw new \RuntimeException('Only https:// URLs are allowed'); }
        $buf = ''; $tooBig = false; $resp = [];
        $max = $this->maxBytes;
        $lines = ['User-Agent: identvia-agentpass-php/1'];
        foreach ($headers as $k => $v) { $lines[] = $k . ': ' . str_replace(["\r", "\n"], '', $v); }
        $ch = curl_init($url);
        $opts = [
            CURLOPT_CUSTOMREQUEST => strtoupper($method),
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_HTTPHEADER => $lines,
            CURLOPT_HEADERFUNCTION => function ($ch, string $line) use (&$resp): int {
                $p = strpos($line, ':');
                if ($p !== false) { $resp[strtolower(trim(substr($line, 0, $p)))] = trim(substr($line, $p + 1)); }
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => function ($ch, string $chunk) use (&$buf, &$tooBig, $max): int {
                if (strlen($buf) + strlen($chunk) > $max) { $tooBig = true; return 0; }
                $buf .= $chunk;
                return strlen($chunk);
            },
        ];
        if ($this->caBundle) { $opts[CURLOPT_CAINFO] = $this->caBundle; }
        if ($body !== null) { $opts[CURLOPT_POSTFIELDS] = $body; }
        curl_setopt_array($ch, $opts);
        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($tooBig) { throw new \RuntimeException('Response too large'); }
        if ($ok === false) { throw new \RuntimeException('HTTP request failed: ' . $err); }
        return ['status' => $status, 'headers' => $resp, 'body' => $buf];
    }
}
