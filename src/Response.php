<?php
declare(strict_types=1);

namespace AgentPass\Service;

/** Minimal HTTP response value (framework-neutral). */
final class Response
{
    /** @param array<string,string> $headers */
    public function __construct(public readonly int $status, public readonly array $headers, public readonly string $body) {}

    public static function json(mixed $data, int $status = 200, array $headers = []): self
    {
        return new self($status, $headers + ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store'], (string) json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    }

    public static function error(AgentPassError $e): self
    {
        return self::json($e->toArray(), $e->status);
    }

    public function send(): void
    {
        http_response_code($this->status);
        foreach ($this->headers as $k => $v) { header($k . ': ' . $v); }
        echo $this->body;
    }
}
