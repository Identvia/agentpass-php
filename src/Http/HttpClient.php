<?php
declare(strict_types=1);

namespace AgentPass\Service\Http;

interface HttpClient
{
    /**
     * @param array<string,string> $headers
     * @return array{status:int, headers:array<string,string>, body:string}
     * @throws \RuntimeException on transport failure
     */
    public function request(string $method, string $url, array $headers = [], ?string $body = null): array;
}
