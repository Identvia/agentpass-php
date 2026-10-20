<?php
declare(strict_types=1);

namespace AgentPass\Service;

/** A protocol error with an HTTP status and machine-readable code; rendered as {"error":{"code","message"}}. */
class AgentPassError extends \RuntimeException
{
    public function __construct(public readonly int $status, public readonly string $errorCode, string $message)
    {
        parent::__construct($message);
    }

    public function toArray(): array
    {
        return ['error' => ['code' => $this->errorCode, 'message' => $this->getMessage()]];
    }
}
