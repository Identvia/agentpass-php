<?php
declare(strict_types=1);

namespace AgentPass\Service;

/** An active AgentPass delegation as seen by your Service: who, which agent, what scope, from which Authority. */
final class Delegation
{
    /** @param list<string> $scope */
    public function __construct(
        public readonly string $authorizationId,
        public readonly string $authority,
        public readonly string $userEmail,
        public readonly string $agentId,
        public readonly array $scope,
        public readonly string $type,
        public readonly ?string $taskId = null,
        public readonly ?string $taskDescription = null,
        public readonly ?string $destinationUrl = null,
        public readonly ?int $expiresAt = null,
    ) {}

    public function can(string $scope): bool
    {
        return in_array($scope, $this->scope, true);
    }

    public static function fromRow(array $r): self
    {
        return new self($r['authorization_id'], $r['authority'], $r['user_email'], $r['agent_id'], json_decode((string) $r['scope'], true) ?: [], $r['type'],
            $r['task_id'] ?? null, $r['task_description'] ?? null, $r['destination_url'] ?? null, isset($r['expires_at']) ? (int) $r['expires_at'] : null);
    }
}
