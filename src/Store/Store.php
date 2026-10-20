<?php
declare(strict_types=1);

namespace AgentPass\Service\Store;

interface Store
{
    public function saveDelegation(array $d): void;
    public function delegation(string $authorizationId): ?array;
    public function markChecked(string $authorizationId, array $scope): void;
    public function revokeDelegation(string $authorizationId): void;

    public function saveToken(string $hash, string $authorizationId, int $expiresAt): void;
    public function token(string $hash): ?array;

    public function saveInit(string $hash, string $authorizationId, ?string $destination, int $expiresAt): void;
    /** Atomically mark an init token used. Returns its row only if this call consumed it. */
    public function consumeInit(string $hash): ?array;
    public function init(string $hash): ?array;

    /** Replay cache. Returns false if $key was already seen. */
    public function claimOnce(string $key, int $expiresAt): bool;

    public function cacheGet(string $key): mixed;
    public function cachePut(string $key, mixed $value, int $ttl): void;
}
