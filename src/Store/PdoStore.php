<?php
declare(strict_types=1);

namespace AgentPass\Service\Store;

/**
 * SQLite or MySQL/MariaDB storage. Call install() once (idempotent). Only hashes of tokens are stored.
 */
final class PdoStore implements Store
{
    public function __construct(private \PDO $pdo, private string $prefix = 'agentpass_')
    {
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
    }

    public static function sqlite(string $file): self
    {
        $s = new self(new \PDO('sqlite:' . $file));
        $s->pdo->exec('PRAGMA journal_mode=WAL');
        $s->pdo->exec('PRAGMA busy_timeout=5000');
        $s->install();
        return $s;
    }

    private function t(string $n): string { return $this->prefix . $n; }

    public function install(): void
    {
        $mysql = $this->pdo->getAttribute(\PDO::ATTR_DRIVER_NAME) === 'mysql';
        $txt = $mysql ? 'TEXT' : 'TEXT';
        $k = $mysql ? 'VARCHAR(191)' : 'TEXT';
        $engine = $mysql ? ' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4' : '';
        foreach ([
            "CREATE TABLE IF NOT EXISTS {$this->t('delegations')} (authorization_id $k PRIMARY KEY, authority VARCHAR(255) NOT NULL, user_email VARCHAR(254) NOT NULL, agent_id VARCHAR(255) NOT NULL,
                scope $txt NOT NULL, type VARCHAR(20) NOT NULL, task_id VARCHAR(255) NULL, task_description $txt NULL, destination_url VARCHAR(2000) NULL,
                created_at INTEGER NOT NULL, checked_at INTEGER NOT NULL, revoked_at INTEGER NULL)$engine",
            "CREATE TABLE IF NOT EXISTS {$this->t('tokens')} (token_hash CHAR(64) PRIMARY KEY, authorization_id VARCHAR(191) NOT NULL, expires_at INTEGER NOT NULL)$engine",
            "CREATE TABLE IF NOT EXISTS {$this->t('inits')} (token_hash CHAR(64) PRIMARY KEY, authorization_id VARCHAR(191) NOT NULL, destination_url VARCHAR(2000) NULL, expires_at INTEGER NOT NULL, used_at INTEGER NULL)$engine",
            "CREATE TABLE IF NOT EXISTS {$this->t('once')} (k CHAR(64) PRIMARY KEY, expires_at INTEGER NOT NULL)$engine",
            "CREATE TABLE IF NOT EXISTS {$this->t('cache')} (k $k PRIMARY KEY, v $txt NOT NULL, expires_at INTEGER NOT NULL)$engine",
        ] as $sql) { $this->pdo->exec($sql); }
    }

    private function one(string $sql, array $p): ?array
    {
        $st = $this->pdo->prepare($sql); $st->execute($p);
        $r = $st->fetch(\PDO::FETCH_ASSOC);
        return $r === false ? null : $r;
    }

    private function exec(string $sql, array $p): int
    {
        $st = $this->pdo->prepare($sql); $st->execute($p);
        return $st->rowCount();
    }

    public function saveDelegation(array $d): void
    {
        $this->exec("INSERT INTO {$this->t('delegations')} (authorization_id, authority, user_email, agent_id, scope, type, task_id, task_description, destination_url, created_at, checked_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)", [
            $d['authorization_id'], $d['authority'], $d['user_email'], $d['agent_id'], json_encode(array_values($d['scope'])), $d['type'], $d['task_id'] ?? null,
            $d['task_description'] ?? null, $d['destination_url'] ?? null, time(), time(),
        ]);
    }

    public function delegation(string $authorizationId): ?array
    {
        return $this->one("SELECT * FROM {$this->t('delegations')} WHERE authorization_id = ?", [$authorizationId]);
    }

    public function markChecked(string $authorizationId, array $scope): void
    {
        $this->exec("UPDATE {$this->t('delegations')} SET checked_at = ?, scope = ? WHERE authorization_id = ?", [time(), json_encode(array_values($scope)), $authorizationId]);
    }

    public function revokeDelegation(string $authorizationId): void
    {
        $this->exec("UPDATE {$this->t('delegations')} SET revoked_at = ? WHERE authorization_id = ? AND revoked_at IS NULL", [time(), $authorizationId]);
        $this->exec("DELETE FROM {$this->t('tokens')} WHERE authorization_id = ?", [$authorizationId]);
    }

    public function saveToken(string $hash, string $authorizationId, int $expiresAt): void
    {
        $this->exec("INSERT INTO {$this->t('tokens')} (token_hash, authorization_id, expires_at) VALUES (?,?,?)", [$hash, $authorizationId, $expiresAt]);
    }

    public function token(string $hash): ?array
    {
        return $this->one("SELECT * FROM {$this->t('tokens')} WHERE token_hash = ?", [$hash]);
    }

    public function saveInit(string $hash, string $authorizationId, ?string $destination, int $expiresAt): void
    {
        $this->exec("INSERT INTO {$this->t('inits')} (token_hash, authorization_id, destination_url, expires_at) VALUES (?,?,?,?)", [$hash, $authorizationId, $destination, $expiresAt]);
    }

    public function consumeInit(string $hash): ?array
    {
        if ($this->exec("UPDATE {$this->t('inits')} SET used_at = ? WHERE token_hash = ? AND used_at IS NULL", [time(), $hash]) !== 1) { return null; }
        return $this->init($hash);
    }

    public function init(string $hash): ?array
    {
        return $this->one("SELECT * FROM {$this->t('inits')} WHERE token_hash = ?", [$hash]);
    }

    public function claimOnce(string $key, int $expiresAt): bool
    {
        $this->exec("DELETE FROM {$this->t('once')} WHERE expires_at < ?", [time()]);
        try {
            $this->exec("INSERT INTO {$this->t('once')} (k, expires_at) VALUES (?,?)", [hash('sha256', $key), $expiresAt]);
            return true;
        } catch (\PDOException) {
            return false;
        }
    }

    public function cacheGet(string $key): mixed
    {
        $r = $this->one("SELECT v, expires_at FROM {$this->t('cache')} WHERE k = ?", [substr($key, 0, 191)]);
        return $r && (int) $r['expires_at'] > time() ? json_decode($r['v'], true) : null;
    }

    public function cachePut(string $key, mixed $value, int $ttl): void
    {
        $k = substr($key, 0, 191);
        $this->exec("DELETE FROM {$this->t('cache')} WHERE k = ?", [$k]);
        $this->exec("INSERT INTO {$this->t('cache')} (k, v, expires_at) VALUES (?,?,?)", [$k, json_encode($value), time() + $ttl]);
    }
}
