<?php
declare(strict_types=1);

namespace AgentPass\Service;

/** ES256 (P-256) signing keys via OpenSSL, plus their public JWK and RFC 7638 thumbprint. */
final class Keys
{
    /** @return array{private_pem:string, public_jwk:array, kid:string} */
    public static function generate(): array
    {
        $k = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        if ($k === false || !openssl_pkey_export($k, $pem)) { throw new \RuntimeException('OpenSSL could not create a P-256 key'); }
        $jwk = self::publicJwk($pem);
        return ['private_pem' => $pem, 'public_jwk' => $jwk, 'kid' => $jwk['kid']];
    }

    public static function publicJwk(string $privatePem): array
    {
        $k = openssl_pkey_get_private($privatePem);
        if ($k === false) { throw new \InvalidArgumentException('Not a valid private key PEM'); }
        $d = openssl_pkey_get_details($k);
        if (($d['type'] ?? null) !== OPENSSL_KEYTYPE_EC || ($d['ec']['curve_name'] ?? '') !== 'prime256v1') { throw new \InvalidArgumentException('The signing key must be EC P-256 (ES256)'); }
        $jwk = ['kty' => 'EC', 'crv' => 'P-256', 'x' => self::b64u(str_pad($d['ec']['x'], 32, "\0", STR_PAD_LEFT)), 'y' => self::b64u(str_pad($d['ec']['y'], 32, "\0", STR_PAD_LEFT))];
        return $jwk + ['kid' => self::thumbprint($jwk), 'alg' => 'ES256', 'use' => 'sig'];
    }

    public static function thumbprint(array $jwk): string
    {
        $members = match ($jwk['kty'] ?? '') {
            'EC' => ['crv' => $jwk['crv'], 'kty' => 'EC', 'x' => $jwk['x'], 'y' => $jwk['y']],
            'RSA' => ['e' => $jwk['e'], 'kty' => 'RSA', 'n' => $jwk['n']],
            'OKP' => ['crv' => $jwk['crv'], 'kty' => 'OKP', 'x' => $jwk['x']],
            default => throw new \InvalidArgumentException('Unsupported kty'),
        };
        return self::b64u(hash('sha256', (string) json_encode($members, JSON_UNESCAPED_SLASHES), true));
    }

    public static function b64u(string $b): string
    {
        return rtrim(strtr(base64_encode($b), '+/', '-_'), '=');
    }
}
