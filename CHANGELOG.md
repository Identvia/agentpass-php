# Changelog

## 0.1.2 (2026-11-09)

- First release on Packagist (`identvia/agentpass-php`), which updates automatically from this repository's tags.
- `composer.json` metadata: homepage `https://identvia.com`, authors and support links (issues, source, docs, email). No code changes.

## 0.1.1 (2026-10-21)

- Requires `firebase/php-jwt` **^7.0**. Composer blocks all 6.x releases because of CVE-2025-45769 (GHSA-2x45-7fc3-mxwq).
- First standalone repository, split from the Identvia monorepo with its history. Added `.gitignore` and GitHub Actions CI (PHP 8.1–8.4).

