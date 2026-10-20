<?php
// php -S router (local testing): static files from public/, everything else through index.php
$p = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($p !== '/' && is_file(__DIR__ . '/public' . $p) && !str_ends_with($p, '.php')) { return false; }
require __DIR__ . '/public/index.php';
