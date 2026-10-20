<?php
// Copy to config.php and edit. Keep config.php, the key and data/ outside public_html in production.
return [
    'origin' => 'https://todo.example.com',
    'name' => 'Example Todo',
    'authority' => 'https://identvia.com',          // the Federated Authority you trust
    'key_file' => __DIR__ . '/data/agentpass-key.pem', // php ../../bin/agentpass-keygen data/agentpass-key.pem
    'db_file' => __DIR__ . '/data/todo.sqlite',
    'check_cache_seconds' => 60,                     // how long a successful authorization-check is trusted (max 60)
    'ca_bundle' => null,                             // custom CA bundle (tests only)
    'dns' => [],                                     // static TXT answers (tests only), e.g. ['_agentpass.example.com' => []]
];
