<?php
declare(strict_types=1);

require_once __DIR__ . '/env.php';

$dbHost = getenv('DB_HOST') ?: '127.0.0.1';
$dbName = getenv('DB_NAME') ?: 'medic_vault_db';
$dbUser = getenv('DB_USER') ?: 'app_readwrite';   // NOT root
$dbPass = getenv('DB_PASS') ?: '';

$dsn = "mysql:host={$dbHost};dbname={$dbName};charset=utf8mb4";

$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION, // fail loudly, catch centrally
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false, // use REAL server-side prepared statements
];

$pdo = new PDO($dsn, $dbUser, $dbPass, $options);
