<?php
require_once __DIR__ . '/vendor/autoload.php';
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

header('Content-Type: application/json');

$token = $_COOKIE['AUTH_TOKEN'] ?? null;

if (!$token) {
    http_response_code(401);
    echo json_encode(['error' => 'Missing authentication token']);
    exit;
}

$secretKey = 'your-super-secret-key-that-no-one-knows';

try {
    $decoded = JWT::decode($token, new Key($secretKey, 'HS256'));
    $userId = $decoded->sub;

    http_response_code(200);
    echo json_encode(['id' => $userId]);

} catch (Exception $e) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized: ' . $e->getMessage()]);
}