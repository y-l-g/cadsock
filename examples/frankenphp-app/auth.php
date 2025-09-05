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

$secretKey = getenv('JWT_SECRET_KEY');
if (empty($secretKey)) {
    error_log('JWT_SECRET_KEY environment variable not set');
    http_response_code(500);
    echo json_encode(['error' => 'Server configuration error']);
    exit;
}

try {
    $decoded = JWT::decode($token, new Key($secretKey, 'HS256'));
    $userId = $decoded->sub;

    http_response_code(200);
    echo json_encode(['id' => $userId]);

} catch (Exception $e) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized: ' . $e->getMessage()]);
}