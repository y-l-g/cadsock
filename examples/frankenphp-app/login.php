<?php
require_once __DIR__ . '/vendor/autoload.php';
use Firebase\JWT\JWT;

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
$userId = $input['userId'] ?? null;

if (empty($userId)) {
    http_response_code(400);
    echo json_encode(['error' => 'User ID is required']);
    exit;
}

$secretKey = getenv('JWT_SECRET_KEY');
if (empty($secretKey)) {
    error_log('JWT_SECRET_KEY environment variable not set');
    http_response_code(500);
    echo json_encode(['error' => 'Server configuration error']);
    exit;
}

$payload = [
    'iat' => time(),
    'exp' => time() + 3600,
    'sub' => $userId
];

$jwt = JWT::encode($payload, $secretKey, 'HS256');

setcookie('AUTH_TOKEN', $jwt, [
    'expires' => time() + 3600,
    'path' => '/',
    'httponly' => true,
    'samesite' => 'Strict'
]);

http_response_code(200);
echo json_encode(['status' => 'ok']);