<?php

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit;
}

setcookie('AUTH_TOKEN', '', [
    'expires' => time() - 3600,
    'path' => '/',
    'httponly' => true,
    'samesite' => 'Strict'
]);

http_response_code(200);
echo json_encode(['status' => 'logged_out']);