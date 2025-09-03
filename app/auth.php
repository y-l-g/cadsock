<?php

header('Content-Type: application/json');

// This is a dummy authentication logic.
// In a real application, you would validate a session cookie or a JWT token
// against your database or session store.
if (isset($_COOKIE['AUTH_TOKEN']) && str_starts_with($_COOKIE['AUTH_TOKEN'], 'user-')) {
    http_response_code(200);
    echo json_encode(['id' => $_COOKIE['AUTH_TOKEN']]);
    exit;
}

http_response_code(401);
echo json_encode(['error' => 'Unauthorized']);