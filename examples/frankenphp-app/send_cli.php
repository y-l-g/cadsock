<?php

// A command-line script to demonstrate server-to-server broadcasting.
// Usage: php examples/frankenphp-app/send_cli.php "my channel" "My message from the backend"

if (php_sapi_name() !== 'cli') {
    die("This script can only be run from the command line.");
}

// Load environment variables if a .env file exists (useful for local dev)
if (file_exists(__DIR__ . '/.env')) {
    $lines = file(__DIR__ . '/.env', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0) continue;
        list($name, $value) = explode('=', $line, 2);
        $_ENV[$name] = $value;
        $_SERVER[$name] = $value;
        putenv("$name=$value");
    }
}

function broadcast(string $channel, string $message): bool
{
    $secret = getenv('BROADCAST_SECRET_KEY');
    if (empty($secret)) {
        error_log('BROADCAST_SECRET_KEY environment variable not set');
        return false;
    }
    
    $url = 'http://localhost:8080/internal/broadcast';
    $payload = json_encode("CLI: " . $message);
    $data = http_build_query([
        'channel' => $channel,
        'message' => $payload,
    ]);

    $headers = [
        "Content-type: application/x-www-form-urlencoded",
        "X-Broadcast-Secret: " . $secret,
    ];

    $options = [
        'http' => [
            'header'  => implode("\r\n", $headers),
            'method'  => 'POST',
            'content' => $data,
            'timeout' => 5,
            'ignore_errors' => true,
        ],
    ];

    $context = stream_context_create($options);
    $result = file_get_contents($url, false, $context);

    if ($result === false || !isset($http_response_header[0])) {
         error_log("Broadcast failed: Could not connect or no response from server.");
        return false;
    }

    $statusCode = (int) substr($http_response_header[0], 9, 3);
    if ($statusCode >= 200 && $statusCode < 300) {
        return true;
    }
    
    error_log("Broadcast failed with status code: {$statusCode}. Response: " . $result);
    return false;
}

$channel = $argv[1] ?? 'default';
$message = $argv[2] ?? 'A message from the CLI script at ' . date('H:i:s');

echo "Attempting to broadcast to channel '{$channel}'...\n";

if (broadcast($channel, $message)) {
    echo "Message sent successfully.\n";
} else {
    echo "Failed to send message. Check server logs for details.\n";
    exit(1);
}