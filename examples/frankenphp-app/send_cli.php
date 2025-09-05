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

/**
 * Broadcasts a message to the cadsock server using cURL.
 *
 * @param string $channel The channel to publish to.
 * @param string $message The JSON-encoded message payload.
 * @return bool True on success (2xx status code), false on failure.
 */
function broadcast(string $channel, string $message): bool
{
    $secret = getenv('BROADCAST_SECRET_KEY');
    if (empty($secret)) {
        error_log('BROADCAST_SECRET_KEY environment variable not set');
        return false;
    }
    
    $url = 'http://localhost:8080/internal/broadcast';
    $postData = http_build_query([
        'channel' => $channel,
        'message' => $message,
    ]);

    $headers = [
        "X-Broadcast-Secret: " . $secret,
    ];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_VERBOSE, false); // Set to true for debugging

    $response = curl_exec($ch);
    
    if (curl_errno($ch)) {
        error_log('cURL error broadcasting message: ' . curl_error($ch));
        curl_close($ch);
        return false;
    }

    $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($statusCode < 200 || $statusCode >= 300) {
        error_log("Broadcast failed with status code: {$statusCode}. Response: " . $response);
        return false;
    }

    return true;
}


$channel = $argv[1] ?? 'default';
$messageBody = $argv[2] ?? 'A message from the CLI script at ' . date('H:i:s');
$payload = json_encode("CLI: " . $messageBody);

echo "Attempting to broadcast to channel '{$channel}'...\n";

if (broadcast($channel, $payload)) {
    echo "Message sent successfully.\n";
} else {
    echo "Failed to send message. Check server logs for details.\n";
    exit(1);
}