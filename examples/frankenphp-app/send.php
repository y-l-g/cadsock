<?php
session_start();

function generate_csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validate_csrf_token($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
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

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !validate_csrf_token($_POST['csrf_token'])) {
        http_response_code(403);
        $status = "Error: Invalid CSRF token.";
    } else {
        $channel = $_POST['channel'] ?? 'default';
        $message = $_POST['message'] ?? 'empty message';

        $fullMessage = "($channel) " . $message . " at " . date('H:i:s');
        
        if (broadcast($channel, json_encode($fullMessage))) {
            $status = "Message sent to channel '{$channel}'.";
        } else {
            http_response_code(500);
            $status = "Error: Failed to broadcast message.";
        }
    }
    unset($_SESSION['csrf_token']);
}

$csrf_token = generate_csrf_token();

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Send Message</title>
</head>
<body>
    <h1>Send a WebSocket Message</h1>
    <?php if (isset($status)): ?>
        <p><strong><?= htmlspecialchars($status) ?></strong></p>
    <?php endif; ?>
    <form action="send.php" method="post">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
        <div>
            <label for="channel">Channel:</label>
            <input type="text" id="channel" name="channel" value="news" required>
        </div>
        <br>
        <div>
            <label for="message">Message:</label>
            <input type="text" id="message" name="message" value="Hello World!" required>
        </div>
        <br>
        <button type="submit">Send</button>
    </form>
</body>
</html>