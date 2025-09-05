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

function broadcast(string $channel, string $message): bool
{
    $secret = getenv('BROADCAST_SECRET_KEY');
    if (empty($secret)) {
        error_log('BROADCAST_SECRET_KEY environment variable not set');
        return false;
    }
    
    $url = 'http://localhost:8080/internal/broadcast';
    $data = http_build_query([
        'channel' => $channel,
        'message' => $message,
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

    set_error_handler(function($severity, $message, $file, $line) {
        throw new ErrorException($message, 0, $severity, $file, $line);
    });

    try {
        $result = file_get_contents($url, false, $context);
    } catch (ErrorException $e) {
        error_log("Broadcast request failed: " . $e->getMessage());
        restore_error_handler();
        return false;
    }
    restore_error_handler();

    if ($result === false || !isset($http_response_header[0])) {
         error_log("Broadcast failed: No response or headers from server.");
        return false;
    }

    $statusCode = (int) substr($http_response_header[0], 9, 3);
    return $statusCode >= 200 && $statusCode < 300;
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