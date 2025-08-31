<?php

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $channel = $_POST['channel'] ?? 'default';
    $message = $_POST['message'] ?? 'empty message';

    if (function_exists('broadcast')) {
        broadcast($channel, "($channel) " . $message . " at " . date('H:i:s'));
        $status = "Message sent to channel '{$channel}'.";
    } else {
        $status = "Error: broadcast() function does not exist.";
    }
}

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