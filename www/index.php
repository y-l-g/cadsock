<?php

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['message'])) {
    $message = htmlspecialchars($_POST['message']);
    Realtime\broadcast("Nouveau message : " . $message);
    header('Location: /');
    exit;
}
?>
<!DOCTYPE html><html><head><title>Serveur PHP</title></head><body><h1>Envoyer un message</h1><form method="POST"><input type="text" name="message" required autofocus><button type="submit">Envoyer</button></form><p><a href="client.html" target="_blank">Ouvrir le client WebSocket</a></p></body></html>