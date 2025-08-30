<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['message'])) {
    Realtime\broadcast($_POST['message']);
    header('Location: /');
    exit;
}
?>
<!DOCTYPE html><html lang="fr"><head><title>Panneau</title></head><body><h1>Envoyer un Message</h1><form method="POST"><input type="text" name="message" required autofocus><button type="submit">Diffuser</button></form><hr><p><a href="client.html" target="_blank">Ouvrir le client</a></p></body></html>