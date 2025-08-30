<?php

Realtime\start();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['message'])) {
    $message = htmlspecialchars($_POST['message']);
    
    Realtime\broadcast("Nouveau message : " . $message);
    
    header('Location: /');
    exit;
}

?>

<!DOCTYPE html>
<html>
<head>
    <title>Serveur de Broadcast PHP</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: sans-serif; max-width: 600px; margin: 2em auto; padding: 0 1em; }
        input { width: 70%; padding: 8px; }
        button { padding: 8px; }
        p { margin-top: 2em; }
        a { color: #007bff; }
    </style>
</head>
<body>
    <h1>Envoyer un message à tous</h1>
    <form method="POST">
        <input type="text" name="message" placeholder="Votre message ici" required autofocus>
        <button type="submit">Envoyer</button>
    </form>
    <p>
        Ouvrez <a href="client.html" target="_blank">le client WebSocket</a> dans un ou plusieurs autres onglets pour voir les messages arriver.
    </p>
</body>
</html>
