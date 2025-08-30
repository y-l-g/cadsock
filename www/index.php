<?php

// Démarre le serveur WebSocket en arrière-plan (ne fait rien s'il est déjà démarré)
Realtime\start();

// Si le formulaire est soumis, diffuse le message
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['message'])) {
    Realtime\broadcast($_POST['message']);
    header('Location: /');
    exit;
}

?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Panneau de Contrôle</title>
</head>
<body>

    <h1>Envoyer un Message</h1>

    <form method="POST">
        <input type="text" name="message" size="50" required autofocus>
        <button type="submit">Diffuser le message</button>
    </form>

    <hr>

    <p>
        <a href="client.html" target="_blank">Ouvrir le client pour voir les messages</a>
    </p>

</body>
</html>