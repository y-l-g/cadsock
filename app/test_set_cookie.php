<?php
$result = setcookie(
    'TestCookie',
    'hello-world',
    [
        'expires' => time() + 3600,
        'path' => '/',
        'samesite' => 'Strict'
    ]
);

if ($result) {
    echo '<h1>Cookie envoyé au navigateur.</h1>';
} else {
    echo '<h1>Erreur : setcookie() a échoué. Vérifiez qu\'aucun contenu n\'a été envoyé avant cet appel (headers already sent).</h1>';
}

echo '<p><a href="/test_read_cookie.php">Cliquez ici pour vérifier le cookie</a></p>';