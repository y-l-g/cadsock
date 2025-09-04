<?php
header('Content-Type: text/plain');

if (isset($_COOKIE['TestCookie']) && $_COOKIE['TestCookie'] === 'hello-world') {
    echo 'SUCCÈS : Le cookie a été lu correctement.';
} else {
    echo 'ÉCHEC : Le cookie n\'a pas été trouvé.';
    echo "\n\nContenu de \$_COOKIE :\n";
    print_r($_COOKIE);
}