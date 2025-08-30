<?php

echo 'Vérification des fonctions de l\'extension Realtime :<br>';

if (function_exists('Realtime\\start')) {
    echo '✅ La fonction Realtime\\start existe.<br>';
} else {
    echo '❌ La fonction Realtime\\start N\'EXISTE PAS.<br>';
}

if (function_exists('Realtime\\broadcast')) {
    echo '✅ La fonction Realtime\\broadcast existe.<br>';
} else {
    echo '❌ La fonction Realtime\\broadcast N\'EXISTE PAS.<br>';
}