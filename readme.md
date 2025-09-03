# FrankenPHP Realtime Project

Un service de diffusion WebSocket basé sur des canaux, construit avec un module Caddy en Go et une extension PHP en Go. Il dispose de backends interchangeables pour des déploiements sur un seul nœud ou en scaling horizontal.

## Architecture

Le système utilise une architecture "Hub and Spoke" pour gérer les connexions et les messages. Il est conçu pour être à la fois simple pour les petits projets et scalable pour les environnements de production.

-   **Hub (`handler/hub.go`):** Le composant central. Il s'exécute dans une seule goroutine et gère tout l'état (canaux, abonnements des clients) pour les clients connectés à une instance de serveur. Son modèle basé sur les canaux garantit la sécurité des accès concurrents sans nécessiter de verrous complexes.
-   **Client (`handler/hub.go`):** Un wrapper pour chaque `*websocket.Conn`. Chaque client exécute deux goroutines dédiées (`readPump`, `writePump`) pour gérer les I/O, respectant le modèle de concurrence un-lecteur/un-écrivain de `gorilla/websocket`.
-   **Authentication:** La connexion WebSocket est sécurisée via une étape d'authentification obligatoire. Le handler Go effectue une requête HTTP interne vers un endpoint PHP (configurable) pour valider la session de l'utilisateur (par exemple, via un cookie). Si le script PHP renvoie une réponse positive, la connexion est mise à niveau et associée à un User ID.
-   **Broker (`handler/hub.go`):** Pour supporter les déploiements mono-nœud et multi-nœuds, le Hub utilise un "Broker" interchangeable pour la diffusion des messages.
    -   **Memory Broker:** Le mode par défaut. Les messages sont diffusés en mémoire à tous les clients connectés à la *même instance de serveur*. Parfait pour les applications simples sur un seul serveur.
    -   **Redis Broker:** Lorsqu'il est activé, les messages sont publiés sur un canal Redis Pub/Sub (via `PSUBSCRIBE` pour supporter les patterns). Toutes les instances de serveur s'abonnent à ce canal et livrent les messages à leurs clients locaux respectifs, permettant un scaling horizontal transparent.
-   **Caddy Module (`handler/handler.go`):** Le point d'entrée HTTP. Il gère le flux d'authentification et met à niveau les requêtes HTTP autorisées en connexions WebSocket.
-   **PHP Extension (`broadcast/broadcast.go`):** Un pont FFI qui expose une fonction native `broadcast()` à PHP. Cette fonction envoie les messages au Broker configuré pour distribution.

## Key Features

-   **Sécurisé par Défaut:** Les connexions WebSocket sont rejetées sauf si elles sont authentifiées via un endpoint backend PHP, dont l'URL est entièrement configurable.
-   **Architecture Scalable:** Commencez avec une configuration simple en mémoire et passez à un backend Redis pour le scaling horizontal avec une seule ligne de configuration. Aucun changement de code n'est requis.
-   **Découplé:** Le handler Go délègue toute la logique d'authentification à votre application PHP existante, vous permettant de réutiliser votre gestion de session et votre logique utilisateur.
-   **Robuste et Résilient:** Le Hub est conçu pour gérer les interruptions de service. En cas d'indisponibilité du broker (ex: redémarrage de Redis), il tentera de se reconnecter automatiquement sans faire planter le serveur principal.

## Roadmap: Next Steps for Production Readiness

L'architecture de base étant désormais sécurisée, scalable et robuste, les prochaines priorités visent à enrichir l'API et à garantir la stabilité à long terme.

1.  **Mettre en place une suite de tests automatisés:** Avant d'ajouter de nouvelles fonctionnalités, il est crucial de construire une suite de tests d'intégration (par exemple avec Docker et Pest) pour valider le comportement actuel et prévenir les régressions futures.
2.  **Enrichir l'API PHP:** L'API PHP doit être étendue pour permettre un contrôle plus fin :
    *   `broadcastToUser(int|string $userId, string $message)`: Pour envoyer un message privé à un utilisateur spécifique sur toutes les instances de serveur.
    *   `getChannelUsers(string $channel): array`: Pour obtenir la liste des utilisateurs abonnés à un canal (nécessite un backend comme Redis pour stocker cet état partagé).
    *   `disconnectUser(int|string $userId)`: Pour fermer de force la connexion d'un utilisateur.
3.  **Ajouter des "Presence Hooks":** Fournir un mécanisme pour notifier l'application PHP lorsqu'un utilisateur rejoint ou quitte un canal. Cela permet de construire facilement des fonctionnalités de type "qui est en ligne ?".

## Project Structure

```
realtime/
├── app/
│   ├── Caddyfile
│   ├── auth.php
│   ├── index.php
│   └── send.php
├── broadcast/
│   ├── broadcast.go
│   └── go.mod
└── handler/
    ├── handler.go
    ├── hub.go
    └── go.mod
```

## API Reference

### PHP API

-   `broadcast(string $channel, string $message): void`
    -   Envoie `$message` à tous les clients actuellement abonnés à `$channel` via le broker configuré.

### Client-Side Protocol (JSON)

-   **S'abonner à un canal:**
    ```json
    {
        "action": "subscribe",
        "channel": "channel_name"
    }
    ```
-   **Se désabonner d'un canal:**
    ```json
    {
        "action": "unsubscribe",
        "channel": "channel_name"
    }
    ```

## Build Procedure

**(Prérequis: Go (>= 1.25), en-têtes de développement PHP (`php-config`), code source de PHP.)**

La procédure de build reste la même. Après tout changement dans les modules Go `handler` ou `broadcast`, vous devez recompiler le binaire FrankenPHP.

## Configuration

L'application est configurée via le `app/Caddyfile`. Le handler `go_handler` accepte plusieurs options dans son bloc de configuration.

| Directive | Description | Défaut |
|---|---|---|
| `driver` | Le backend de diffusion à utiliser (`memory` ou `redis`). | `memory` |
| `redis_address` | L'adresse du serveur Redis (utilisée si `driver` est `redis`). | `localhost:6379` |
| `auth_endpoint` | L'URL interne complète pour la validation de l'authentification. | `http://localhost:8080/auth.php` |

### Exemples de Configuration

-   **Défaut (En-Mémoire):** Pour les déploiements sur un seul serveur. Un bloc vide suffit pour utiliser les valeurs par défaut.
    ```caddyfile
    handle /ws {
        go_handler {}
    }
    ```

-   **Redis:** Pour les déploiements multi-serveurs en scaling horizontal.
    ```caddyfile
    handle /ws {
        go_handler {
            driver redis
            redis_address redis.internal:6379
            auth_endpoint http://localhost:8080/api/auth
        }
    }
