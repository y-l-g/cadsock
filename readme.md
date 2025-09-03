Of course. Here is the complete `readme.md` file, rewritten in English to reflect all the recent architectural improvements and roadmap updates.

---

# FrankenPHP Realtime Project

A channel-based WebSocket broadcast service built with a Go Caddy module and a Go PHP extension, featuring pluggable backends for single-node or horizontally-scaled deployments.

## Architecture

The system uses a "Hub and Spoke" architecture for managing connections and messages. It is designed to be both simple for small projects and scalable for production environments.

-   **Hub (`handler/hub.go`):** The central component. It runs in a single goroutine and manages all state (channels, client subscriptions) for the clients connected to a single server instance. Its channel-based design ensures concurrency safety without the need for complex locks.
-   **Client (`handler/hub.go`):** A wrapper for each `*websocket.Conn`. Each client runs two dedicated goroutines (`readPump`, `writePump`) to handle I/O, respecting the one-reader/one-writer concurrency model of `gorilla/websocket`.
-   **Authentication:** The WebSocket connection is secured via a mandatory authentication step. The Go handler performs an internal HTTP request to a configurable PHP endpoint to validate the user's session (e.g., via a cookie). If the PHP script returns a successful response, the connection is upgraded and associated with a User ID.
-   **Broker (`handler/hub.go`):** To support both single-node and multi-node deployments, the Hub uses a pluggable "Broker" for broadcasting messages.
    -   **Memory Broker:** The default mode. Messages are broadcast in-memory to all clients connected to the *same server instance*. Perfect for simple, single-server applications.
    -   **Redis Broker:** When enabled, messages are published to a Redis Pub/Sub channel. All server instances subscribe to a channel pattern (using `PSUBSCRIBE`) and deliver messages to their respective local clients, enabling seamless horizontal scaling.
-   **Caddy Module (`handler/handler.go`):** The HTTP entry point. It handles the authentication flow and upgrades authorized HTTP requests to WebSocket connections.
-   **PHP Extension (`broadcast/broadcast.go`):** An FFI bridge that exposes a native `broadcast()` function to PHP. This function sends messages to the configured Broker for distribution.

## Key Features

-   **Secure by Default:** WebSocket connections are rejected unless authenticated via a backend PHP endpoint, whose URL is fully configurable.
-   **Scalable Architecture:** Start with a simple in-memory setup and switch to a Redis-backed backend for horizontal scaling with a single line of configuration. No code changes required.
-   **Decoupled:** The Go handler delegates all authentication logic to your existing PHP application, allowing you to reuse your session management and user logic.
-   **Robust and Resilient:** The Hub is designed to handle service interruptions. If the broker becomes unavailable (e.g., a Redis restart), it will automatically attempt to reconnect without crashing the main server.

## Roadmap: Next Steps for Production Readiness

Now that the core architecture is secure, scalable, and robust, the next priorities are to enrich the API and ensure long-term stability.

1.  **Implement an Automated Test Suite:** Before adding new features, it's crucial to build an integration test suite (e.g., with Docker and Pest) to validate the current behavior and prevent future regressions.
2.  **Enrich the PHP API:** The PHP API must be expanded to allow for finer control:
    *   `broadcastToUser(int|string $userId, string $message)`: To send a private message to a specific user across all server instances.
    *   `getChannelUsers(string $channel): array`: To get a list of users subscribed to a channel (requires a backend like Redis to store this shared state).
    *   `disconnectUser(int|string $userId)`: To forcibly close a user's connection.
3.  **Add Presence Hooks:** Provide a mechanism to notify the PHP application when a user joins or leaves a channel. This allows for easily building "who's online?" features.

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
    -   Sends `$message` to all clients currently subscribed to `$channel` via the configured broker.

### Client-Side Protocol (JSON)

-   **Subscribe to a channel:**
    ```json
    {
        "action": "subscribe",
        "channel": "channel_name"
    }
    ```
-   **Unsubscribe from a channel:**
    ```json
    {
        "action": "unsubscribe",
        "channel": "channel_name"
    }
    ```

## Build Procedure

**(Prerequisites: Go (>= 1.25), PHP development headers (`php-config`), PHP source code.)**

The build procedure remains the same. After any changes in the `handler` or `broadcast` Go modules, you must recompile the FrankenPHP binary.

## Configuration

The application is configured via the `app/Caddyfile`. The `go_handler` directive accepts several options within its configuration block.

| Directive | Description | Default Value |
|---|---|---|
| `driver` | The broadcast backend to use (`memory` or `redis`). | `memory` |
| `redis_address` | The address of the Redis server (used if `driver` is `redis`). | `localhost:6379` |
| `auth_endpoint` | The full internal URL for authentication validation. | `http://localhost:8080/auth.php` |

### Configuration Examples

-   **Default (In-Memory):** For single-server deployments. An empty block is sufficient to use the defaults.
    ```caddyfile
    handle /ws {
        go_handler {}
    }
    ```

-   **Redis:** For multi-server, horizontally-scaled deployments.
    ```caddyfile
    handle /ws {
        go_handler {
            driver redis
            redis_address redis.internal:6379
            auth_endpoint http://localhost:8080/api/auth
        }
    }
    ```