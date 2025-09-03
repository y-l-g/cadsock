# FrankenPHP Realtime Project

A channel-based WebSocket broadcast service built with a Go Caddy module and a Go PHP extension, featuring pluggable backends for single-node or horizontally-scaled deployments.

## Architecture

The system uses a "Hub and Spoke" architecture for managing connections and messages. It is designed to be both simple for small projects and scalable for production environments.

-   **Hub (`handler/hub.go`):** The central component. It runs in a single goroutine and manages all state (channels, client subscriptions) for the clients connected to a single server instance.
-   **Client (`handler/hub.go`):** A wrapper for each `*websocket.Conn`. Each client runs two dedicated goroutines (`readPump`, `writePump`) to handle I/O, respecting the one-reader/one-writer concurrency model of `gorilla/websocket`.
-   **Authentication:** The WebSocket connection is secured via a mandatory authentication step. The Go handler performs an internal HTTP request to a PHP endpoint (`/auth.php`) to validate the user's session (e.g., via a cookie). If the PHP script returns a successful response, the connection is upgraded and associated with a User ID.
-   **Broker (`handler/hub.go`):** To support both single-node and multi-node deployments, the Hub uses a pluggable "Broker" for broadcasting messages.
    -   **Memory Broker:** The default mode. Messages are broadcast in-memory to all clients connected to the *same server instance*. Perfect for simple, single-server applications.
    -   **Redis Broker:** When enabled, messages are published to a Redis Pub/Sub channel. All server instances subscribe to this channel and deliver messages to their respective local clients, enabling seamless horizontal scaling.
-   **Caddy Module (`handler/handler.go`):** The HTTP entry point. It handles the authentication flow and upgrades authorized HTTP requests to WebSocket connections.
-   **PHP Extension (`broadcast/broadcast.go`):** An FFI bridge that exposes a native `broadcast()` function to PHP. This function sends messages to the configured Broker for distribution.

## Key Features

-   **Secure by Default:** WebSocket connections are rejected unless authenticated via a backend PHP endpoint.
-   **Scalable Architecture:** Start with a simple in-memory setup and switch to a Redis-backed backend for horizontal scaling with a single line of configuration. No code changes required.
-   **Decoupled:** The Go handler delegates all authentication logic to your existing PHP application, allowing you to reuse your session management and user logic.

## Roadmap: The Essential Next Steps

Now that the core architecture is secure and scalable, the next priorities are to enrich the API and add more features:

1.  **Richer PHP API:** The PHP API must be expanded to allow for finer control:
    *   `broadcastToUser(int|string $userId, string $message)`: To send a private message to a specific user across all server instances.
    *   `getChannelUsers(string $channel): array`: To get a list of users subscribed to a channel (requires a backend like Redis to store this shared state).
    *   `disconnectUser(int|string $userId)`: To forcibly close a user's connection.
2.  **Presence Hooks:** Provide a mechanism to notify the PHP application when a user joins or leaves a channel. This allows for easily building "who's online?" features.

## Project Structure

```
realtime/
├── app/
│   ├── Caddyfile
│   ├── auth.php      # New authentication endpoint
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

**1. Generate Extension Stubs (if `broadcast.go` changes)**
```bash
# From project root, adjust PHP source path
GEN_STUB_SCRIPT=../php-8.4.11/build/gen_stub.php frankenphp extension-init broadcast/broadcast.go
cp broadcast/go.mod broadcast/build/go.mod
```

**2. Compile Custom Binary**
```bash
# From project root
CGO_ENABLED=1 \
XCADDY_GO_BUILD_FLAGS="-ldflags='-w -s'" \
CGO_CFLAGS=$(php-config --includes) \
CGO_LDFLAGS="$(php-config --ldflags) $(php-config --libs)" \
xcaddy build \
    --output app/frankenphp \
    --with github.com/y-l-g/realtime/handler=./handler \
    --with github.com/y-l-g/realtime/broadcast/build=./broadcast/build \
    --with github.com/dunglas/frankenphp/caddy \
    --with github.com/dunglas/caddy-cbrotli
```

**3. Run Server**
```bash
cd app
./frankenphp run
```

## Configuration

The application is configured via the `app/Caddyfile`.

### Broker Configuration

The WebSocket handler can be configured to use different broadcasting backends.

-   **Default (In-Memory):** For single-server deployments. No specific configuration is needed.
    ```caddyfile
    handle /ws {
        go_handler
    }
    ```

-   **Redis:** For multi-server, horizontally-scaled deployments.
    ```caddyfile
    handle /ws {
        go_handler {
            driver redis
            redis_address localhost:6379
        }
    }
    ```

### Environment Variables

-   `SERVER_ADDRESS`: The address and port for Caddy to listen on. (Default: `:8080`)
-   `ALLOWED_ORIGINS`: A space-separated list of WebSocket origins to allow. (Default: `http://localhost:8080`)
