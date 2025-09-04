# FrankenPHP Realtime Project

A channel-based WebSocket broadcast service built with a Go Caddy module. This project serves as a technical demonstration of a real-time communication architecture using FrankenPHP.

It is **not** considered production-ready and has several known limitations detailed below.

## Architecture

The system uses a "Hub and Spoke" architecture to manage connections and messages, with a pluggable broker to allow for horizontal scaling.

-   **Hub (`handler/hub.go`):** The central component, running in a single goroutine. It manages the state of client subscriptions for a single server instance. Its channel-based design ensures concurrency safety. The Hub implements a graceful shutdown routine to properly close connections and resources.
-   **Client (`handler/hub.go`):** A wrapper for each `*websocket.Conn`. Each client runs two dedicated goroutines (`readPump`, `writePump`) to handle I/O, respecting the `gorilla/websocket` concurrency model.
-   **Authentication Flow (JWT):** The WebSocket connection is secured via a JSON Web Token (JWT) authentication process.
    1.  A user authenticates by sending a `POST` request to a PHP endpoint (`/login.php`).
    2.  The server generates a signed JWT containing the user's identity and an expiration date, then sets it in a secure `AUTH_TOKEN` cookie (`HttpOnly`, `SameSite=Strict`).
    3.  When a WebSocket connection to `/ws` is attempted, the Go handler performs an internal HTTP request to a validation endpoint (`/auth.php`), forwarding the cookie.
    4.  The PHP endpoint validates the JWT's signature and expiration. If the token is valid, it returns a `200 OK` response with the user ID.
    5.  The Go handler upgrades the HTTP request to a WebSocket connection only if the validation succeeds.
-   **Broadcast Mechanism (Internal HTTP):** To decouple the PHP application from the Go infrastructure, message broadcasting is handled via an internal HTTP endpoint. The PHP application sends a `POST` request to `/internal/broadcast`. This endpoint, managed by the same Go handler, receives the message and publishes it to the configured broker. This approach avoids the tight coupling and deployment complexity of FFI.
-   **Broker (`handler/hub.go`):**
    -   **Memory Broker:** The default mode. Messages are broadcast in-memory to all clients connected to the *same server instance*. Suitable for simple, single-node deployments.
    -   **Redis Broker:** Messages are published to a Redis Pub/Sub channel. All server instances subscribe to this channel and deliver messages to their respective local clients, enabling horizontal scaling.
-   **Caddy Module (`handler/handler.go`):** A single Go module handles both WebSocket and broadcast requests using a Caddy path matcher (`@go_paths`):
    -   `/ws`: Manages the WebSocket handshake and authentication.
    -   `/internal/broadcast`: Receives messages for broadcasting.
    The module also implements the `caddy.CleanerUpper` interface to trigger a graceful shutdown when Caddy is reloaded or stopped.

## Design Choices and Known Limitations

This project was built as a learning foundation and has several limitations that must be addressed before any production use.

-   **Insecure Broadcast Endpoint:** The `/internal/broadcast` endpoint is publicly accessible on the same port as the main application. In a real-world deployment, this endpoint must be secured, for instance by moving it to a separate, non-public port, firewalling it to only allow localhost access, or requiring an API key.
-   **Lack of Presence Management:** The system is a pure "fire-and-forget" broadcast mechanism. It does not track user state within channels. Features like `getChannelUsers()` are not implementable without a shared state tracking mechanism (e.g., using Redis `SETS` to store user IDs per channel).
-   **Basic Error Handling:** The broker reconnection logic is a rudimentary `time.Sleep` loop. A more robust strategy like exponential backoff should be used. Furthermore, a failure to publish a message from PHP results only in a server-side log entry in Go, with no specific feedback to the original caller.
-   **No Automated Test Suite:** The project lacks any unit or integration tests. This is the most significant technical debt. Any future modifications are inherently risky and may introduce regressions.
-   **Session-Based CSRF Protection:** The CSRF protection on `send.php` relies on PHP sessions, which introduces statefulness. A stateless approach like the "double submit cookie" pattern could be considered as an alternative.

## API Reference

### Server-Side API (Broadcasting)

Broadcasting is performed by sending a `POST` request to the `/internal/broadcast` endpoint with the following `application/x-www-form-urlencoded` parameters:
-   `channel` (string): The name of the destination channel.
-   `message` (string): The message payload to be sent.

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

## Configuration (Caddyfile)

The application is configured via `app/Caddyfile`.

| Directive     | Description                                     | Default Value                    |
|---------------|-------------------------------------------------|----------------------------------|
| `driver`        | The broadcast backend to use (`memory` or `redis`). | `memory`                         |
| `redis_address` | The address of the Redis server.                | `localhost:6379`                 |
| `auth_endpoint` | The internal URL for JWT validation.            | `http://localhost:8080/auth.php` |

### Configuration Examples

-   **Default (In-Memory):**
    ```caddyfile
    handle @go_paths {
        go_handler {}
    }
    ```

-   **Redis (Horizontally Scaled):**
    ```caddyfile
    handle @go_paths {
        go_handler {
            driver redis
            redis_address redis.internal:6379
        }
    }
    ```

## Build Procedure

**(Prerequisites: Go (>= 1.25), xcaddy)**

The build process no longer requires PHP development headers or CGO, as the tight coupling via FFI has been removed.

Use `xcaddy` to compile FrankenPHP with the Go module included:

```console
CGO_ENABLED=1 \
XCADDY_GO_BUILD_FLAGS="-ldflags='-w -s' -tags=nobadger,nomysql,nopgx,nowatcher" \
CGO_CFLAGS=$(php-config --includes) \
CGO_LDFLAGS="$(php-config --ldflags) $(php-config --libs)" \
xcaddy build \
    --output app/frankenphp \
    --with github.com/y-l-g/realtime/handler=./handler \
    --with github.com/dunglas/frankenphp/caddy \
    --with github.com/dunglas/caddy-cbrotli
```