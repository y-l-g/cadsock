# cadsock

A high-performance, language-agnostic WebSocket module for the Caddy web server. It provides a real-time messaging hub that can be integrated with any backend application capable of making HTTP requests.

The module is built in Go and leverages Caddy's powerful architecture to offer a scalable and efficient solution for adding real-time features to your web applications.

**Project Status:** This is a proof-of-concept and has not been battle-tested in a large-scale production environment. It serves as a solid foundation but lacks critical components like an automated test suite. See the "Known Limitations" section before considering production use.

## Features

-   **Language-Agnostic:** Your backend can be written in PHP, Python, Node.js, Ruby, or any other language. Broadcasting is done via a simple HTTP POST request.
-   **Scalable Architecture:** Start with a simple in-memory broker for single-node deployments and switch to a Redis Pub/Sub broker for horizontal scaling with a single line of configuration.
-   **Decoupled Authentication:** The module delegates authentication to your existing backend via a configurable webhook, allowing you to reuse your application's session and user logic. The recommended flow is JWT-based.
-   **Efficient & Performant:** Built in Go to handle a large number of concurrent WebSocket connections with a low memory footprint.
-   **Graceful Shutdown:** Integrates with Caddy's lifecycle to ensure clean shutdowns, properly closing client connections and broker resources.

## How It Works

The module exposes two primary endpoints managed by the same handler:

1.  `/ws`: The WebSocket endpoint where clients connect.
2.  `/internal/broadcast`: The HTTP endpoint your backend calls to send messages.

### The Authentication Flow

The module does not implement authentication logic itself. Instead, it acts as a gatekeeper that queries your backend.

1.  A client attempts to open a WebSocket connection to `/ws`.
2.  The module makes an internal HTTP request to the `auth_endpoint` you configured, forwarding the client's cookies.
3.  Your backend application at `auth_endpoint` receives this request. It's responsible for validating the user's session (e.g., by decoding a JWT from a cookie).
4.  If the user is valid, your backend must respond with `200 OK` and a JSON body containing a user identifier, like `{"id": "user-123"}`. Any other response is treated as an authentication failure.
5.  If authentication succeeds, the module upgrades the connection to a WebSocket. Otherwise, the connection is rejected.

### The Broadcast Flow

1.  An event occurs in your backend application (e.g., a new order is placed, a message is posted).
2.  Your backend sends a `POST` request to the module's `/internal/broadcast` endpoint.
3.  The module receives this request and publishes the message to the configured broker (Memory or Redis).
4.  The broker distributes the message to all connected and subscribed clients across all server instances.

## Usage Guide

### 1. Build Caddy with the Module

You must compile a custom Caddy binary that includes this module. The recommended way is to use `xcaddy`.

Assuming your module is located at a public Git repository:
```console
xcaddy build \
    --with github.com/y-l-g/cadsock
```
Or, from a local directory:
```console
xcaddy build \
    --with github.com/y-l-g/cadsock=./
```

### 2. Configure Your Caddyfile

Add a `handle` block to your `Caddyfile` to configure and activate the module.

```caddyfile
@go_paths path /ws /internal/broadcast

handle @go_paths {
    go_handler {
        # driver redis
        # redis_address localhost:6379
        # auth_endpoint http://localhost:8080/auth.php
    }
}
```

#### Configuration Directives

| Directive     | Description                                     | Default Value                    |
|---------------|-------------------------------------------------|----------------------------------|
| `driver`        | The broadcast backend (`memory` or `redis`).    | `memory`                         |
| `redis_address` | The address of the Redis server.                | `localhost:6379`                 |
| `auth_endpoint` | The internal URL for the authentication webhook. | `http://localhost:8080/auth.php` |

### 3. Implement Backend Endpoints

Your backend application is responsible for implementing the logic for the `auth_endpoint` and for sending broadcast requests.

-   **Authentication Endpoint:** Must validate credentials and return `{"id": "..."}` on success.
-   **Broadcasting:** Must send `POST` requests to `/internal/broadcast` with `channel` and `message` form fields.

## API Reference

### Module Endpoints

-   `GET /ws`: WebSocket handshake endpoint.
-   `POST /internal/broadcast`: Broadcast endpoint.
    -   `channel` (form field): The channel to publish to.
    -   `message` (form field): The message payload.

### Client-Side Protocol (JSON)

-   **Subscribe:**
    ```json
    { "action": "subscribe", "channel": "channel_name" }
    ```
-   **Unsubscribe:**
    ```json
    { "action": "unsubscribe", "channel": "channel_name" }
    ```

## Known Limitations

-   **Insecure Broadcast Endpoint:** The `/internal/broadcast` endpoint is not secured by the module itself. It is your responsibility to protect it using a firewall, network policies (e.g., binding it to a localhost-only port), or a Caddy directive that requires a secret token.
-   **No Presence Management:** The module is stateless and does not track which users are in which channels. Building features like "who's online" requires an external state store managed by your application.
-   **No Automated Tests:** The lack of a test suite is the biggest risk. Contributions in this area are highly welcome.

## Example Application

A complete example of a backend application using **FrankenPHP** is provided in the `examples/frankenphp-app` directory. It includes a working `Caddyfile` and all necessary PHP scripts to demonstrate the authentication and broadcast flows.