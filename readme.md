# cadsock

A high-performance, language-agnostic WebSocket module for the Caddy web server. It provides a resilient, real-time messaging hub that can be integrated with any backend application capable of making HTTP requests.

The module is built in Go and leverages Caddy's powerful, managed lifecycle to offer a scalable, secure, and efficient solution for adding real-time features to your web applications.

## Core Concepts

The module operates by exposing two primary endpoints, both managed by the `go_handler` directive:

1.  `/ws`: The WebSocket endpoint where clients establish a persistent connection.
2.  `/internal/broadcast`: A secure, internal HTTP endpoint your backend calls to publish messages to connected clients.

### The Authentication Flow

`cadsock` delegates authentication entirely to your existing backend application, acting as a secure gatekeeper. This allows you to reuse your application's session and user validation logic without modification.

1.  A client attempts to open a WebSocket connection to `/ws`.
2.  The module intercepts this request and makes an internal, server-to-server HTTP `GET` request to the configured `auth_endpoint`. For security, only a **safe subset of headers** from the original client request are forwarded, including `Cookie`, `Authorization`, `User-Agent`, and IP-forwarding headers.
3.  Your backend application at the `auth_endpoint` receives this request. It is responsible for validating the user's credentials using the provided headers (e.g., by decoding a JWT from a bearer token or validating a session cookie).
4.  If the user is valid, your backend **must** respond with a `200 OK` status and a JSON body containing a unique user identifier, such as `{"id": "user-123"}`.
5.  Any other response status or a malformed JSON body is treated as an authentication failure. If authentication succeeds, `cadsock` upgrades the client's connection to a WebSocket; otherwise, the connection is rejected with an HTTP error.

### The Broadcast Flow

Broadcasting is designed for server-to-server communication and is secured by a shared secret key.

1.  An event occurs in your backend application (e.g., a new order is placed, a user posts a comment).
2.  Your backend sends an HTTP `POST` request to the module's `/internal/broadcast` endpoint.
3.  This request **must** include a secret token in the `X-Broadcast-Secret` header to authenticate the broadcast request itself.
4.  The body of the POST request must contain two form fields: `channel` (the topic to publish to) and `message` (the payload, which must be a valid JSON value).
5.  `cadsock` validates the secret. If valid, it publishes the message to the configured broker (In-Memory or Redis).
6.  The broker distributes the message to all clients currently subscribed to that channel across all server instances.

## Features

-   **Language-Agnostic:** Your backend can be written in PHP, Python, Node.js, Ruby, or any other language capable of making HTTP requests.
-   **Secure Authentication:** Forwards a safe whitelist of headers (`Cookie`, `Authorization`, etc.) to your backend, supporting virtually any authentication scheme without exposing internal server details.
-   **Secure by Default:** The critical `/internal/broadcast` endpoint is protected by a mandatory shared secret, preventing unauthorized message publishing.
-   **Resilient and Scalable:** Features automatic reconnection to the message broker (e.g., Redis) with exponential backoff. Start with an in-memory broker and scale horizontally to a Redis Pub/Sub cluster with a single line of configuration.
-   **Unit Tested Core:** The central hub logic is covered by unit tests, ensuring reliability and simplifying maintenance.
-   **Flexible Origin Control:** Use the `allowed_origins` directive to precisely control which domains can establish WebSocket connections, perfect for securing production and enabling local development.
-   **Robust Communication Protocol:** All server-to-client communication uses a clear JSON protocol, providing clients with explicit confirmations and detailed error messages for easier debugging.

## Usage Guide

### 1. Build Caddy with the Module

You must compile a custom Caddy binary that includes this module. The recommended way is to use `xcaddy`.

```console
# From anywhere
xcaddy build \
    --with github.com/y-l-g/cadsock
```

### 2. Configure Your Caddyfile

Add a `handle` block to your `Caddyfile` to configure and activate the module.

```caddyfile
@cadsock_paths path /ws /internal/broadcast

handle @cadsock_paths {
    go_handler {
        # The shared secret for securing the broadcast endpoint.
        # This is mandatory for production.
        broadcast_secret "your-very-strong-and-secret-key"

        # The internal URL for the authentication webhook.
        auth_endpoint http://localhost:8080/auth.php

        # (Optional) A space-separated list of allowed WebSocket origins.
        # Defaults to same-origin if not set.
        allowed_origins http://localhost:8080 http://localhost:3000

        # (Optional) The broadcast backend driver ("memory" or "redis").
        # driver redis

        # (Optional) The address of the Redis server if driver is "redis".
        # redis_address localhost:6379
    }
}
```

#### Configuration Directives

| Directive | Description | Default Value |
| :--- | :--- | :--- |
| `broadcast_secret` | **(Required)** The shared secret sent in the `X-Broadcast-Secret` header. | (none) |
| `auth_endpoint` | The internal URL for the authentication webhook. | `http://localhost:8080/auth.php` |
| `allowed_origins` | A space-separated list of allowed WebSocket origins. | (Same-origin policy) |
| `driver` | The broadcast backend (`memory` or `redis`). | `memory` |
| `redis_address` | The address of the Redis server. | `localhost:6379` |

### 3. Implement Backend Endpoints

Your application is responsible for two key pieces of logic:

1.  **Authentication Endpoint (`auth_endpoint`)**
    -   Must inspect incoming headers (e.g., `Cookie`, `Authorization`) to validate the user.
    -   On success, must respond with `200 OK` and a JSON body: `{"id": "some-user-id"}`.
    -   On failure, must respond with a non-200 status code.

2.  **Broadcasting Logic**
    -   To send a message, make a `POST` request to `/internal/broadcast`.
    -   The request must include the header: `X-Broadcast-Secret: your-very-strong-and-secret-key`.
    -   The request body must be `application/x-www-form-urlencoded` with two fields:
        -   `channel`: The target channel name (e.g., `orders`).
        -   `message`: The message payload, **which must be a valid JSON value** (e.g., a JSON-encoded string `"hello"`, a number `123`, or an object `{"foo":"bar"}`).

## Communication Protocol

### Client-to-Server (JSON)

Clients send JSON messages to the `/ws` endpoint to manage subscriptions.

-   **Subscribe:**
    ```json
    { "action": "subscribe", "channel": "channel_name" }
    ```-   **Unsubscribe:**
    ```json
    { "action": "unsubscribe", "channel": "channel_name" }
    ```

### Server-to-Client (JSON)

The server sends structured JSON messages to clients to confirm actions or deliver broadcasts. All messages from the server have a `type` field.

-   **Subscription Confirmation:**
    ```json
    { "type": "subscribed", "channel": "channel_name" }
    ```
-   **Broadcast Message:**
    ```json
    {
      "type": "message",
      "channel": "channel_name",
      "payload": "your-json-encoded-message"
    }
    ```
-   **Error Message:** Sent when the client sends a malformed or invalid request.
    ```json
    { "type": "error", "error": "a description of the error" }
    ```

## Example Application

A complete example of a backend application using **FrankenPHP** is provided in the `examples/frankenphp-app` directory. It includes a working `Caddyfile` and all necessary PHP scripts to demonstrate the authentication and broadcast flows.

The example has been updated to follow best practices:
-   It reads secrets from environment variables rather than hardcoding them.
-   It uses **cURL** for robust server-to-server broadcast requests.
-   The frontend includes **automatic reconnection logic** with exponential backoff.
-   It includes a `send_cli.php` script demonstrating the primary server-to-server broadcast use case.

To run the example, first build the custom Caddy binary.

```console
CGO_ENABLED=1 \
XCADDY_GO_BUILD_FLAGS="-ldflags='-w -s' -tags=nobadger,nomysql,nopgx,nowatcher" \
CGO_CFLAGS=$(php-config --includes) \
CGO_LDFLAGS="$(php-config --ldflags) $(php-config --libs)" \
xcaddy build \
    --output examples/frankenphp-app/frankenphp \
    --with github.com/y-l-g/cadsock=. \
    --with github.com/dunglas/frankenphp/caddy \
    --with github.com/dunglas/caddy-cbrotli
```

Then, from the project root:

```console
cd examples/frankenphp-app
JWT_SECRET_KEY='your-super-secret-key' \
BROADCAST_SECRET_KEY='your-very-strong-and-secret-key' \
./frankenphp run
```
Then visit localhost:8080 and localhost:8080/send.php

## Known Limitations & Future Work

-   **No Presence Management:** The module is stateless and does not track which users are in which channels. Building features like "who's online" requires an external state store managed by your application. This is a deliberate design choice to keep the module simple and scalable.
-   **Expand Test Coverage:** While the core hub logic is unit-tested, integration tests could be added to further guarantee stability across different versions of Caddy and other dependencies.
-   **Advanced Protocol Features:** The client-server protocol could be extended to include acknowledgements (QoS), request IDs, or binary message support in the future.