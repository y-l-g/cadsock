# FrankenPHP Realtime Project

A channel-based WebSocket broadcast service built with a Go Caddy module and a Go PHP extension.

## Architecture

The system uses a "Hub and Spoke" architecture for managing connections and messages, ensuring concurrency safety and performance.

-   **Hub (`handler/hub.go`):** The central component. It runs in a single goroutine and manages all state (channels, client subscriptions) via Go channels, avoiding the need for complex mutex locking in the core logic.
-   **Client (`handler/hub.go`):** A wrapper for each `*websocket.Conn`. Each client runs two dedicated goroutines (`readPump`, `writePump`) to handle I/O, respecting the one-reader/one-writer concurrency model of `gorilla/websocket`.
-   **Caddy Module (`handler/handler.go`):** The HTTP entry point. It upgrades HTTP requests to WebSocket connections and registers new `Client` instances with the `Hub`.
-   **PHP Extension (`broadcast/broadcast.go`):** An FFI bridge that exposes a native `broadcast()` function to PHP. It sends messages into the `Hub`'s broadcast channel for distribution.

## Project Structure

```
realtime/
├── app/
│   ├── Caddyfile
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
    -   Sends `$message` to all clients currently subscribed to `$channel`.

### Client-Side Protocol (JSON)

Clients communicate with the server over the WebSocket using simple JSON objects.

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

**Prerequisites:** Go (>= 1.25), PHP development headers (`php-config`), PHP source code.

**1. Install `frankenphp` binary**
Required for the `extension-init` tool.
```bash
curl -O https://github.com/dunglas/frankenphp/releases/latest/download/frankenphp-linux-x86_64
chmod +x frankenphp-linux-x86_64
sudo mv frankenphp-linux-x86_64 /usr/local/bin/frankenphp
```

**2. Generate Extension Stubs**
Creates CGO binding code in `broadcast/build/`.
```bash
# From project root, adjust PHP source path
GEN_STUB_SCRIPT=../php-8.4.11/build/gen_stub.php frankenphp extension-init broadcast/broadcast.go
```

**3. Compile Custom Binary**
Builds the final `frankenphp` binary with local Go modules statically linked.
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

**4. Run Server**
```bash
cd app
./frankenphp run```

## Configuration

The `app/Caddyfile` is configured via environment variables with sensible defaults.

-   `SERVER_ADDRESS`: The address and port for Caddy to listen on. (Default: `:8080`)
-   `ALLOWED_ORIGINS`: A space-separated list of WebSocket origins to allow. (Default: `http://localhost:8080`)

**Example (Production):**
```bash
SERVER_ADDRESS=":443" ALLOWED_ORIGINS="https://yourdomain.com" ./frankenphp run
```

## Resources

-   **FrankenPHP - Writing Extensions:** [https://frankenphp.dev/docs/extensions/](https://frankenphp.dev/docs/extensions/)
-   **FrankenPHP - Compiling:** [https://frankenphp.dev/docs/compile/](https://frankenphp.dev/docs/compile/)
-   **Caddy - Extending Caddy:** [https://caddyserver.com/docs/extending-caddy](https://caddyserver.com/docs/extending-caddy)

