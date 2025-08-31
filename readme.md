# FrankenPHP Realtime Project

This project implements a WebSocket broadcast service, architected around two distinct Go components: a Caddy module for connection management and a PHP extension to interface with the application code.

## Technical Architecture

-   **Caddy Module (`handler`)**: An HTTP handler that intercepts requests on `/ws`, upgrades them to WebSocket connections using the `github.com/gorilla/websocket` library, and maintains them in a shared pool.
-   **PHP Extension (`broadcast`)**: Exposes a native `broadcast(string)` function to the PHP environment. This function acts as a Foreign Function Interface (FFI) bridge to trigger a message broadcast to the WebSocket client pool managed by the Caddy module.
-   **Application (`app`)**: Contains the `Caddyfile`, a JavaScript WebSocket client (`index.php`), and the dispatch script (`send.php`).

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
    └── go.mod
```

## Prerequisites

-   Go (>= 1.21)
-   PHP with development headers (`php-config` must be available)
-   Source code of the PHP version being used

## Build and Run Procedure

### 1. Install the `frankenphp` binary

A `frankenphp` binary is required for the `extension-init` tool.

```bash
curl -O https://github.com/dunglas/frankenphp/releases/latest/download/frankenphp-linux-x86_64
chmod +x frankenphp-linux-x86_64
sudo mv frankenphp-linux-x86_64 /usr/local/bin/frankenphp
```

### 2. Generate the PHP Extension

This step generates the CGO stubs and binding code in the `broadcast/build/` directory.

```bash
# From the realtime/ project root
# Adjust the path to your PHP sources.
GEN_STUB_SCRIPT=../php-8.3.11/build/gen_stub.php frankenphp extension-init broadcast/broadcast.go
```

### 3. Compile the Custom Binary

Compile a FrankenPHP binary that includes both Go modules.

```bash
# From the realtime/ project root
CGO_ENABLED=1 \
XCADDY_GO_BUILD_FLAGS="-ldflags='-w -s'" \
CGO_CFLAGS=$(php-config --includes) \
CGO_LDFLAGS="$(php-config --ldflags) $(php-config --libs)" \
xcaddy build \
    --output app/frankenphp \
    --with github.com/y-l-g/realtime/handler@main \
    --with github.com/y-l-g/realtime/broadcast/build@main
```

The resulting binary (`app/frankenphp`) is statically linked with our WebSocket logic and PHP extension.

### 4. Run

```bash
cd app
./frankenphp run
```

The server is now listening on `localhost:8080`.

## Testing the Functionality

1.  **Client**: Open `http://localhost:8080` in a browser. The WebSocket connection is established.
2.  **Server**: Make a request to `http://localhost:8080/send.php`.
3.  **Result**: The message sent via `send.php` instantly appears on the `index.php` page.

## Technical Implementation Details

### `handler` Module (`handler.go`)

-   **Role**: Manages the lifecycle of WebSocket connections.
-   **Caddy Implementation**: Registers an `http.handlers.go_handler` module. The `go_handler` directive in the `Caddyfile` activates this module.
-   **Connection Management**: The `gorilla/websocket` library is used via its `websocket.Upgrader` to switch protocols from HTTP to WebSocket.
-   **Concurrency**: Client connections (`*websocket.Conn`) are stored in a global map `Clients`. Access to this map (add, delete, iterate) is synchronized using a `sync.Mutex` (`ClientsMu`) to ensure thread-safety.
-   **Public API**: The `BroadcastMessage(msg []byte)` function is the only one exported. It takes a `[]byte` argument for performance reasons, as the underlying `websocket.Conn.WriteMessage` function expects this type, thus avoiding a `string` -> `[]byte` conversion on every broadcast.

### `broadcast` Extension (`broadcast.go`)

-   **Role**: Provides an entry point from PHP to the Go broadcast logic.
-   **Go-PHP Binding**: The `//export_php:function broadcast(string $message): void` directive is used by the `frankenphp extension-init` tool to generate the FFI code.
-   **Data Flow**:
    1.  PHP calls `broadcast("...")`.
    2.  The PHP engine passes a `*C.zend_string` to the Go `broadcast` function.
    3.  `frankenphp.GoString(unsafe.Pointer(message))` converts the `*C.zend_string` into a Go `string`.
    4.  The Go `string` is cast to a `[]byte`.
    5.  This `[]byte` is passed to `handler.BroadcastMessage()`.

## Resources

-   **FrankenPHP - Writing Extensions:** [https://frankenphp.dev/docs/extensions/](https://frankenphp.dev/docs/extensions/)
-   **FrankenPHP - Compiling:** [https://frankenphp.dev/docs/compile/](https://frankenphp.dev/docs/compile/)
-   **Caddy - Extending Caddy:** [https://caddyserver.com/docs/extending-caddy](https://caddyserver.com/docs/extending-caddy)