# Project Code Context

## Project Structure

```realtime/
├── app/
│   ├── Caddyfile
│   ├── auth.php
│   ├── composer.json
│   ├── index.php
│   ├── login.php
│   ├── logout.php
│   ├── send.php
│   └── vendor/
└── handler/
    ├── handler.go
    ├── hub.go
    └── go.mod
```

---

### `app/Caddyfile`

```caddyfile
{
	http_port {$SERVER_ADDRESS:8080}
    frankenphp
    order go_handler before file_server
}

{$SERVER_ADDRESS::8080}

@is_bad_origin {
    header Origin *
    not header Origin {$ALLOWED_ORIGINS:http://localhost:8080}
}

@go_paths path /ws /internal/broadcast

handle @go_paths {
    abort @is_bad_origin
    
    go_handler {
        # driver redis
        # redis_address localhost:6379
        # auth_endpoint http://localhost:8080/api/auth
    }
}

php_server
```

---

### `app/composer.json`

```json
{
    "require": {
        "firebase/php-jwt": "^6.10"
    },
    "config": {
        "allow-plugins": {
            "php-http/discovery": true
        }
    }
}
```

---

### `app/login.php`

```php
<?php
require_once __DIR__ . '/vendor/autoload.php';
use Firebase\JWT\JWT;

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);
$userId = $input['userId'] ?? null;

if (empty($userId)) {
    http_response_code(400);
    echo json_encode(['error' => 'User ID is required']);
    exit;
}

$secretKey = 'your-super-secret-key-that-no-one-knows';
$payload = [
    'iat' => time(),
    'exp' => time() + 3600,
    'sub' => $userId
];

$jwt = JWT::encode($payload, $secretKey, 'HS256');

setcookie('AUTH_TOKEN', $jwt, [
    'expires' => time() + 3600,
    'path' => '/',
    'httponly' => true,
    'samesite' => 'Strict'
]);

http_response_code(200);
echo json_encode(['status' => 'ok']);
```

---

### `app/logout.php`

```php
<?php

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit;
}

setcookie('AUTH_TOKEN', '', [
    'expires' => time() - 3600,
    'path' => '/',
    'httponly' => true,
    'samesite' => 'Strict'
]);

http_response_code(200);
echo json_encode(['status' => 'logged_out']);
```

---

### `app/auth.php`

```php
<?php
require_once __DIR__ . '/vendor/autoload.php';
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

header('Content-Type: application/json');

$token = $_COOKIE['AUTH_TOKEN'] ?? null;

if (!$token) {
    http_response_code(401);
    echo json_encode(['error' => 'Missing authentication token']);
    exit;
}

$secretKey = 'your-super-secret-key-that-no-one-knows';

try {
    $decoded = JWT::decode($token, new Key($secretKey, 'HS256'));
    $userId = $decoded->sub;

    http_response_code(200);
    echo json_encode(['id' => $userId]);

} catch (Exception $e) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized: ' . $e->getMessage()]);
}
```

---

### `app/index.php`

```php
<?php
$isAuthenticated = isset($_COOKIE['AUTH_TOKEN']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WebSocket Test</title>
</head>
<body>
    <h1>WebSocket Channels</h1>

    <div>
        <strong>Authentication Status:</strong>
        <span id="auth-status" style="color: <?php echo $isAuthenticated ? 'green' : 'red'; ?>;">
            <?php echo $isAuthenticated ? 'Authenticated' : 'Not authenticated'; ?>
        </span>
    </div>

    <form id="login-form" style="margin-top: 10px;">
        <label for="userId">User ID:</label>
        <input type="text" id="userId" value="user-123">
        <button type="submit">Login</button>
        <button type="button" id="logout">Logout</button>
    </form>

    <hr>
    <div id="websocket-ui" style="display: <?php echo $isAuthenticated ? 'block' : 'none'; ?>;">
        <div id="connection-status" style="color: red;">Disconnected</div>
        <hr>
        <div>
            <label for="channel">Channel:</label>
            <input type="text" id="channel" value="news">
            <button id="subscribe">Subscribe to Channel</button>
        </div>
        <hr>
        <h2>Messages received:</h2>
        <ul id="messages"></ul>
    </div>

    <script>
        const isAuthenticated = <?php echo json_encode($isAuthenticated); ?>;
        const loginForm = document.getElementById('login-form');
        const userIdInput = document.getElementById('userId');
        const logoutBtn = document.getElementById('logout');
        const channelInput = document.getElementById('channel');
        const subscribeBtn = document.getElementById('subscribe');
        const messagesList = document.getElementById('messages');
        const statusDiv = document.getElementById('connection-status');
        let socket;

        function connect() {
            socket = new WebSocket("ws://localhost:8080/ws");

            socket.onopen = function(event) {
                statusDiv.textContent = 'Connected';
                statusDiv.style.color = 'green';
            };

            socket.onmessage = function(event) {
                let message = document.createElement("li");
                message.textContent = event.data;
                messagesList.appendChild(message);
            };

            socket.onclose = function(event) {
                statusDiv.textContent = `Disconnected. (Code: ${event.code})`;
                statusDiv.style.color = 'red';
            };
        }

        function subscribeToChannel() {
            const channel = channelInput.value;
            if (!channel || !socket || socket.readyState !== WebSocket.OPEN) return;
            const subscribeMsg = { action: "subscribe", channel: channel };
            socket.send(JSON.stringify(subscribeMsg));
            let message = document.createElement("li");
            message.style.color = 'blue';
            message.textContent = `Subscription request sent for channel "${channel}".`;
            messagesList.appendChild(message);
        }

        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const userId = userIdInput.value;
            if (!userId) return;
            const response = await fetch('/login.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ userId: userId })
            });
            if (response.ok) window.location.reload();
        });

        logoutBtn.addEventListener('click', async () => {
            const response = await fetch('/logout.php', { method: 'POST' });
            if (response.ok) window.location.reload();
        });

        subscribeBtn.addEventListener('click', subscribeToChannel);
        
        if (isAuthenticated) {
            connect();
        }
    </script>
</body>
</html>```

---

### `app/send.php`

```php
<?php
session_start();

function generate_csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validate_csrf_token($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function broadcast(string $channel, string $message): bool
{
    $url = 'http://localhost:8080/internal/broadcast';
    $data = http_build_query(['channel' => $channel, 'message' => $message]);
    $options = ['http' => ['header'  => "Content-type: application/x-www-form-urlencoded\r\n", 'method'  => 'POST', 'content' => $data, 'timeout' => 5]];
    $context = stream_context_create($options);
    $result = @file_get_contents($url, false, $context);

    if ($result === false) return false;

    $statusCode = (int) substr($http_response_header, 9, 3);
    return $statusCode >= 200 && $statusCode < 300;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !validate_csrf_token($_POST['csrf_token'])) {
        http_response_code(403);
        $status = "Error: Invalid CSRF token.";
    } else {
        $channel = $_POST['channel'] ?? 'default';
        $message = $_POST['message'] ?? 'empty message';
        $fullMessage = "($channel) " . $message . " at " . date('H:i:s');
        $status = broadcast($channel, $fullMessage) ? "Message sent to channel '{$channel}'." : "Error: Failed to broadcast message.";
    }
    unset($_SESSION['csrf_token']);
}

$csrf_token = generate_csrf_token();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Send Message</title>
</head>
<body>
    <h1>Send a WebSocket Message</h1>
    <?php if (isset($status)): ?><p><strong><?= htmlspecialchars($status) ?></strong></p><?php endif; ?>
    <form action="send.php" method="post">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
        <div>
            <label for="channel">Channel:</label>
            <input type="text" id="channel" name="channel" value="news" required>
        </div>
        <br>
        <div>
            <label for="message">Message:</label>
            <input type="text" id="message" name="message" value="Hello World!" required>
        </div>
        <br>
        <button type="submit">Send</button>
    </form>
</body>
</html>
```

---

### `handler/go.mod`

```go
module github.com/y-l-g/realtime/handler

go 1.25.0

require (
	github.com/caddyserver/caddy/v2 v2.10.0
	github.com/gorilla/websocket v1.5.3
	github.com/redis/go-redis/v9 v9.5.3
)

require (
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
)
```

---

### `handler/handler.go`

```go
package handler

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		u, err := url.Parse(origin)
		if err != nil {
			return false
		}
		return u.Host == r.Host
	},
}

func init() {
	caddy.RegisterModule(GoHandler{})
	httpcaddyfile.RegisterHandlerDirective("go_handler", parseGoHandler)
}

type GoHandler struct {
	Driver       string `json:"driver,omitempty"`
	RedisAddress string `json:"redis_address,omitempty"`
	AuthEndpoint string `json:"auth_endpoint,omitempty"`
	hub          *Hub
}

func (GoHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.go_handler",
		New: func() caddy.Module { return new(GoHandler) },
	}
}

func (h *GoHandler) Provision(ctx caddy.Context) error {
	var broker Broker
	switch h.Driver {
	case "redis":
		log.Println("Using Redis broker")
		broker = NewRedisBroker(h.RedisAddress)
	default:
		log.Println("Using in-memory broker")
		broker = NewMemoryBroker()
	}
	h.hub = NewHub(broker)
	go h.hub.Run()
	return nil
}

func (h *GoHandler) Cleanup() error {
	log.Println("Shutting down hub...")
	h.hub.Shutdown()
	return nil
}

func (h *GoHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	h.Driver = "memory"
	h.AuthEndpoint = "http://localhost:8080/auth.php"
	for d.Next() {
		if d.NextArg() { return d.ArgErr() }
		for d.NextBlock(0) {
			switch d.Val() {
			case "driver":
				if !d.NextArg() { return d.ArgErr() }
				h.Driver = d.Val()
			case "redis_address":
				if !d.NextArg() { return d.ArgErr() }
				h.RedisAddress = d.Val()
			case "auth_endpoint":
				if !d.NextArg() { return d.ArgErr() }
				h.AuthEndpoint = d.Val()
			}
		}
	}
	return nil
}

func parseGoHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler GoHandler
	err := handler.UnmarshalCaddyfile(h.Dispenser)
	return &handler, err
}

func (h *GoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	switch r.URL.Path {
	case "/ws":
		return h.serveWs(w, r)
	case "/internal/broadcast":
		return h.serveBroadcast(w, r)
	default:
		return next.ServeHTTP(w, r)
	}
}

func (h *GoHandler) serveBroadcast(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return nil
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return err
	}
	channel, message := r.FormValue("channel"), r.FormValue("message")
	if channel == "" || message == "" {
		http.Error(w, "Missing channel or message", http.StatusBadRequest)
		return nil
	}
	if h.hub == nil || h.hub.broker == nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return errors.New("hub or broker not initialized")
	}
	if err := h.hub.broker.Publish(channel, []byte(message)); err != nil {
		log.Printf("error publishing message: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return err
	}
	w.WriteHeader(http.StatusAccepted)
	return nil
}

func (h *GoHandler) serveWs(w http.ResponseWriter, r *http.Request) error {
	authReq, err := http.NewRequest(http.MethodGet, h.AuthEndpoint, nil)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return err
	}
	if cookie, err := r.Cookie("AUTH_TOKEN"); err == nil {
		authReq.AddCookie(cookie)
	}
	resp, err := (&http.Client{}).Do(authReq)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("authentication failed")
	}
	var authResponse struct{ ID string `json:"id"` }
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil || authResponse.ID == "" {
		return errors.New("invalid auth response")
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return err
	}
	client := &Client{hub: h.hub, conn: conn, send: make(chan []byte, 256), UserID: authResponse.ID}
	h.hub.register <- client
	go client.writePump()
	client.readPump()
	return nil
}

var (
	_ caddy.Module                = (*GoHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*GoHandler)(nil)
	_ caddy.Provisioner           = (*GoHandler)(nil)
	_ caddy.CleanerUpper          = (*GoHandler)(nil)
	_ caddyfile.Unmarshaler       = (*GoHandler)(nil)
)
```

---

### `handler/hub.go`

```go
package handler

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()

const (
	writeWait = 10 * time.Second; pongWait = 60 * time.Second
	pingPeriod = (pongWait * 9) / 10; maxMessageSize = 512
)

type ClientProtocolMessage struct {
	Action  string `json:"action"`
	Channel string `json:"channel"`
}

type Client struct {
	hub *Hub; conn *websocket.Conn
	send chan []byte; UserID string
}

func (c *Client) readPump() {
	defer func() { c.hub.unregister <- c; c.conn.Close() }()
	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error { c.conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil { break }
		var msg ClientProtocolMessage
		if err := json.Unmarshal(message, &msg); err != nil { continue }
		switch msg.Action {
		case "subscribe":
			c.hub.subscribe <- subscription{client: c, channel: msg.Channel}
		case "unsubscribe":
			c.hub.unsubscribe <- subscription{client: c, channel: msg.Channel}
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() { ticker.Stop(); c.conn.Close() }()
	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok { c.conn.WriteMessage(websocket.CloseMessage, []byte{}); return }
			c.conn.WriteMessage(websocket.TextMessage, message)
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil { return }
		}
	}
}

type Broker interface {
	Publish(channel string, message []byte) error
	Subscribe() (<-chan *BrokerMessage, error)
	Close() error
}

type BrokerMessage struct { Channel string; Payload []byte }
type MemoryBroker struct{ broadcast chan *BrokerMessage }

func NewMemoryBroker() *MemoryBroker { return &MemoryBroker{broadcast: make(chan *BrokerMessage, 256)} }
func (b *MemoryBroker) Publish(channel string, message []byte) error { b.broadcast <- &BrokerMessage{channel, message}; return nil }
func (b *MemoryBroker) Subscribe() (<-chan *BrokerMessage, error) { return b.broadcast, nil }
func (b *MemoryBroker) Close() error { close(b.broadcast); return nil }

type RedisBroker struct{ client *redis.Client }

func NewRedisBroker(address string) *RedisBroker {
	if address == "" { address = "localhost:6379" }
	return &RedisBroker{client: redis.NewClient(&redis.Options{Addr: address})}
}
func (b *RedisBroker) Publish(channel string, message []byte) error { return b.client.Publish(ctx, "realtime:"+channel, message).Err() }
func (b *RedisBroker) Subscribe() (<-chan *BrokerMessage, error) {
	pubsub := b.client.PSubscribe(ctx, "realtime:*")
	if _, err := pubsub.Receive(ctx); err != nil { return nil, err }
	ch := make(chan *BrokerMessage)
	go func() {
		defer close(ch); defer pubsub.Close()
		for msg := range pubsub.Channel() { ch <- &BrokerMessage{Channel: msg.Channel[len("realtime:"):], Payload: []byte(msg.Payload)} }
	}()
	return ch, nil
}
func (b *RedisBroker) Close() error { return b.client.Close() }

type Hub struct {
	broker Broker; channels map[string]map[*Client]bool; clients map[*Client]map[string]bool
	register, unregister chan *Client; subscribe, unsubscribe chan subscription; shutdown chan struct{}
}
type subscription struct { client *Client; channel string }

func NewHub(broker Broker) *Hub {
	return &Hub{
		broker: broker, register: make(chan *Client), unregister: make(chan *Client),
		subscribe: make(chan subscription), unsubscribe: make(chan subscription),
		channels: make(map[string]map[*Client]bool), clients: make(map[*Client]map[string]bool),
		shutdown: make(chan struct{}),
	}
}
func (h *Hub) Shutdown() { close(h.shutdown) }

func (h *Hub) Run() {
	var brokerCh <-chan *BrokerMessage
	for {
		var err error
		if brokerCh, err = h.broker.Subscribe(); err == nil { break }
		log.Printf("Failed to subscribe to broker, retrying in 5 seconds: %v", err)
		time.Sleep(5 * time.Second)
	}
	for {
		select {
		case client := <-h.register:
			h.clients[client] = make(map[string]bool)
		case client := <-h.unregister:
			if channels, ok := h.clients[client]; ok {
				for channel := range channels {
					if clientsInChannel, ok := h.channels[channel]; ok {
						delete(clientsInChannel, client)
						if len(clientsInChannel) == 0 { delete(h.channels, channel) }
					}
				}
				delete(h.clients, client)
			}
			close(client.send)
		case sub := <-h.subscribe:
			if _, ok := h.channels[sub.channel]; !ok { h.channels[sub.channel] = make(map[*Client]bool) }
			h.channels[sub.channel][sub.client] = true
			h.clients[sub.client][sub.channel] = true
		case sub := <-h.unsubscribe:
			if clients, ok := h.channels[sub.channel]; ok {
				delete(clients, sub.client)
				if len(clients) == 0 { delete(h.channels, sub.channel) }
			}
			if channels, ok := h.clients[sub.client]; ok { delete(channels, sub.channel) }
		case msg := <-brokerCh:
			if clients, ok := h.channels[msg.Channel]; ok {
				for client := range clients {
					select {
					case client.send <- msg.Payload:
					default: close(client.send); delete(clients, client)
					}
				}
			}
		case <-h.shutdown:
			for client := range h.clients { close(client.send) }
			h.broker.Close()
			return
		}
	}
}
```