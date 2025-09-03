# Project Code Context

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

---

### `app/Caddyfile`

```caddyfile
{
	http_port {$SERVER_ADDRESS:8080}
    frankenphp
    order go_handler before file_server
}

{$SERVER_ADDRESS::8080}

@not_allowed_origins {
    not header Origin {$ALLOWED_ORIGINS:http://localhost:8080}
}

handle /ws {
    abort @not_allowed_origins
    
    # By default, the in-memory driver is used.
    # To enable Redis for horizontal scaling, uncomment the following block.
    # go_handler {
    #     driver redis
    #     redis_address localhost:6379
    # }
    go_handler
}

# The PHP server handles the web UI and the internal /auth.php endpoint
php_server
```

---

### `app/auth.php`

```php
<?php

header('Content-Type: application/json');

// This is a dummy authentication logic.
// In a real application, you would validate a session cookie or a JWT token
// against your database or session store.
if (isset($_COOKIE['AUTH_TOKEN']) && str_starts_with($_COOKIE['AUTH_TOKEN'], 'user-')) {
    http_response_code(200);
    echo json_encode(['id' => $_COOKIE['AUTH_TOKEN']]);
    exit;
}

http_response_code(401);
echo json_encode(['error' => 'Unauthorized']);
```

---

### `app/index.php`

```php
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
        <span id="auth-status" style="color: red;">Not authenticated</span>
    </div>

    <form id="login-form" style="margin-top: 10px;">
        <label for="userId">User ID:</label>
        <input type="text" id="userId" value="user-123">
        <button type-="submit">Login</button>
        <button type="button" id="logout">Logout</button>
    </form>

    <hr>
    <div id="websocket-ui" style="display: none;">
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
        const authStatus = document.getElementById('auth-status');
        const loginForm = document.getElementById('login-form');
        const userIdInput = document.getElementById('userId');
        const logoutBtn = document.getElementById('logout');
        const websocketUi = document.getElementById('websocket-ui');

        const channelInput = document.getElementById('channel');
        const subscribeBtn = document.getElementById('subscribe');
        const messagesList = document.getElementById('messages');
        const statusDiv = document.getElementById('connection-status');
        let socket;

        function getCookie(name) {
            const value = `; ${document.cookie}`;
            const parts = value.split(`; ${name}=`);
            if (parts.length === 2) return parts.pop().split(';').shift();
        }

        function connect() {
            socket = new WebSocket("ws://localhost:8080/ws");

            socket.onopen = function(event) {
                console.log('WebSocket connection opened.');
                statusDiv.textContent = 'Connected';
                statusDiv.style.color = 'green';
            };

            socket.onmessage = function(event) {
                let message = document.createElement("li");
                message.textContent = event.data;
                messagesList.appendChild(message);
            };

            socket.onclose = function(event) {
                console.log('WebSocket connection closed.', event.reason);
                statusDiv.textContent = `Disconnected. (Code: ${event.code})`;
                statusDiv.style.color = 'red';
            };

            socket.onerror = function(error) {
                console.error('WebSocket Error:', error);
            };
        }

        function subscribeToChannel() {
            const channel = channelInput.value;
            if (!channel) {
                alert('Please enter a channel name.');
                return;
            }

            if (!socket || socket.readyState !== WebSocket.OPEN) {
                alert('Not connected to the WebSocket server.');
                return;
            }

            const subscribeMsg = {
                action: "subscribe",
                channel: channel
            };
            socket.send(JSON.stringify(subscribeMsg));
            console.log(`Sent subscription request for channel: ${channel}`);
            
            let message = document.createElement("li");
            message.style.color = 'blue';
            message.textContent = `Subscription request sent for channel "${channel}".`;
            messagesList.appendChild(message);
        }

        loginForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const userId = userIdInput.value;
            if (userId) {
                document.cookie = `AUTH_TOKEN=${userId};path=/`;
                window.location.reload();
            }
        });

        logoutBtn.addEventListener('click', () => {
            document.cookie = 'AUTH_TOKEN=;path=/;expires=Thu, 01 Jan 1970 00:00:01 GMT';
            window.location.reload();
        });

        subscribeBtn.addEventListener('click', subscribeToChannel);
        
        const authToken = getCookie('AUTH_TOKEN');
        if (authToken) {
            authStatus.textContent = `Authenticated as ${authToken}`;
            authStatus.style.color = 'green';
            websocketUi.style.display = 'block';
            connect();
        } else {
            authStatus.textContent = 'Not authenticated';
            authStatus.style.color = 'red';
            websocketUi.style.display = 'none';
        }
    </script>
</body>
</html>
```

---

### `app/send.php`

```php
<?php

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $channel = $_POST['channel'] ?? 'default';
    $message = $_POST['message'] ?? 'empty message';

    if (function_exists('broadcast')) {
        broadcast($channel, "($channel) " . $message . " at " . date('H:i:s'));
        $status = "Message sent to channel '{$channel}'.";
    } else {
        $status = "Error: broadcast() function does not exist.";
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Send Message</title>
</head>
<body>
    <h1>Send a WebSocket Message</h1>
    <?php if (isset($status)): ?>
        <p><strong><?= htmlspecialchars($status) ?></strong></p>
    <?php endif; ?>
    <form action="send.php" method="post">
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

### `broadcast/broadcast.go`

```go
package broadcast

import (
	"C"
	"unsafe"

	"github.com/dunglas/frankenphp"
	"github.com/y-l-g/realtime/handler"
)

//export_php:function broadcast(string $channel, string $message): void
func broadcast(channel *C.zend_string, message *C.zend_string) {
	goChannel := frankenphp.GoString(unsafe.Pointer(channel))
	goMessage := []byte(frankenphp.GoString(unsafe.Pointer(message)))
	handler.BroadcastToChannel(goChannel, goMessage)
}
```

### `broadcast/go.mod`

```go
module github.com/y-l-g/realtime/broadcast

go 1.25.0
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
		return true
	},
}

var PubSubHub *Hub

func init() {
	caddy.RegisterModule(GoHandler{})
	httpcaddyfile.RegisterHandlerDirective("go_handler", parseGoHandler)
}

type GoHandler struct {
	Driver       string `json:"driver,omitempty"`
	RedisAddress string `json:"redis_address,omitempty"`
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

	PubSubHub = NewHub(broker)
	go PubSubHub.Run()
	return nil
}

func (h *GoHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	h.Driver = "memory" // Default driver
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "driver":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.Driver = d.Val()
			case "redis_address":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.RedisAddress = d.Val()
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
	authReq, err := http.NewRequest(http.MethodGet, "http://localhost:8080/auth.php", nil)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return err
	}
	if cookie, err := r.Cookie("AUTH_TOKEN"); err == nil {
		authReq.AddCookie(cookie)
	}

	httpClient := &http.Client{}
	resp, err := httpClient.Do(authReq)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return errors.New("authentication failed")
	}

	var authResponse struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&authResponse); err != nil || authResponse.ID == "" {
		http.Error(w, "Invalid auth response", http.StatusInternalServerError)
		return errors.New("invalid auth response")
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return err
	}

	client := &Client{hub: PubSubHub, conn: conn, send: make(chan []byte, 256), UserID: authResponse.ID}
	PubSubHub.register <- client

	go client.writePump()
	client.readPump()

	return nil
}

func BroadcastToChannel(channel string, msg []byte) {
	if PubSubHub == nil || PubSubHub.broker == nil {
		log.Println("error: Hub or broker not initialized")
		return
	}
	err := PubSubHub.broker.Publish(channel, msg)
	if err != nil {
		log.Printf("error publishing message: %v", err)
	}
}

var (
	_ caddy.Module                = (*GoHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*GoHandler)(nil)
	_ caddy.Provisioner           = (*GoHandler)(nil)
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
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/gorilla/websocket"
)

var ctx = context.Background()

// --- Client and Message Definitions ---
const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 512
)
type ClientProtocolMessage struct {
	Action  string `json:"action"`
	Channel string `json:"channel"`
}
type Client struct {
	hub    *Hub
	conn   *websocket.Conn
	send   chan []byte
	UserID string
}
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error { c.conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })
	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("error: %v", err)
			}
			break
		}
		var msg ClientProtocolMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Printf("error decoding client message: %v", err)
			continue
		}
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
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			c.conn.WriteMessage(websocket.TextMessage, message)
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// --- Broker Abstraction ---
type Broker interface {
	Publish(channel string, message []byte) error
	Subscribe() (<-chan *BrokerMessage, error)
	Close() error
}
type BrokerMessage struct {
	Channel string
	Payload []byte
}

// --- MemoryBroker Implementation ---
type MemoryBroker struct {
	broadcast chan *BrokerMessage
}
func NewMemoryBroker() *MemoryBroker {
	return &MemoryBroker{
		broadcast: make(chan *BrokerMessage, 256),
	}
}
func (b *MemoryBroker) Publish(channel string, message []byte) error {
	b.broadcast <- &BrokerMessage{Channel: channel, Payload: message}
	return nil
}
func (b *MemoryBroker) Subscribe() (<-chan *BrokerMessage, error) {
	return b.broadcast, nil
}
func (b *MemoryBroker) Close() error {
	close(b.broadcast)
	return nil
}

// --- RedisBroker Implementation ---
type RedisBroker struct {
	client *redis.Client
}
func NewRedisBroker(address string) *RedisBroker {
	if address == "" {
		address = "localhost:6379"
	}
	return &RedisBroker{
		client: redis.NewClient(&redis.Options{Addr: address}),
	}
}
func (b *RedisBroker) Publish(channel string, message []byte) error {
	return b.client.Publish(ctx, "realtime:"+channel, message).Err()
}
func (b *RedisBroker) Subscribe() (<-chan *BrokerMessage, error) {
	pubsub := b.client.PSubscribe(ctx, "realtime:*")

	if _, err := pubsub.Receive(ctx); err != nil {
		log.Printf("[RedisBroker] Failed to receive subscription confirmation: %v", err)
		return nil, err
	}

	ch := make(chan *BrokerMessage)
	go func() {
		defer close(ch)
		defer pubsub.Close()
		redisCh := pubsub.Channel()
		for msg := range redisCh {
			ch <- &BrokerMessage{
				Channel: msg.Channel[len("realtime:"):],
				Payload: []byte(msg.Payload),
			}
		}
	}()
	return ch, nil
}
func (b *RedisBroker) Close() error {
	return b.client.Close()
}

// --- Hub Implementation ---
type Hub struct {
	mu          sync.RWMutex
	broker      Broker
	channels    map[string]map[*Client]bool
	clients     map[*Client]map[string]bool
	register    chan *Client
	unregister  chan *Client
	subscribe   chan subscription
	unsubscribe chan subscription
}
type subscription struct {
	client  *Client
	channel string
}
func NewHub(broker Broker) *Hub {
	return &Hub{
		broker:      broker,
		register:    make(chan *Client),
		unregister:  make(chan *Client),
		subscribe:   make(chan subscription),
		unsubscribe: make(chan subscription),
		channels:    make(map[string]map[*Client]bool),
		clients:     make(map[*Client]map[string]bool),
	}
}
func (h *Hub) Run() {
	brokerCh, err := h.broker.Subscribe()
	if err != nil {
		log.Fatalf("Failed to subscribe to broker: %v", err)
	}

	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = make(map[string]bool)
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if channels, ok := h.clients[client]; ok {
				for channel := range channels {
					if clientsInChannel, ok := h.channels[channel]; ok {
						delete(clientsInChannel, client)
						if len(clientsInChannel) == 0 {
							delete(h.channels, channel)
						}
					}
				}
				delete(h.clients, client)
			}
			h.mu.Unlock()
			close(client.send)

		case sub := <-h.subscribe:
			h.mu.Lock()
			if _, ok := h.channels[sub.channel]; !ok {
				h.channels[sub.channel] = make(map[*Client]bool)
			}
			h.channels[sub.channel][sub.client] = true
			h.clients[sub.client][sub.channel] = true
			h.mu.Unlock()
			log.Printf("Client %s subscribed to channel %s", sub.client.UserID, sub.channel)

		case sub := <-h.unsubscribe:
			h.mu.Lock()
			if clients, ok := h.channels[sub.channel]; ok {
				delete(clients, sub.client)
				if len(clients) == 0 {
					delete(h.channels, sub.channel)
				}
			}
			if channels, ok := h.clients[sub.client]; ok {
				delete(channels, sub.channel)
			}
			h.mu.Unlock()
			log.Printf("Client %s unsubscribed from channel %s", sub.client.UserID, sub.channel)

		case msg := <-brokerCh:
			h.mu.RLock()
			if clients, ok := h.channels[msg.Channel]; ok {
				for client := range clients {
					select {
					case client.send <- msg.Payload:
					default:
						close(client.send)
						delete(clients, client)
					}
				}
			}
			h.mu.RUnlock()
		}
	}
}