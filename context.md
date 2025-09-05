# Project Code Context

## Project Structure

The project is structured as a standalone Caddy module with an accompanying example application.

```
cadsock/
├── go.mod
├── handler.go
├── hub.go
└── examples/
    └── frankenphp-app/
        ├── Caddyfile
        ├── auth.php
        ├── composer.json
        ├── index.php
        ├── login.php
        ├── logout.php
        ├── send.php
        └── send_cli.php
```

---

### `cadsock/go.mod`

```go
module github.com/y-l-g/cadsock

go 1.25.0

require (
	github.com/gorilla/websocket v1.5.3
	github.com/redis/go-redis/v9 v9.5.3
	go.uber.org/zap v1.27.0
)

require (
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	go.uber.org/multierr v1.10.0 // indirect
)
```

---

### `cadsock/handler.go`

```go
package cadsock

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(GoHandler{})
	httpcaddyfile.RegisterHandlerDirective("go_handler", parseGoHandler)
}

type GoHandler struct {
	Driver          string   `json:"driver,omitempty"`
	RedisAddress    string   `json:"redis_address,omitempty"`
	AuthEndpoint    string   `json:"auth_endpoint,omitempty"`
	BroadcastSecret string   `json:"broadcast_secret,omitempty"`
	AllowedOrigins  []string `json:"allowed_origins,omitempty"`
	hub             *Hub
	log             *zap.Logger
	httpClient      *http.Client
	ctx             context.Context
	cancel          context.CancelFunc
	upgrader        websocket.Upgrader
}

func (GoHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.go_handler",
		New: func() caddy.Module { return new(GoHandler) },
	}
}

func (h *GoHandler) Provision(ctx caddy.Context) error {
	h.log = ctx.Logger(h)
	h.httpClient = &http.Client{}
	h.ctx, h.cancel = context.WithCancel(ctx)

	h.upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true
			}
			if len(h.AllowedOrigins) == 0 {
				u, err := url.Parse(origin)
				if err != nil {
					return false
				}
				return u.Host == r.Host
			}
			for _, allowedOrigin := range h.AllowedOrigins {
				if allowedOrigin == origin {
					return true
				}
			}
			h.log.Warn("websocket origin not allowed", zap.String("origin", origin))
			return false
		},
	}

	var broker Broker
	switch h.Driver {
	case "redis":
		h.log.Info("using redis broker", zap.String("address", h.RedisAddress))
		broker = NewRedisBroker(h.RedisAddress)
	default:
		h.log.Info("using in-memory broker")
		broker = NewMemoryBroker()
	}

	h.hub = NewHub(broker, h.log.Named("hub"), h.ctx)
	go h.hub.Run()

	return nil
}

func (h *GoHandler) Cleanup() error {
	h.log.Info("cleaning up handler resources")
	h.cancel()
	h.hub.Shutdown()
	return nil
}

func (h *GoHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	h.Driver = "memory"
	h.AuthEndpoint = "http://localhost:8080/auth.php"

	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
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
			case "auth_endpoint":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.AuthEndpoint = d.Val()
			case "broadcast_secret":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.BroadcastSecret = d.Val()
			case "allowed_origins":
				h.AllowedOrigins = d.RemainingArgs()
				if len(h.AllowedOrigins) == 0 {
					return d.ArgErr()
				}
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
	if h.BroadcastSecret != "" {
		headerSecret := r.Header.Get("X-Broadcast-Secret")
		if subtle.ConstantTimeCompare([]byte(h.BroadcastSecret), []byte(headerSecret)) != 1 {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return errors.New("invalid broadcast secret")
		}
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return errors.New("method not allowed")
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return err
	}
	channel := r.FormValue("channel")
	message := r.FormValue("message")

	if channel == "" || message == "" {
		http.Error(w, "Missing channel or message", http.StatusBadRequest)
		return errors.New("missing channel or message")
	}

	if h.hub == nil || h.hub.broker == nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return errors.New("hub or broker not initialized")
	}

	err := h.hub.broker.Publish(r.Context(), channel, []byte(message))
	if err != nil {
		h.log.Error("error publishing message", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return err
	}

	w.WriteHeader(http.StatusAccepted)
	return nil
}

func (h *GoHandler) serveWs(w http.ResponseWriter, r *http.Request) error {
	authReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, h.AuthEndpoint, nil)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return err
	}

	headersToForward := []string{
		"Authorization",
		"Cookie",
		"User-Agent",
		"X-Forwarded-For",
		"X-Real-IP",
	}
	for _, headerName := range headersToForward {
		if headerValue := r.Header.Get(headerName); headerValue != "" {
			authReq.Header.Set(headerName, headerValue)
		}
	}

	resp, err := h.httpClient.Do(authReq)
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

	conn, err := h.upgrader.Upgrade(w, r, nil)
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

### `cadsock/hub.go`

```go
package cadsock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 512
)

const (
	ActionSubscribe   = "subscribe"
	ActionUnsubscribe = "unsubscribe"
)

const (
	TypeMessage      = "message"
	TypeSubscribed   = "subscribed"
	TypeUnsubscribed = "unsubscribed"
	TypeError        = "error"
)

type WebsocketConnection interface {
	SetReadLimit(limit int64)
	SetReadDeadline(t time.Time) error
	SetPongHandler(h func(appData string) error)
	ReadMessage() (messageType int, p []byte, err error)
	SetWriteDeadline(t time.Time) error
	WriteMessage(messageType int, data []byte) error
	Close() error
}

type ClientProtocolMessage struct {
	Action  string `json:"action"`
	Channel string `json:"channel"`
}

type ServerProtocolMessage struct {
	Type    string          `json:"type"`
	Channel string          `json:"channel,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   string          `json:"error,omitempty"`
}

type Client struct {
	hub    *Hub
	conn   WebsocketConnection
	send   chan []byte
	UserID string
}

func (c *Client) sendErrorMessage(errMsg string) {
	msg, err := json.Marshal(ServerProtocolMessage{
		Type:  TypeError,
		Error: errMsg,
	})
	if err != nil {
		c.hub.log.Error("failed to marshal error message", zap.Error(err))
		return
	}
	select {
	case c.send <- msg:
	default:
		c.hub.log.Warn("client send buffer full, could not send error message", zap.String("user_id", c.UserID))
	}
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
				c.hub.log.Debug("websocket closed unexpectedly", zap.Error(err))
			}
			break
		}
		var msg ClientProtocolMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			c.hub.log.Warn("could not decode client message", zap.Error(err))
			c.sendErrorMessage("invalid JSON message")
			continue
		}

		if msg.Channel == "" {
			c.sendErrorMessage("channel must be specified")
			continue
		}

		switch msg.Action {
		case ActionSubscribe:
			c.hub.subscribe <- subscription{client: c, channel: msg.Channel}
		case ActionUnsubscribe:
			c.hub.unsubscribe <- subscription{client: c, channel: msg.Channel}
		default:
			c.hub.log.Warn("unknown client action", zap.String("action", msg.Action))
			c.sendErrorMessage(fmt.Sprintf("unknown action: %s", msg.Action))
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

type Broker interface {
	Publish(ctx context.Context, channel string, message []byte) error
	Subscribe(ctx context.Context) (<-chan *BrokerMessage, error)
	Close() error
}

type BrokerMessage struct {
	Channel string
	Payload []byte
}

type MemoryBroker struct {
	broadcast chan *BrokerMessage
}

func NewMemoryBroker() *MemoryBroker {
	return &MemoryBroker{
		broadcast: make(chan *BrokerMessage, 256),
	}
}

func (b *MemoryBroker) Publish(ctx context.Context, channel string, message []byte) error {
	select {
	case b.broadcast <- &BrokerMessage{Channel: channel, Payload: message}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return errors.New("memory broker channel is full")
	}
}

func (b *MemoryBroker) Subscribe(ctx context.Context) (<-chan *BrokerMessage, error) {
	return b.broadcast, nil
}

func (b *MemoryBroker) Close() error {
	close(b.broadcast)
	return nil
}

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

func (b *RedisBroker) Publish(ctx context.Context, channel string, message []byte) error {
	return b.client.Publish(ctx, "realtime:"+channel, message).Err()
}

func (b *RedisBroker) Subscribe(ctx context.Context) (<-chan *BrokerMessage, error) {
	pubsub := b.client.PSubscribe(ctx, "realtime:*")
	if _, err := pubsub.Receive(ctx); err != nil {
		return nil, err
	}

	ch := make(chan *BrokerMessage)
	go func() {
		defer close(ch)
		defer pubsub.Close()
		redisCh := pubsub.Channel()
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-redisCh:
				if !ok {
					return
				}
				ch <- &BrokerMessage{
					Channel: msg.Channel[len("realtime:"):],
					Payload: []byte(msg.Payload),
				}
			}
		}
	}()
	return ch, nil
}

func (b *RedisBroker) Close() error {
	return b.client.Close()
}

type Hub struct {
	broker      Broker
	channels    map[string]map[*Client]bool
	clients     map[*Client]map[string]bool
	register    chan *Client
	unregister  chan *Client
	subscribe   chan subscription
	unsubscribe chan subscription
	shutdown    chan struct{}
	log         *zap.Logger
	ctx         context.Context
}

type subscription struct {
	client  *Client
	channel string
}

func NewHub(broker Broker, log *zap.Logger, ctx context.Context) *Hub {
	return &Hub{
		broker:      broker,
		register:    make(chan *Client),
		unregister:  make(chan *Client),
		subscribe:   make(chan subscription),
		unsubscribe: make(chan subscription),
		channels:    make(map[string]map[*Client]bool),
		clients:     make(map[*Client]map[string]bool),
		shutdown:    make(chan struct{}),
		log:         log,
		ctx:         ctx,
	}
}

func (h *Hub) Shutdown() {
	close(h.shutdown)
}

func (h *Hub) Run() {
	go h.runLoop()
}

func (h *Hub) runLoop() {
	defer func() {
		h.log.Info("hub shutdown complete")
		h.broker.Close()
		for client := range h.clients {
			close(client.send)
		}
	}()

	for {
		select {
		case <-h.ctx.Done():
			h.log.Info("hub context cancelled, shutting down")
			return
		case <-h.shutdown:
			h.log.Info("hub received shutdown signal, shutting down")
			return
		default:
			err := h.processMessages()
			if err != nil {
				if err == context.Canceled || err == context.DeadlineExceeded {
					return
				}
				h.log.Error("hub message processing loop failed, restarting", zap.Error(err))
				time.Sleep(2 * time.Second)
			}
		}
	}
}

func (h *Hub) processMessages() error {
	const maxBackoff = 30 * time.Second
	nextBackoff := 1 * time.Second
	var brokerCh <-chan *BrokerMessage
	var err error

	for {
		select {
		case <-h.ctx.Done():
			return h.ctx.Err()
		case <-h.shutdown:
			return nil
		default:
		}

		brokerCh, err = h.broker.Subscribe(h.ctx)
		if err == nil {
			h.log.Info("successfully subscribed to broker")
			break
		}
		h.log.Error("failed to subscribe to broker, retrying",
			zap.Duration("retry_in", nextBackoff),
			zap.Error(err),
		)

		select {
		case <-h.ctx.Done():
			return h.ctx.Err()
		case <-h.shutdown:
			return nil
		case <-time.After(nextBackoff):
			nextBackoff *= 2
			if nextBackoff > maxBackoff {
				nextBackoff = maxBackoff
			}
		}
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
						if len(clientsInChannel) == 0 {
							delete(h.channels, channel)
						}
					}
				}
				delete(h.clients, client)
			}
			close(client.send)

		case sub := <-h.subscribe:
			if _, ok := h.channels[sub.channel]; !ok {
				h.channels[sub.channel] = make(map[*Client]bool)
			}
			h.channels[sub.channel][sub.client] = true
			h.clients[sub.client][sub.channel] = true
			h.log.Info("client subscribed",
				zap.String("user_id", sub.client.UserID),
				zap.String("channel", sub.channel),
			)

			response, _ := json.Marshal(ServerProtocolMessage{Type: TypeSubscribed, Channel: sub.channel})
			sub.client.send <- response

		case sub := <-h.unsubscribe:
			if clients, ok := h.channels[sub.channel]; ok {
				delete(clients, sub.client)
				if len(clients) == 0 {
					delete(h.channels, sub.channel)
				}
			}
			if channels, ok := h.clients[sub.client]; ok {
				delete(channels, sub.channel)
			}
			h.log.Info("client unsubscribed",
				zap.String("user_id", sub.client.UserID),
				zap.String("channel", sub.channel),
			)
			response, _ := json.Marshal(ServerProtocolMessage{Type: TypeUnsubscribed, Channel: sub.channel})
			sub.client.send <- response

		case msg, ok := <-brokerCh:
			if !ok {
				h.log.Warn("broker channel closed, attempting to reconnect")
				return nil
			}
			wrappedMsg, err := json.Marshal(ServerProtocolMessage{
				Type:    TypeMessage,
				Channel: msg.Channel,
				Payload: msg.Payload,
			})
			if err != nil {
				h.log.Error("failed to marshal broadcast message", zap.Error(err))
				continue
			}
			if clients, ok := h.channels[msg.Channel]; ok {
				for client := range clients {
					select {
					case client.send <- wrappedMsg:
					default:
						h.log.Warn("client send buffer full, disconnecting",
							zap.String("user_id", client.UserID),
							zap.String("channel", msg.Channel),
						)
						close(client.send)
						delete(clients, client)
					}
				}
			}

		case <-h.shutdown:
			return nil

		case <-h.ctx.Done():
			return h.ctx.Err()
		}
	}
}
```

---

### `examples/frankenphp-app/Caddyfile`

```caddyfile
{
	frankenphp
	order go_handler before file_server
}

:8080

@go_paths path /ws /internal/broadcast

handle @go_paths {
	go_handler {
		broadcast_secret "a-very-strong-and-secret-key-for-broadcast"
		
		# Add all the origins you want to allow here.
		# For example, for a React development server on port 3000:
		# allowed_origins http://localhost:8080 http://localhost:3000
		allowed_origins http://localhost:8080

		# driver redis
		# redis_address localhost:6379
		# auth_endpoint http://localhost:8080/auth.php
	}
}

php_server
```

---

### `examples/frankenphp-app/auth.php`

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

$secretKey = getenv('JWT_SECRET_KEY');
if (empty($secretKey)) {
    error_log('JWT_SECRET_KEY environment variable not set');
    http_response_code(500);
    echo json_encode(['error' => 'Server configuration error']);
    exit;
}

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

### `examples/frankenphp-app/index.php`

```php
<?php
$isAuthenticated = isset($_COOKIE['AUTH_TOKEN']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WebSocket Test</title>
    <style>
        .msg-system { color: blue; font-style: italic; }
        .msg-error { color: red; font-weight: bold; }
    </style>
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
        let reconnectInterval;
        let reconnectAttempts = 0;

        function connect() {
            // Prevent multiple parallel connection attempts
            if (socket && socket.readyState === WebSocket.OPEN) {
                console.log('WebSocket is already connected.');
                return;
            }

            socket = new WebSocket("ws://localhost:8080/ws");

            socket.onopen = function(event) {
                console.log('WebSocket connection opened.');
                statusDiv.textContent = 'Connected';
                statusDiv.style.color = 'green';
                // Reset reconnect attempts on successful connection
                reconnectAttempts = 0;
                if (reconnectInterval) {
                    clearInterval(reconnectInterval);
                    reconnectInterval = null;
                }
            };

            socket.onmessage = function(event) {
                const messageData = JSON.parse(event.data);
                let li = document.createElement("li");

                switch (messageData.type) {
                    case 'message':
                        // The payload can be any JSON value, we stringify it for display.
                        li.textContent = `(Channel: ${messageData.channel}) Payload: ${JSON.stringify(JSON.parse(messageData.payload))}`;
                        break;
                    case 'subscribed':
                        li.textContent = `Successfully subscribed to channel "${messageData.channel}".`;
                        li.className = 'msg-system';
                        break;
                    case 'unsubscribed':
                         li.textContent = `Successfully unsubscribed from channel "${messageData.channel}".`;
                        li.className = 'msg-system';
                        break;
                     case 'error':
                        li.textContent = `Server Error: ${messageData.error}`;
                        li.className = 'msg-error';
                        break;
                    default:
                        li.textContent = `Unknown message type: ${event.data}`;
                        break;
                }
                messagesList.appendChild(li);
            };

            socket.onclose = function(event) {
                console.log('WebSocket connection closed.', event.reason);
                statusDiv.textContent = `Disconnected. (Code: ${event.code})`;
                statusDiv.style.color = 'red';
                // Attempt to reconnect if the closure was unexpected
                if (event.code !== 1000) { // 1000 is normal closure
                    scheduleReconnect();
                }
            };

            socket.onerror = function(error) {
                console.error('WebSocket Error:', error);
                // An error will likely be followed by a close event, which will trigger reconnection.
            };
        }

        function scheduleReconnect() {
            if (reconnectInterval) return; // Reconnect already scheduled

            reconnectAttempts++;
            // Exponential backoff: 2s, 4s, 8s, 16s, max 30s
            const delay = Math.min(30000, Math.pow(2, reconnectAttempts) * 1000);

            statusDiv.textContent += ` Reconnecting in ${delay / 1000}s...`;
            console.log(`Scheduling reconnect attempt ${reconnectAttempts} in ${delay}ms`);

            reconnectInterval = setTimeout(() => {
                reconnectInterval = null; // Clear the timer ID before attempting to connect
                connect();
            }, delay);
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
        }

        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const userId = userIdInput.value;
            if (!userId) return;

            try {
                const response = await fetch('/login.php', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ userId: userId })
                });

                if (response.ok) {
                    window.location.reload();
                } else {
                    alert('Login failed.');
                }
            } catch (error) {
                console.error('Login request failed:', error);
                alert('Login request failed.');
            }
        });

        logoutBtn.addEventListener('click', async () => {
            try {
                const response = await fetch('/logout.php', { method: 'POST' });
                if (response.ok) {
                    window.location.reload();
                } else {
                    alert('Logout failed.');
                }
            } catch (error) {
                console.error('Logout request failed:', error);
                alert('Logout request failed.');
            }
        });

        subscribeBtn.addEventListener('click', subscribeToChannel);
        
        if (isAuthenticated) {
            connect();
        }
    </script>
</body>
</html>
```

---

### `examples/frankenphp-app/send.php`

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

/**
 * Broadcasts a message to the cadsock server using cURL.
 *
 * @param string $channel The channel to publish to.
 * @param string $message The JSON-encoded message payload.
 * @return bool True on success (2xx status code), false on failure.
 */
function broadcast(string $channel, string $message): bool
{
    $secret = getenv('BROADCAST_SECRET_KEY');
    if (empty($secret)) {
        error_log('BROADCAST_SECRET_KEY environment variable not set');
        return false;
    }
    
    $url = 'http://localhost:8080/internal/broadcast';
    $postData = http_build_query([
        'channel' => $channel,
        'message' => $message,
    ]);

    $headers = [
        "X-Broadcast-Secret: " . $secret,
    ];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);

    $response = curl_exec($ch);
    
    if (curl_errno($ch)) {
        error_log('cURL error broadcasting message: ' . curl_error($ch));
        curl_close($ch);
        return false;
    }

    $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($statusCode < 200 || $statusCode >= 300) {
        error_log("Broadcast failed with status code: {$statusCode}. Response: " . $response);
        return false;
    }

    return true;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !validate_csrf_token($_POST['csrf_token'])) {
        http_response_code(403);
        $status = "Error: Invalid CSRF token.";
    } else {
        $channel = $_POST['channel'] ?? 'default';
        $message = $_POST['message'] ?? 'empty message';

        $fullMessage = "($channel) " . $message . " at " . date('H:i:s');
        
        if (broadcast($channel, json_encode($fullMessage))) {
            $status = "Message sent to channel '{$channel}'.";
        } else {
            http_response_code(500);
            $status = "Error: Failed to broadcast message.";
        }
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
    <?php if (isset($status)): ?>
        <p><strong><?= htmlspecialchars($status) ?></strong></p>
    <?php endif; ?>
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

### `examples/frankenphp-app/send_cli.php`

```php
<?php

// A command-line script to demonstrate server-to-server broadcasting.
// Usage: php examples/frankenphp-app/send_cli.php "my channel" "My message from the backend"

if (php_sapi_name() !== 'cli') {
    die("This script can only be run from the command line.");
}

// Load environment variables if a .env file exists (useful for local dev)
if (file_exists(__DIR__ . '/.env')) {
    $lines = file(__DIR__ . '/.env', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0) continue;
        list($name, $value) = explode('=', $line, 2);
        $_ENV[$name] = $value;
        $_SERVER[$name] = $value;
        putenv("$name=$value");
    }
}

/**
 * Broadcasts a message to the cadsock server using cURL.
 *
 * @param string $channel The channel to publish to.
 * @param string $message The JSON-encoded message payload.
 * @return bool True on success (2xx status code), false on failure.
 */
function broadcast(string $channel, string $message): bool
{
    $secret = getenv('BROADCAST_SECRET_KEY');
    if (empty($secret)) {
        error_log('BROADCAST_SECRET_KEY environment variable not set');
        return false;
    }
    
    $url = 'http://localhost:8080/internal/broadcast';
    $postData = http_build_query([
        'channel' => $channel,
        'message' => $message,
    ]);

    $headers = [
        "X-Broadcast-Secret: " . $secret,
    ];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_VERBOSE, false); // Set to true for debugging

    $response = curl_exec($ch);
    
    if (curl_errno($ch)) {
        error_log('cURL error broadcasting message: ' . curl_error($ch));
        curl_close($ch);
        return false;
    }

    $statusCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($statusCode < 200 || $statusCode >= 300) {
        error_log("Broadcast failed with status code: {$statusCode}. Response: " . $response);
        return false;
    }

    return true;
}


$channel = $argv[1] ?? 'default';
$messageBody = $argv[2] ?? 'A message from the CLI script at ' . date('H:i:s');
$payload = json_encode("CLI: " . $messageBody);

echo "Attempting to broadcast to channel '{$channel}'...\n";

if (broadcast($channel, $payload)) {
    echo "Message sent successfully.\n";
} else {
    echo "Failed to send message. Check server logs for details.\n";
    exit(1);
}
```