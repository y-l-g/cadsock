# Project Code Context

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
    go_handler 
}

php_server
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

    <script>
        const channelInput = document.getElementById('channel');
        const subscribeBtn = document.getElementById('subscribe');
        const messagesList = document.getElementById('messages');
        const statusDiv = document.getElementById('connection-status');
        let socket;

        // Établit la connexion WebSocket une seule fois au chargement de la page.
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
                console.log('WebSocket connection closed.');
                statusDiv.textContent = 'Disconnected. Attempting to reconnect in 3 seconds...';
                statusDiv.style.color = 'red';
                setTimeout(connect, 3000);
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

        subscribeBtn.addEventListener('click', subscribeToChannel);

        connect();
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

### `handler/handler.go`

```go
package handler

import (
	"net/http"

	"github.com/caddyserver/caddy/v2"
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

func init() {
	caddy.RegisterModule(GoHandler{})
	httpcaddyfile.RegisterHandlerDirective("go_handler", parseGoHandler)
	go PubSubHub.Run()
}

type GoHandler struct{}

func (GoHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.go_handler",
		New: func() caddy.Module { return new(GoHandler) },
	}
}

func parseGoHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	return new(GoHandler), nil
}

func (h *GoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return err
	}

	client := &Client{hub: PubSubHub, conn: conn, send: make(chan []byte, 256)}
	client.hub.register <- client

	go client.writePump()
	client.readPump()

	return nil
}

func BroadcastToChannel(channel string, msg []byte) {
	message := &Message{
		Channel: channel,
		Data:    msg,
	}
	PubSubHub.broadcast <- message
}

var (
	_ caddy.Module                = (*GoHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*GoHandler)(nil)
)
```

### `handler/hub.go`

```go
package handler

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 512
)

type Message struct {
	Channel string
	Data    []byte
}
type ClientProtocolMessage struct {
	Action  string `json:"action"`
	Channel string `json:"channel"`
}
type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan []byte
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

type Hub struct {
	mu          sync.RWMutex
	channels    map[string]map[*Client]bool
	clients     map[*Client]map[string]bool
	broadcast   chan *Message
	register    chan *Client
	unregister  chan *Client
	subscribe   chan subscription
	unsubscribe chan subscription
}

type subscription struct {
	client  *Client
	channel string
}

func NewHub() *Hub {
	return &Hub{
		broadcast:   make(chan *Message),
		register:    make(chan *Client),
		unregister:  make(chan *Client),
		subscribe:   make(chan subscription),
		unsubscribe: make(chan subscription),
		channels:    make(map[string]map[*Client]bool),
		clients:     make(map[*Client]map[string]bool),
	}
}

func (h *Hub) Run() {
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

		case message := <-h.broadcast:
			h.mu.RLock()
			if clients, ok := h.channels[message.Channel]; ok {
				for client := range clients {
					select {
					case client.send <- message.Data:
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

var PubSubHub = NewHub()
```

### `handler/go.mod`

```go
module github.com/y-l-g/realtime/handler

go 1.25.0

require (
	github.com/gorilla/websocket v1.5.3 // indirect
)
```