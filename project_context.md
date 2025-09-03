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
    
    go_handler {
        # Par défaut, le driver "memory" est utilisé.
        # Pour activer Redis pour le scaling horizontal, décommentez les lignes suivantes.
        # driver redis
        # redis_address localhost:6379

        # (Optionnel) Spécifiez un endpoint d'authentification interne différent.
        # La valeur par défaut est "http://localhost:8080/auth.php".
        # auth_endpoint http://localhost:8080/api/auth
    }
}

# Le serveur PHP gère l'interface web et le endpoint interne /auth.php
php_server
```

---

### `app/auth.php`

```php
<?php

header('Content-Type: application/json');

// Ceci est une logique d'authentification factice.
// Dans une application réelle, vous valideriez un cookie de session ou un token JWT
// auprès de votre base de données ou de votre gestionnaire de session.
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

*(Inchangé)*

---

### `app/send.php`

*(Inchangé)*

---

### `broadcast/broadcast.go`

*(Inchangé)*

---

### `broadcast/go.mod`

*(Inchangé)*

---

### `handler/go.mod`

*(Inchangé)*

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
	AuthEndpoint string `json:"auth_endpoint,omitempty"`
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
	h.Driver = "memory"
	h.AuthEndpoint = "http://localhost:8080/auth.php"

	for d.Next() {
		if !d.NextArg() {
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
				}
			}
		} else {
			return d.ArgErr()
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
	authReq, err := http.NewRequest(http.MethodGet, h.AuthEndpoint, nil)
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
	"time"

	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()

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

type Broker interface {
	Publish(channel string, message []byte) error
	Subscribe() (<-chan *BrokerMessage, error)
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

type Hub struct {
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
	var brokerCh <-chan *BrokerMessage
	var err error

	for {
		brokerCh, err = h.broker.Subscribe()
		if err == nil {
			log.Println("Successfully subscribed to broker")
			break
		}
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
			log.Printf("Client %s subscribed to channel %s", sub.client.UserID, sub.channel)

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
			log.Printf("Client %s unsubscribed from channel %s", sub.client.UserID, sub.channel)

		case msg := <-brokerCh:
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
		}
	}
}
