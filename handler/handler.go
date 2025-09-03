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
		// This handles the case of `go_handler` without a block.
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
			// To prevent `go_handler some_arg`
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