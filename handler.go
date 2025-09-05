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
	Driver          string `json:"driver,omitempty"`
	RedisAddress    string `json:"redis_address,omitempty"`
	AuthEndpoint    string `json:"auth_endpoint,omitempty"`
	BroadcastSecret string `json:"broadcast_secret,omitempty"`
	hub             *Hub
	log             *zap.Logger
	httpClient      *http.Client
	ctx             context.Context
	cancel          context.CancelFunc
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
		return h.serveBroadcast(w, r, r.Context())
	default:
		return next.ServeHTTP(w, r)
	}
}

func (h *GoHandler) serveBroadcast(w http.ResponseWriter, r *http.Request, ctx context.Context) error {
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

	err := h.hub.broker.Publish(ctx, channel, []byte(message))
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

	authReq.Header = r.Header.Clone()

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