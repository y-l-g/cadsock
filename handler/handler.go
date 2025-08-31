package handler

import (
	"context"
	"net/http"
	"sync"

	"github.comcom/caddyserver/caddy/v2"
	"github.comcom/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.comcom/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.comcom/caddyserver/caddy/v2/modules/caddyhttp"
	"github.comcom/gorilla/websocket"
	"go.uber.org/zap"
)

var (
	Clients   = make(map[*websocket.Conn]bool)
	ClientsMu sync.Mutex
)

func init() {
	caddy.RegisterModule(GoHandler{})
	httpcaddyfile.RegisterHandlerDirective("go_handler", parseGoHandler)
}

type GoHandler struct {
	Origins []string `json:"origins,omitempty"`

	// Le logger sera initialisé par Caddy.
	log *zap.Logger
}

func (GoHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.go_handler",
		New: func() caddy.Module { return new(GoHandler) },
	}
}

// Provision est appelée par Caddy après le parsing pour finaliser la configuration.
// C'est le bon endroit pour obtenir un logger.
func (h *GoHandler) Provision(ctx caddy.Context) error {
	h.log = ctx.Logger() // Obtient un logger préfixé pour notre module.
	h.log.Info("handler provisioned", zap.Strings("allowed_origins", h.Origins))
	return nil
}

func (h *GoHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "origins":
				h.Origins = d.RemainingArgs()
				if len(h.Origins) == 0 {
					return d.ArgErr()
				}
			default:
				return d.Errf("unknown subdirective '%s'", d.Val())
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
	h.log.Info("ServeHTTP called", zap.Strings("configured_origins", h.Origins))

	var upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			h.log.Info("CheckOrigin called", zap.String("request_origin", origin))

			for _, allowedOrigin := range h.Origins {
				if origin == allowedOrigin {
					h.log.Info("origin is allowed", zap.String("origin", origin))
					return true
				}
			}
			
			h.log.Warn("origin is NOT allowed", zap.String("origin", origin))
			return false
		},
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.log.Error("failed to upgrade connection", zap.Error(err))
		return nil
	}
	defer conn.Close()

	ClientsMu.Lock()
	Clients[conn] = true
	ClientsMu.Unlock()

	defer func() {
		ClientsMu.Lock()
		delete(Clients, conn)
		ClientsMu.Unlock()
	}()

	for {
		if _, _, err := conn.NextReader(); err != nil {
			break
		}
	}
	
	return nil
}

func BroadcastMessage(msg []byte) {
	ClientsMu.Lock()
	defer ClientsMu.Unlock()

	for client := range Clients {
		err := client.WriteMessage(websocket.TextMessage, msg)
		if err != nil {
			// On pourrait vouloir un logger ici aussi, mais restons simple pour l'instant.
			client.Close()
			delete(Clients, client)
		}
	}
}

var (
	_ caddy.Module                = (*GoHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*GoHandler)(nil)
	_ caddyfile.Unmarshaler       = (*GoHandler)(nil)
	_ caddy.Provisioner           = (*GoHandler)(nil) // On implémente maintenant Provisioner.
)