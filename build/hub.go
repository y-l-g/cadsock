package hub

/*
#include <stdlib.h>
#include "hub.h"
*/
import "C"
import "log"
import "net/http"
import "sync"
import "unsafe"
import "github.com/caddyserver/caddy/v2"
import "github.com/caddyserver/caddy/v2/modules/caddyhttp"
import "github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
import "github.com/dunglas/frankenphp"
import "github.com/gorilla/websocket"

func init() {
	frankenphp.RegisterExtension(unsafe.Pointer(&C.hub_module_entry))
}


var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	clients   = make(map[*websocket.Conn]bool)
	clientsMu sync.Mutex
)
var (
	_ caddy.Module                = (*GoHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*GoHandler)(nil)
)


func init() {
	caddy.RegisterModule(GoHandler{})
	httpcaddyfile.RegisterHandlerDirective("go_handler", parseGoHandler)
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
	HandleWebSocket(w, r)
	return nil
}
func HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade:", err)
		return
	}
	defer conn.Close()

	clientsMu.Lock()
	clients[conn] = true
	clientsMu.Unlock()

	defer func() {
		clientsMu.Lock()
		delete(clients, conn)
		clientsMu.Unlock()
	}()

	for {
		if _, _, err := conn.NextReader(); err != nil {
			break
		}
	}
}
func main() {}
//export broadcast
func broadcast(message *C.zend_string) {
	msg := frankenphp.GoString(unsafe.Pointer(message))
	clientsMu.Lock()
	defer clientsMu.Unlock()

	for client := range clients {
		err := client.WriteMessage(websocket.TextMessage, []byte(msg))
		if err != nil {
			client.Close()
			delete(clients, client)
		}
	}
}

