package realtime

/*
#include <stdlib.h>
#include "realtime.h"
*/
import "C"
import "github.com/caddyserver/caddy/v2"
import "github.com/caddyserver/caddy/v2/modules/caddyhttp"
import "github.com/dunglas/frankenphp"
import "github.comcom/gorilla/websocket"
import "log"
import "net/http"
import "sync"
import "unsafe"

func init() {
	frankenphp.RegisterExtension(unsafe.Pointer(&C.realtime_module_entry))
}

type Hub struct {
	clients    map[*websocket.Conn]bool
	broadcast  chan []byte
	register   chan *websocket.Conn
	unregister chan *websocket.Conn
	lock       sync.RWMutex
}

var hub *Hub
var once sync.Once


func init() {
	caddy.RegisterModule(FrankenRelay{})
}
func getHub() *Hub {
	once.Do(func() {
		hub = &Hub{
			clients:    make(map[*websocket.Conn]bool),
			broadcast:  make(chan []byte),
			register:   make(chan *websocket.Conn),
			unregister: make(chan *websocket.Conn),
		}
		go hub.run()
		log.Println("--- Hub Temps-Réel Démarré (une seule fois) ---")
	})
	return hub
}
func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.lock.Lock(); h.clients[client] = true; h.lock.Unlock(); log.Println("--- Client WebSocket Connecté ---")
		case client := <-h.unregister:
			h.lock.Lock(); if _, ok := h.clients[client]; ok { delete(h.clients, client); client.Close() }; h.lock.Unlock()
		case message := <-h.broadcast:
			h.lock.RLock(); for client := range h.clients { client.WriteMessage(websocket.TextMessage, message) }; h.lock.RUnlock()
		}
	}
}

type FrankenRelay struct{}

func (FrankenRelay) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{ID: "http.handlers.franken_relay", New: func() caddy.Module { return new(FrankenRelay) }}
}
func (m FrankenRelay) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil { return err }
	defer ws.Close()
	hub := getHub()
	hub.register <- ws
	for {
		if _, _, err := ws.ReadMessage(); err != nil { hub.unregister <- ws; break }
	}
	return nil
}
//export broadcast
func broadcast(message *C.zend_string) {
	hub := getHub()
	goMessage := frankenphp.GoString(unsafe.Pointer(message))
	if hub != nil { hub.broadcast <- []byte(goMessage) }
}

