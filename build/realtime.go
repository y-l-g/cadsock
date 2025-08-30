package realtime

/*
#include <stdlib.h>
#include "realtime.h"
*/
import "C"
import "github.com/dunglas/frankenphp"
import "github.com/gorilla/websocket"
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


func getHubAndStartServer() {
	once.Do(func() {
		hub = &Hub{
			clients:    make(map[*websocket.Conn]bool),
			broadcast:  make(chan []byte),
			register:   make(chan *websocket.Conn),
			unregister: make(chan *websocket.Conn),
		}
		go hub.run()

		// On lance un serveur HTTP standard sur le port 8081
		http.HandleFunc("/ws", handleConnections)
		log.Println("--- SERVEUR WEBSOCKET SUR LE POINT DE DÉMARRER SUR :8081 ---")
		go func() {
			if err := http.ListenAndServe(":8081", nil); err != nil {
				log.Printf("ERREUR SERVEUR WEBSOCKET: %v", err)
			}
		}()
	})
}
func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.lock.Lock(); h.clients[client] = true; h.lock.Unlock(); log.Println("--- CLIENT CONNECTÉ ---")
		case client := <-h.unregister:
			h.lock.Lock(); if _, ok := h.clients[client]; ok { delete(h.clients, client); client.Close() }; h.lock.Unlock()
		case message := <-h.broadcast:
			h.lock.RLock(); for client := range h.clients { client.WriteMessage(websocket.TextMessage, message) }; h.lock.RUnlock()
		}
	}
}
func handleConnections(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil { return }
	defer ws.Close()
	hub.register <- ws
	for {
		if _, _, err := ws.ReadMessage(); err != nil { hub.unregister <- ws; break }
	}
}
//export start
func start() { getHubAndStartServer() }
//export_php:function broadcast(string $message): void
func broadcast(message *C.zend_string) {
	getHubAndStartServer() // Assure que le hub est démarré
	goMessage := frankenphp.GoString(unsafe.Pointer(message))
	if hub != nil { hub.broadcast <- []byte(goMessage) }
}

