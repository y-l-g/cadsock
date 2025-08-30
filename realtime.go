package main

import (
	"C"
	"github.com/dunglas/frankenphp"
	"github.com/gorilla/websocket"
	"log"
	"net/http"
	"sync"
	"unsafe"
)

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
		http.HandleFunc("/ws", handleConnections)
		log.Println("Serveur WebSocket démarréee une seule fois sur :8081")
		go func() {
			if err := http.ListenAndServe(":8081", nil); err != nil {
				log.Printf("Erreur du serveur WebSocket: %v", err)
			}
		}()
	})
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.lock.Lock()
			h.clients[client] = true
			h.lock.Unlock()
		case client := <-h.unregister:
			h.lock.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				client.Close()
			}
			h.lock.Unlock()
		case message := <-h.broadcast:
			h.lock.RLock()
			for client := range h.clients {
				client.WriteMessage(websocket.TextMessage, message)
			}
			h.lock.RUnlock()
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
		if _, _, err := ws.ReadMessage(); err != nil {
			hub.unregister <- ws
			break
		}
	}
}

//export_php:namespace Realtime

//export_php:function start(): void
func start() {
	getHubAndStartServer()
}
//export_php:function broadcast(string $message): void
func broadcast(message *C.zend_string) {
	getHubAndStartServer()
	goMessage := frankenphp.GoString(unsafe.Pointer(message))
	if hub != nil {
		hub.broadcast <- []byte(goMessage)
	}
}