package main

import (
	"github.com/gorilla/websocket"
	"log"
	"net/http"
	"sync"
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	hub  *Hub
	once sync.Once
)

type Hub struct {
	clients    map[*websocket.Conn]bool
	broadcast  chan []byte
	register   chan *websocket.Conn
	unregister chan *websocket.Conn
	lock       sync.RWMutex
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
	})
	return hub
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.lock.Lock()
			h.clients[client] = true
			h.lock.Unlock()
			log.Println("Client connecté")
		case client := <-h.unregister:
			h.lock.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				client.Close()
				log.Println("Client déconnecté")
			}
			h.lock.Unlock()
		case message := <-h.broadcast:
			h.lock.RLock()
			for client := range h.clients {
				if err := client.WriteMessage(websocket.TextMessage, message); err != nil {
					log.Printf("Erreur d'écriture: %v", err)
					h.unregister <- client
				}
			}
			h.lock.RUnlock()
		}
	}
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer ws.Close()
	hub := getHub()
	hub.register <- ws
	for {
		if _, _, err := ws.ReadMessage(); err != nil {
			hub.unregister <- ws
			break
		}
	}
}

func startServer() {
	http.HandleFunc("/ws", handleConnections)
	log.Println("Serveur WebSocket démarré sur :8081")
	go func() {
		if err := http.ListenAndServe(":8081", nil); err != nil {
			log.Printf("Erreur du serveur WebSocket: %v", err)
		}
	}()
}