package handler

import (
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/gorilla/websocket"
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

const (
	writeWait = 10 * time.Second
	pongWait = 60 * time.Second
	pingPeriod = (pongWait * 9) / 10
	maxMessageSize = 512
)

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
				// Le hub a fermé le canal.
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
	mu           sync.RWMutex
	channels     map[string]map[*Client]bool
	broadcast    chan *Message
	register     chan *Client
	unregister   chan *Client
	subscribe    chan subscription
	unsubscribe  chan subscription
}

type subscription struct {
	client  *Client
	channel string
}

func NewHub() *Hub {
	return &Hub{
		broadcast:    make(chan *Message),
		register:     make(chan *Client),
		unregister:   make(chan *Client),
		subscribe:    make(chan subscription),
		unsubscribe:  make(chan subscription),
		channels:     make(map[string]map[*Client]bool),
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
		case client := <-h.unregister:
			h.mu.Lock()
			for channel, clients := range h.channels {
				if _, ok := clients[client]; ok {
					delete(clients, client)
					if len(clients) == 0 {
						delete(h.channels, channel)
					}
				}
			}
			h.mu.Unlock()
			close(client.send)
		case sub := <-h.subscribe:
			h.mu.Lock()
			if _, ok := h.channels[sub.channel]; !ok {
				h.channels[sub.channel] = make(map[*Client]bool)
			}
			h.channels[sub.channel][sub.client] = true
			h.mu.Unlock()
		case sub := <-h.unsubscribe:
			h.mu.Lock()
			if clients, ok := h.channels[sub.channel]; ok {
				delete(clients, sub.client)
				if len(clients) == 0 {
					delete(h.channels, sub.channel)
				}
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
					}
				}
			}
			h.mu.RUnlock()
		}
	}
}

var PubSubHub = NewHub()