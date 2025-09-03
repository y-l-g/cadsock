package handler

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/gorilla/websocket"
)

var ctx = context.Background()

// --- Client and Message Definitions ---
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

// --- Broker Abstraction ---
type Broker interface {
	Publish(channel string, message []byte) error
	Subscribe() (<-chan *BrokerMessage, error)
	Close() error
}
type BrokerMessage struct {
	Channel string
	Payload []byte
}

// --- MemoryBroker Implementation ---
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

// --- RedisBroker Implementation ---
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

// --- Hub Implementation ---
type Hub struct {
	mu          sync.RWMutex
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
	brokerCh, err := h.broker.Subscribe()
	if err != nil {
		log.Fatalf("Failed to subscribe to broker: %v", err)
	}

	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = make(map[string]bool)
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
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
			h.mu.Unlock()
			close(client.send)

		case sub := <-h.subscribe:
			h.mu.Lock()
			if _, ok := h.channels[sub.channel]; !ok {
				h.channels[sub.channel] = make(map[*Client]bool)
			}
			h.channels[sub.channel][sub.client] = true
			h.clients[sub.client][sub.channel] = true
			h.mu.Unlock()
			log.Printf("Client %s subscribed to channel %s", sub.client.UserID, sub.channel)

		case sub := <-h.unsubscribe:
			h.mu.Lock()
			if clients, ok := h.channels[sub.channel]; ok {
				delete(clients, sub.client)
				if len(clients) == 0 {
					delete(h.channels, sub.channel)
				}
			}
			if channels, ok := h.clients[sub.client]; ok {
				delete(channels, sub.channel)
			}
			h.mu.Unlock()
			log.Printf("Client %s unsubscribed from channel %s", sub.client.UserID, sub.channel)

		case msg := <-brokerCh:
			h.mu.RLock()
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
			h.mu.RUnlock()
		}
	}
}