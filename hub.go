package cadsock

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()

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

type Broker interface {
	Publish(channel string, message []byte) error
	Subscribe() (<-chan *BrokerMessage, error)
	Close() error
}

type BrokerMessage struct {
	Channel string
	Payload []byte
}

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

type Hub struct {
	broker      Broker
	channels    map[string]map[*Client]bool
	clients     map[*Client]map[string]bool
	register    chan *Client
	unregister  chan *Client
	subscribe   chan subscription
	unsubscribe chan subscription
	shutdown    chan struct{}
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
		shutdown:    make(chan struct{}),
	}
}

func (h *Hub) Shutdown() {
	close(h.shutdown)
}

func (h *Hub) Run() {
	var brokerCh <-chan *BrokerMessage
	var err error

	for {
		brokerCh, err = h.broker.Subscribe()
		if err == nil {
			log.Println("Successfully subscribed to broker")
			break
		}
		log.Printf("Failed to subscribe to broker, retrying in 5 seconds: %v", err)
		time.Sleep(5 * time.Second)
	}

	for {
		select {
		case client := <-h.register:
			h.clients[client] = make(map[string]bool)

		case client := <-h.unregister:
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
			close(client.send)

		case sub := <-h.subscribe:
			if _, ok := h.channels[sub.channel]; !ok {
				h.channels[sub.channel] = make(map[*Client]bool)
			}
			h.channels[sub.channel][sub.client] = true
			h.clients[sub.client][sub.channel] = true
			log.Printf("Client %s subscribed to channel %s", sub.client.UserID, sub.channel)

		case sub := <-h.unsubscribe:
			if clients, ok := h.channels[sub.channel]; ok {
				delete(clients, sub.client)
				if len(clients) == 0 {
					delete(h.channels, sub.channel)
				}
			}
			if channels, ok := h.clients[sub.client]; ok {
				delete(channels, sub.channel)
			}
			log.Printf("Client %s unsubscribed from channel %s", sub.client.UserID, sub.channel)

		case msg := <-brokerCh:
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
		
		case <-h.shutdown:
			log.Println("Hub received shutdown signal. Closing client connections.")
			for client := range h.clients {
				close(client.send)
			}
			h.broker.Close()
			log.Println("Hub shutdown complete.")
			return
		}
	}
}