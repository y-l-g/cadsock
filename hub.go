package cadsock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 512
)

const (
	ActionSubscribe   = "subscribe"
	ActionUnsubscribe = "unsubscribe"
)

const (
	TypeMessage      = "message"
	TypeSubscribed   = "subscribed"
	TypeUnsubscribed = "unsubscribed"
	TypeError        = "error"
)

type WebsocketConnection interface {
	SetReadLimit(limit int64)
	SetReadDeadline(t time.Time) error
	SetPongHandler(h func(appData string) error)
	ReadMessage() (messageType int, p []byte, err error)
	SetWriteDeadline(t time.Time) error
	WriteMessage(messageType int, data []byte) error
	Close() error
}

type ClientProtocolMessage struct {
	Action  string `json:"action"`
	Channel string `json:"channel"`
}

type ServerProtocolMessage struct {
	Type    string          `json:"type"`
	Channel string          `json:"channel,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   string          `json:"error,omitempty"`
}

type Client struct {
	hub    *Hub
	conn   WebsocketConnection
	send   chan []byte
	UserID string
}

func (c *Client) sendErrorMessage(errMsg string) {
	msg, err := json.Marshal(ServerProtocolMessage{
		Type:  TypeError,
		Error: errMsg,
	})
	if err != nil {
		c.hub.log.Error("failed to marshal error message", zap.Error(err))
		return
	}
	select {
	case c.send <- msg:
	default:
		c.hub.log.Warn("client send buffer full, could not send error message", zap.String("user_id", c.UserID))
	}
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
				c.hub.log.Debug("websocket closed unexpectedly", zap.Error(err))
			}
			break
		}
		var msg ClientProtocolMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			c.hub.log.Warn("could not decode client message", zap.Error(err))
			c.sendErrorMessage("invalid JSON message")
			continue
		}

		if msg.Channel == "" {
			c.sendErrorMessage("channel must be specified")
			continue
		}

		switch msg.Action {
		case ActionSubscribe:
			c.hub.subscribe <- subscription{client: c, channel: msg.Channel}
		case ActionUnsubscribe:
			c.hub.unsubscribe <- subscription{client: c, channel: msg.Channel}
		default:
			c.hub.log.Warn("unknown client action", zap.String("action", msg.Action))
			c.sendErrorMessage(fmt.Sprintf("unknown action: %s", msg.Action))
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
	Publish(ctx context.Context, channel string, message []byte) error
	Subscribe(ctx context.Context) (<-chan *BrokerMessage, error)
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

func (b *MemoryBroker) Publish(ctx context.Context, channel string, message []byte) error {
	select {
	case b.broadcast <- &BrokerMessage{Channel: channel, Payload: message}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return errors.New("memory broker channel is full")
	}
}

func (b *MemoryBroker) Subscribe(ctx context.Context) (<-chan *BrokerMessage, error) {
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

func (b *RedisBroker) Publish(ctx context.Context, channel string, message []byte) error {
	return b.client.Publish(ctx, "realtime:"+channel, message).Err()
}

func (b *RedisBroker) Subscribe(ctx context.Context) (<-chan *BrokerMessage, error) {
	pubsub := b.client.PSubscribe(ctx, "realtime:*")
	if _, err := pubsub.Receive(ctx); err != nil {
		return nil, err
	}

	ch := make(chan *BrokerMessage)
	go func() {
		defer close(ch)
		defer pubsub.Close()
		redisCh := pubsub.Channel()
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-redisCh:
				if !ok {
					return
				}
				ch <- &BrokerMessage{
					Channel: msg.Channel[len("realtime:"):],
					Payload: []byte(msg.Payload),
				}
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
	log         *zap.Logger
	ctx         context.Context
}

type subscription struct {
	client  *Client
	channel string
}

func NewHub(broker Broker, log *zap.Logger, ctx context.Context) *Hub {
	return &Hub{
		broker:      broker,
		register:    make(chan *Client),
		unregister:  make(chan *Client),
		subscribe:   make(chan subscription),
		unsubscribe: make(chan subscription),
		channels:    make(map[string]map[*Client]bool),
		clients:     make(map[*Client]map[string]bool),
		shutdown:    make(chan struct{}),
		log:         log,
		ctx:         ctx,
	}
}

func (h *Hub) Shutdown() {
	close(h.shutdown)
}

func (h *Hub) Run() {
	go h.runLoop()
}

func (h *Hub) runLoop() {
	defer func() {
		h.log.Info("hub shutdown complete")
		h.broker.Close()
		for client := range h.clients {
			close(client.send)
		}
	}()

	for {
		select {
		case <-h.ctx.Done():
			h.log.Info("hub context cancelled, shutting down")
			return
		case <-h.shutdown:
			h.log.Info("hub received shutdown signal, shutting down")
			return
		default:
			err := h.processMessages()
			if err != nil {
				if err == context.Canceled || err == context.DeadlineExceeded {
					return
				}
				h.log.Error("hub message processing loop failed, restarting", zap.Error(err))
				time.Sleep(2 * time.Second)
			}
		}
	}
}

func (h *Hub) processMessages() error {
	const maxBackoff = 30 * time.Second
	nextBackoff := 1 * time.Second
	var brokerCh <-chan *BrokerMessage
	var err error

	for {
		select {
		case <-h.ctx.Done():
			return h.ctx.Err()
		case <-h.shutdown:
			return nil
		default:
		}

		brokerCh, err = h.broker.Subscribe(h.ctx)
		if err == nil {
			h.log.Info("successfully subscribed to broker")
			break
		}
		h.log.Error("failed to subscribe to broker, retrying",
			zap.Duration("retry_in", nextBackoff),
			zap.Error(err),
		)

		select {
		case <-h.ctx.Done():
			return h.ctx.Err()
		case <-h.shutdown:
			return nil
		case <-time.After(nextBackoff):
			nextBackoff *= 2
			if nextBackoff > maxBackoff {
				nextBackoff = maxBackoff
			}
		}
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
			h.log.Info("client subscribed",
				zap.String("user_id", sub.client.UserID),
				zap.String("channel", sub.channel),
			)

			response, _ := json.Marshal(ServerProtocolMessage{Type: TypeSubscribed, Channel: sub.channel})
			sub.client.send <- response

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
			h.log.Info("client unsubscribed",
				zap.String("user_id", sub.client.UserID),
				zap.String("channel", sub.channel),
			)
			response, _ := json.Marshal(ServerProtocolMessage{Type: TypeUnsubscribed, Channel: sub.channel})
			sub.client.send <- response

		case msg, ok := <-brokerCh:
			if !ok {
				h.log.Warn("broker channel closed, attempting to reconnect")
				return nil
			}
			wrappedMsg, err := json.Marshal(ServerProtocolMessage{
				Type:    TypeMessage,
				Channel: msg.Channel,
				Payload: msg.Payload,
			})
			if err != nil {
				h.log.Error("failed to marshal broadcast message", zap.Error(err))
				continue
			}
			if clients, ok := h.channels[msg.Channel]; ok {
				for client := range clients {
					select {
					case client.send <- wrappedMsg:
					default:
						h.log.Warn("client send buffer full, disconnecting",
							zap.String("user_id", client.UserID),
							zap.String("channel", msg.Channel),
						)
						close(client.send)
						delete(clients, client)
					}
				}
			}

		case <-h.shutdown:
			return nil

		case <-h.ctx.Done():
			return h.ctx.Err()
		}
	}
}