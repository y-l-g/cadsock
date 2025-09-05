package cadsock

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

type mockConn struct {
	mu          sync.Mutex
	closed      bool
	writtenData chan []byte
	readData    chan []byte
}

func newMockConn() *mockConn {
	return &mockConn{
		writtenData: make(chan []byte, 10),
		readData:    make(chan []byte, 10),
	}
}

func (c *mockConn) SetReadLimit(limit int64)                   {}
func (c *mockConn) SetReadDeadline(t time.Time) error          { return nil }
func (c *mockConn) SetPongHandler(h func(appData string) error) {}

func (c *mockConn) ReadMessage() (int, []byte, error) {
	msg, ok := <-c.readData
	if !ok {
		return 0, nil, &websocket.CloseError{Code: websocket.CloseNormalClosure, Text: "connection closed"}
	}
	return websocket.TextMessage, msg, nil
}

func (c *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *mockConn) WriteMessage(messageType int, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("mock connection is closed")
	}
	select {
	case c.writtenData <- data:
	default:
	}
	return nil
}

func (c *mockConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		c.closed = true
		close(c.readData)
		close(c.writtenData)
	}
	return nil
}

func newTestHub(broker Broker) *Hub {
	logger, _ := zap.NewDevelopment()
	hub := NewHub(broker, logger, context.Background())
	go hub.Run()
	return hub
}

func TestHubRegistration(t *testing.T) {
	broker := NewMemoryBroker()
	hub := newTestHub(broker)
	defer hub.Shutdown()

	client := &Client{hub: hub, send: make(chan []byte, 1), UserID: "user-1"}

	hub.register <- client

	time.Sleep(10 * time.Millisecond)

	if _, ok := hub.clients[client]; !ok {
		t.Fatal("client should be registered in the hub")
	}

	hub.unregister <- client
	time.Sleep(10 * time.Millisecond)

	if _, ok := hub.clients[client]; ok {
		t.Fatal("client should be unregistered from the hub")
	}
}

func TestHubSubscription(t *testing.T) {
	broker := NewMemoryBroker()
	hub := newTestHub(broker)
	defer hub.Shutdown()

	client := &Client{hub: hub, send: make(chan []byte, 1), UserID: "user-1"}
	hub.register <- client

	sub := subscription{client: client, channel: "news"}
	hub.subscribe <- sub

	time.Sleep(10 * time.Millisecond)

	if _, ok := hub.channels["news"]; !ok {
		t.Fatal("channel 'news' should exist")
	}
	if _, ok := hub.channels["news"][client]; !ok {
		t.Fatal("client should be subscribed to channel 'news'")
	}
	if _, ok := hub.clients[client]["news"]; !ok {
		t.Fatal("channel 'news' should be associated with the client")
	}

	select {
	case msgBytes := <-client.send:
		var msg ServerProtocolMessage
		if err := json.Unmarshal(msgBytes, &msg); err != nil {
			t.Fatalf("failed to unmarshal confirmation message: %v", err)
		}
		if msg.Type != TypeSubscribed || msg.Channel != "news" {
			t.Fatalf("unexpected subscription confirmation message: got %+v", msg)
		}
	case <-time.After(50 * time.Millisecond):
		t.Fatal("timed out waiting for subscription confirmation")
	}
}

func TestHubUnsubscription(t *testing.T) {
	broker := NewMemoryBroker()
	hub := newTestHub(broker)
	defer hub.Shutdown()

	client := &Client{hub: hub, send: make(chan []byte, 1), UserID: "user-1"}
	hub.register <- client

	sub := subscription{client: client, channel: "news"}
	hub.subscribe <- sub
	time.Sleep(10 * time.Millisecond)

	<-client.send

	unsub := subscription{client: client, channel: "news"}
	hub.unsubscribe <- unsub
	time.Sleep(10 * time.Millisecond)

	if len(hub.channels["news"]) != 0 {
		t.Fatal("client should be removed from channel 'news'")
	}
	if len(hub.clients[client]) != 0 {
		t.Fatal("channel 'news' should be removed from client's subscriptions")
	}
}

func TestHubBroadcast(t *testing.T) {
	broker := NewMemoryBroker()
	hub := newTestHub(broker)
	defer hub.Shutdown()

	client1 := &Client{hub: hub, send: make(chan []byte, 1), UserID: "user-1"}
	client2 := &Client{hub: hub, send: make(chan []byte, 1), UserID: "user-2"}
	client3 := &Client{hub: hub, send: make(chan []byte, 1), UserID: "user-3"}

	hub.register <- client1
	hub.register <- client2
	hub.register <- client3
	time.Sleep(10 * time.Millisecond)

	hub.subscribe <- subscription{client: client1, channel: "news"}
	hub.subscribe <- subscription{client: client2, channel: "news"}
	hub.subscribe <- subscription{client: client3, channel: "sports"}
	time.Sleep(20 * time.Millisecond)

	for len(client1.send) > 0 {
		<-client1.send
	}
	for len(client2.send) > 0 {
		<-client2.send
	}
	for len(client3.send) > 0 {
		<-client3.send
	}

	messagePayload := `{"title":"breaking news"}`
	err := broker.Publish(context.Background(), "news", []byte(messagePayload))
	if err != nil {
		t.Fatalf("failed to publish message: %v", err)
	}

	checkMessage := func(c *Client, t *testing.T) {
		select {
		case msgBytes := <-c.send:
			var msg ServerProtocolMessage
			if err := json.Unmarshal(msgBytes, &msg); err != nil {
				t.Fatalf("failed to unmarshal broadcast message: %v", err)
			}
			if msg.Type != TypeMessage || msg.Channel != "news" {
				t.Errorf("unexpected message type or channel: %+v", msg)
			}
			if string(msg.Payload) != messagePayload {
				t.Errorf("unexpected message payload: got %s, want %s", msg.Payload, messagePayload)
			}
		case <-time.After(50 * time.Millisecond):
			t.Error("timed out waiting for message")
		}
	}

	checkMessage(client1, t)
	checkMessage(client2, t)

	select {
	case <-client3.send:
		t.Error("client3 should not have received a message on 'news' channel")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestClientErrorHandling(t *testing.T) {
	hub := newTestHub(NewMemoryBroker())
	defer hub.Shutdown()

	mockWsConn := newMockConn()
	client := &Client{hub: hub, conn: mockWsConn, send: make(chan []byte, 10), UserID: "user-err"}

	go client.writePump()
	go client.readPump()
	defer client.conn.Close()

	tests := []struct {
		name          string
		inputMessage  []byte
		expectedError string
	}{
		{
			"Invalid JSON",
			[]byte(`{"action":"subscribe", "channel":}`),
			"invalid JSON message",
		},
		{
			"Unknown Action",
			[]byte(`{"action":"delete", "channel":"news"}`),
			"unknown action: delete",
		},
		{
			"Missing Channel",
			[]byte(`{"action":"subscribe"}`),
			"channel must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockWsConn.readData <- tt.inputMessage

			select {
			case msgBytes := <-mockWsConn.writtenData:
				var serverMsg ServerProtocolMessage
				if err := json.Unmarshal(msgBytes, &serverMsg); err != nil {
					t.Fatalf("could not unmarshal error response: %v", err)
				}
				if serverMsg.Type != TypeError {
					t.Fatalf("expected message type 'error', got '%s'", serverMsg.Type)
				}
				if !strings.Contains(serverMsg.Error, tt.expectedError) {
					t.Fatalf("expected error message to contain '%s', got '%s'", tt.expectedError, serverMsg.Error)
				}
			case <-time.After(100 * time.Millisecond):
				t.Fatal("timed out waiting for error message from server")
			}
		})
	}
}