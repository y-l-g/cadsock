package hub

import (
	"C"
	"unsafe"

	"github.com/dunglas/frankenphp"
	"github.com/gorilla/websocket"
)

//export_php:function broadcast(string $message): void
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