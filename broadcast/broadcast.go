package broadcast

import (
	"C"
	"unsafe"

	"github.com/dunglas/frankenphp"
	"github.com/gorilla/websocket"

	"github.com/y-l-g/realtime/handler"
)

//export_php:function broadcast(string $message): void
func broadcast(message *C.zend_string) {
	msg := frankenphp.GoString(unsafe.Pointer(message))

	handler.ClientsMu.Lock()
	defer handler.ClientsMu.Unlock()

	for client := range handler.Clients {
		err := client.WriteMessage(websocket.TextMessage, []byte(msg))
		if err != nil {
			client.Close()
			delete(handler.Clients, client)
		}
	}
}