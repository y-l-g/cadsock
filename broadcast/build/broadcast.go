package broadcast

/*
#include <stdlib.h>
#include "broadcast.h"
*/
import "C"
import "unsafe"
import "github.com/dunglas/frankenphp"
import "github.com/gorilla/websocket"
import "github.com/y-l-g/realtime/handler"

func init() {
	frankenphp.RegisterExtension(unsafe.Pointer(&C.broadcast_module_entry))
}




//export broadcast
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

