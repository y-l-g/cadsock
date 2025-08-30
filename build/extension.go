package extension

/*
#include <stdlib.h>
#include "extension.h"
*/
import "C"
import "unsafe"
import "github.com/dunglas/frankenphp"
import "github.com/gorilla/websocket"

func init() {
	frankenphp.RegisterExtension(unsafe.Pointer(&C.extension_module_entry))
}




//export broadcast
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

