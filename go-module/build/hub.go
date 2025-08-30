package hub

/*
#include <stdlib.h>
#include "hub.h"
*/
import "C"
import "log"
import "net/http"
import "sync"
import "unsafe"
import "github.comcom/dunglas/frankenphp"
import "github.com/gorilla/websocket"

func init() {
	frankenphp.RegisterExtension(unsafe.Pointer(&C.hub_module_entry))
}


var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	clients   = make(map[*websocket.Conn]bool)
	clientsMu sync.Mutex
)


func HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade:", err)
		return
	}
	defer conn.Close()

	clientsMu.Lock()
	clients[conn] = true
	clientsMu.Unlock()

	defer func() {
		clientsMu.Lock()
		delete(clients, conn)
		clientsMu.Unlock()
	}()

	for {
		if _, _, err := conn.NextReader(); err != nil {
			break
		}
	}
}
func main() {}
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

