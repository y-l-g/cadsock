package broadcast

/*
#include <stdlib.h>
#include "broadcast.h"
*/
import "C"
import "unsafe"
import "github.com/dunglas/frankenphp"
import "github.com/y-l-g/realtime/handler"

func init() {
	frankenphp.RegisterExtension(unsafe.Pointer(&C.broadcast_module_entry))
}




//export broadcast
func broadcast(message *C.zend_string) {
	msg := frankenphp.GoString(unsafe.Pointer(message))
	msgBytes := []byte(goString)
	handler.BroadcastMessage(msgBytes)
}

