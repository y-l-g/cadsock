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
func broadcast(channel *C.zend_string, message *C.zend_string) {
	goChannel := frankenphp.GoString(unsafe.Pointer(channel))
	goMessage := []byte(frankenphp.GoString(unsafe.Pointer(message)))
	handler.BroadcastToChannel(goChannel, goMessage)
}

