package broadcast

import (
	"C"
	"unsafe"

	"github.com/dunglas/frankenphp"

	"github.com/y-l-g/realtime/handler"
)

//export_php:function broadcast(string $message): void
func broadcast(message *C.zend_string) {
	msg := frankenphp.GoString(unsafe.Pointer(message))
	msgBytes := []byte(goString)
	handler.BroadcastMessage(msgBytes)
}