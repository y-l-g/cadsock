package broadcast

import (
	"C"
	"unsafe"

	"github.com/dunglas/frankenphp"
	"github.com/y-l-g/realtime/handler"
)

//export_php:function broadcast(string $channel, string $message): void
func broadcast(channel *C.zend_string, message *C.zend_string) {
	goChannel := frankenphp.GoString(unsafe.Pointer(channel))
	goMessage := []byte(frankenphp.GoString(unsafe.Pointer(message)))
	handler.BroadcastToChannel(goChannel, goMessage)
}

