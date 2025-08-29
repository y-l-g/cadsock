package extension

/*
#include <stdlib.h>
#include "extension.h"
*/
import "C"
import "github.com/dunglas/frankenphp"
import "unsafe"

func init() {
	frankenphp.RegisterExtension(unsafe.Pointer(&C.extension_module_entry))
}




//export start
func start() bool {
	getHub()
	startServer()
	return true
}

//export broadcast
func broadcast(message *C.zend_string) {
	goMessage := frankenphp.GoString(unsafe.Pointer(message))
	hub := getHub()
	hub.broadcast <- []byte(goMessage)
}

