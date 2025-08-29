package main

import (
	"C"
	"github.com/dunglas/frankenphp"
	"unsafe"
)

//export_php:namespace Realtime

//export_php:function start(): bool
func start() bool {
	getHub()
	startServer()
	return true
}

//export_php:function broadcast(string $message): void
func broadcast(message *C.zend_string) {
	goMessage := frankenphp.GoString(unsafe.Pointer(message))
	hub := getHub()
	hub.broadcast <- []byte(goMessage)
}