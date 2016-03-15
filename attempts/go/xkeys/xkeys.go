package main

/*
#cgo LDFLAGS: -I /usr/include/libusb-1.0/ -lusb-1.0 -l pthread
#include "xkeys.h"
*/
import "C"

import (
	"fmt"
)

func main() {
	deviceHandle := C.connect_to_hid()
	for {
		deviceData := C.read_from_hid( deviceHandle )
	}
	fmt.Println("Done!!")
}