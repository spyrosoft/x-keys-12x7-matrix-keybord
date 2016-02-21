package main

import (
	"github.com/GeertJohan/go.hid"
	"fmt"
)

func main() {
	// Open HID by vendorId, productId and serialNumber
	matrixKeyboardDevice, error := hid.Open( 0x05f3, 0x0309, "" )
	panicOnError( error )
	defer matrixKeyboardDevice.Close()
	
	// Create a feature report
	// This is always 8*n+1 bytes long where n is > 1
	data := make( []byte, 9 )

	input, error := matrixKeyboardDevice.Read( data )
	panicOnError( error )
	
	fmt.Println( input )
}

func panicOnError( error error ) { if error != nil { panic( error ) } }