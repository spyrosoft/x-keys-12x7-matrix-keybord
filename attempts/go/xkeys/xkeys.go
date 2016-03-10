package main

/*
#cgo LDFLAGS: -lusb-1.0
#include "xkeys.h"
*/
import "C"

import (
	"fmt"
)

func main() {
	fmt.Println("yes")
}