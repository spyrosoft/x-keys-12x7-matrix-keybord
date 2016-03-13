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




	
//// 	char data[80];
//// 	while (1) {
		
//// 		unsigned int hid_device_data_chunk = 0;
		
//// 		hid_device_data_chunk = ReadLast(hid_device_handle, data);
// 		if (hid_device_data_chunk == 0) {
// 			printf("LAST: \n");
// 			print_buf(data, 33);
// 			printf("ENDLAST\n\n");
// 		}
		
// 		hid_device_data_chunk = 0;
		
// 		while (hid_device_data_chunk == 0) {
// 			hid_device_data_chunk = BlockingReadData(hid_device_handle, data, 20);
// 			if (hid_device_data_chunk == 0) {
// 				print_buf(data, 33);
// 			}
// 			else if (hid_device_data_chunk == PIE_HID_READ_INSUFFICIENT_DATA) {
// 				printf(".");
// 				fflush(stdout);
// 			}	
// 			else {
// 				printf("Error Reading\n");
// 			}
// 		}
		
// 		printf("Sleeping\n");
// 		#if 1
// 		if (hid_device_data_chunk != 0) {
// 			//usleep(10*1000); //Sleep 10 milliseconds.
// 			sleep(1); //seconds
// 		}
// 		#endif
		
// 		ClearBuffer(hid_device_handle);
//// 	}