void print_buf(char *data, int data_length)
{
	int data_index;
	for (data_index = 0; data_index < data_length; data_index++) {
		//printf("%08hh", data[data_index]);
		printf("%02hhx ", data[data_index]);
		if ((data_index+1) % 8 == 0)
			printf("  ");
		if ((data_index+1) % 16 == 0)
			printf("\n");
	}
	printf("\n\n");
}

int main(void)
{
	TEnumHIDInfo info[128];
	long number_of_hid;
	int hid_index;
	long hid_device_handle = -1;
	
	unsigned hid_devices = EnumeratePIE(PI_VID, info, &number_of_hid);
	
	for (hid_index = 0; hid_index < number_of_hid; hid_index++) {
		TEnumHIDInfo *hid_device = &info[hid_index];
		printf("Found X-Keys Device:\n");
		printf("\tPID: %04x\n", hid_device->PID);
		printf("\tUsage Page: %04x\n", hid_device->UP);
		printf("\tUsage:      %04x\n", hid_device->Usage);
		printf("\tVersion: %d\n\n", hid_device->Version);
		
		hid_device_handle = hid_device->Handle;
		unsigned int hid_devices = SetupInterfaceEx(hid_device_handle);
		if (hid_devices != 0) {
			printf("Unabe to open device. err: %d\n", hid_devices);
		}
		break;
	}
	
	if (hid_device_handle < 0) {
		printf("Unable to open device\n");
		exit(1);
	}
	
	char data[80];
	while (1) {
		
		unsigned int hid_device_data_chunk = 0;
		
		hid_device_data_chunk = ReadLast(hid_device_handle, data);
		if (hid_device_data_chunk == 0) {
			printf("LAST: \n");
			print_buf(data, 33);
			printf("ENDLAST\n\n");
		}
		
		hid_device_data_chunk = 0;
		
		while (hid_device_data_chunk == 0) {
			hid_device_data_chunk = BlockingReadData(hid_device_handle, data, 20);
			if (hid_device_data_chunk == 0) {
				print_buf(data, 33);
			}
			else if (hid_device_data_chunk == PIE_HID_READ_INSUFFICIENT_DATA) {
				printf(".");
				fflush(stdout);
			}	
			else {
				printf("Error Reading\n");
			}
		}
		
		printf("Sleeping\n");
		#if 1
		if (hid_device_data_chunk != 0) {
			//usleep(10*1000); //Sleep 10 milliseconds.
			sleep(1); //seconds
		}
		#endif
		
		//ClearBuffer(hid_device_handle);
	}
	
	return 0;
}