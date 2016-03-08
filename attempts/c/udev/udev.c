/* Linux */
#include <linux/hidraw.h>

/* C */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

int main(void) {
	num_devs = libusb_get_device_list(NULL, &devs);
	return 0;
}