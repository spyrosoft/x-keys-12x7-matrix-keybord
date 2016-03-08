/*
 * Hidraw Userspace Example
 *
 * Copyright (c) 2010 Alan Ott <alan@signal11.us>
 * Copyright (c) 2010 Signal 11 Software
 *
 * The code may be used by anyone for any purpose,
 * and can serve as a starting point for developing
 * applications using hidraw.
 */

/* Linux */
#include <linux/types.h>
#include <linux/input.h>
#include <linux/hidraw.h>

/*
 * Ugly hack to work around failing compilation on systems that don't
 * yet populate new version of hidraw.h to userspace.
 */
#ifndef HIDIOCSFEATURE
#warning Please have your distro update the userspace kernel headers
#define HIDIOCSFEATURE(len)    _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x06, len)
#define HIDIOCGFEATURE(len)    _IOC(_IOC_WRITE|_IOC_READ, 'H', 0x07, len)
#endif

/* Unix */
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* C */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

const char *bus_str(int bus);

int main(int argc, char **argv)
{
	int device_handle;
	int i, report_reponse, desc_size = 0;
	char data_buffer[256];
	struct hidraw_report_descriptor rpt_desc;
	struct hidraw_devinfo info;
	char *device = "/dev/bus/usb/001/009";

	if (argc > 1)
		device = argv[1];

	/* Open the Device with non-blocking reads. In real life,
	   don't use a hard coded path; use libudev instead. */
	device_handle = open(device, O_RDWR|O_NONBLOCK);

	if (device_handle < 0) {
		perror("Unable to open device");
		return 1;
	}

	memset(&rpt_desc, 0x0, sizeof(rpt_desc));
	memset(&info, 0x0, sizeof(info));
	memset(data_buffer, 0x0, sizeof(data_buffer));

	/* /\* Get Report Descriptor Size *\/ */
	/* report_reponse = ioctl(device_handle, HIDIOCGRDESCSIZE, &desc_size); */
	/* if (report_reponse < 0) */
	/* 	perror("HIDIOCGRDESCSIZE"); */
	/* else */
	/* 	printf("Report Descriptor Size: %d\n", desc_size); */

	/* /\* Get Report Descriptor *\/ */
	/* rpt_desc.size = desc_size; */
	/* report_reponse = ioctl(device_handle, HIDIOCGRDESC, &rpt_desc); */
	/* if (report_reponse < 0) { */
	/* 	perror("HIDIOCGRDESC"); */
	/* } else { */
	/* 	printf("Report Descriptor:\n"); */
	/* 	for (i = 0; i < rpt_desc.size; i++) */
	/* 		printf("%hhx ", rpt_desc.value[i]); */
	/* 	puts("\n"); */
	/* } */

	/* /\* Get Raw Name *\/ */
	/* report_reponse = ioctl(device_handle, HIDIOCGRAWNAME(256), data_buffer); */
	/* if (report_reponse < 0) */
	/* 	perror("HIDIOCGRAWNAME"); */
	/* else */
	/* 	printf("Raw Name: %s\n", data_buffer); */

	/* /\* Get Physical Location *\/ */
	/* report_reponse = ioctl(device_handle, HIDIOCGRAWPHYS(256), data_buffer); */
	/* if (report_reponse < 0) */
	/* 	perror("HIDIOCGRAWPHYS"); */
	/* else */
	/* 	printf("Raw Phys: %s\n", data_buffer); */

	/* /\* Get Raw Info *\/ */
	/* report_reponse = ioctl(device_handle, HIDIOCGRAWINFO, &info); */
	/* if (report_reponse < 0) { */
	/* 	perror("HIDIOCGRAWINFO"); */
	/* } else { */
	/* 	printf("Raw Info:\n"); */
	/* 	printf("\tbustype: %d (%s)\n", */
	/* 		info.bustype, bus_str(info.bustype)); */
	/* 	printf("\tvendor: 0x%04hx\n", info.vendor); */
	/* 	printf("\tproduct: 0x%04hx\n", info.product); */
	/* } */

	/* /\* Set Feature *\/ */
	/* data_buffer[0] = 0x9; /\* Report Number *\/ */
	/* data_buffer[1] = 0xff; */
	/* data_buffer[2] = 0xff; */
	/* data_buffer[3] = 0xff; */
	/* report_reponse = ioctl(device_handle, HIDIOCSFEATURE(4), data_buffer); */
	/* if (report_reponse < 0) */
	/* 	perror("HIDIOCSFEATURE"); */
	/* else */
	/* 	printf("ioctl HIDIOCGFEATURE returned: %d\n", report_reponse); */

	/* /\* Get Feature *\/ */
	/* data_buffer[0] = 0x9; /\* Report Number *\/ */
	/* report_reponse = ioctl(device_handle, HIDIOCGFEATURE(256), data_buffer); */
	/* if (report_reponse < 0) { */
	/* 	perror("HIDIOCGFEATURE"); */
	/* } else { */
	/* 	printf("ioctl HIDIOCGFEATURE returned: %d\n", report_reponse); */
	/* 	printf("Report data (not containing the report number):\n\t"); */
	/* 	for (i = 0; i < report_reponse; i++) */
	/* 		printf("%hhx ", data_buffer[i]); */
	/* 	puts("\n"); */
	/* } */

	/* /\* Send a Report to the Device *\/ */
	/* data_buffer[0] = 0x1; /\* Report Number *\/ */
	/* data_buffer[1] = 0x77; */
	/* report_reponse = write(device_handle, data_buffer, 2); */
	/* if (report_reponse < 0) { */
	/* 	printf("Error: %d\n", errno); */
	/* 	perror("write"); */
	/* } else { */
	/* 	printf("write() wrote %d bytes\n", report_reponse); */
	/* } */

	/* Get a report from the device */
	report_reponse = read(device_handle, data_buffer, 16);
	if (report_reponse < 0) {
		perror("read");
	} else {
		printf("read() read %d bytes:\n\t", report_reponse);
		for (i = 0; i < report_reponse; i++)
			printf("%hhx ", data_buffer[i]);
		puts("\n");
	}
	close(device_handle);
	return 0;
}

const char * bus_str(int bus)
{
	switch (bus) {
	case BUS_USB:
		return "USB";
		break;
	case BUS_HIL:
		return "HIL";
		break;
	case BUS_BLUETOOTH:
		return "Bluetooth";
		break;
	case BUS_VIRTUAL:
		return "Virtual";
		break;
	default:
		return "Other";
		break;
	}
}