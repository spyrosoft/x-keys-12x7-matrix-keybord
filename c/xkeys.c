/* C */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <locale.h>
#include <errno.h>

/* Unix */
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <pthread.h>

/* GNU / LibUSB */
#include </usr/include/libusb-1.0/libusb.h>
#include "iconv.h"

#include "xkeys.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <signal.h>

#define BUFFER_LENGTH 5 /* number of reports in the buffer */
#define REPORT_SIZE 80   /* max size of a single report */

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DEBUG_PRINTF
#define LOG(...) fprintf(stderr, __VA_ARGS__)
#else
#define LOG(...) do {} while (0)
#endif

/* Linked List of input reports received from the device. */
struct input_report {
	uint8_t *data;
	size_t len;
	struct input_report *next;
};


struct hid_device_ {
	/* Handle to the actual device. */
	libusb_device_handle *device_handle;
	
	/* Endpoint information */
	int input_endpoint;
	int output_endpoint;
	int input_ep_max_packet_size;

	/* The interface number of the HID */	
	int interface;
	
	/* Indexes of Strings */
	int manufacturer_index;
	int product_index;
	int serial_index;
	
	/* Whether blocking reads are used */
	int blocking; /* boolean */
	
	/* Read thread objects */
	pthread_t thread;
	pthread_mutex_t mutex; /* Protects input_reports */
	pthread_cond_t condition;
	pthread_barrier_t barrier; /* Ensures correct startup sequence */
	int shutdown_thread;
	struct libusb_transfer *transfer;

	/* List of received input reports. */
	struct input_report *input_reports;
};

static int initialized = 0;

uint16_t get_usb_code_for_current_locale(void);
static int return_hid_data(hid_device *dev, unsigned char *data, size_t length);

static hid_device *new_hid_device(void)
{
	hid_device *dev = calloc(1, sizeof(hid_device));
	dev->device_handle = NULL;
	dev->input_endpoint = 0;
	dev->output_endpoint = 0;
	dev->input_ep_max_packet_size = 0;
	dev->interface = 0;
	dev->manufacturer_index = 0;
	dev->product_index = 0;
	dev->serial_index = 0;
	dev->blocking = 1;
	dev->shutdown_thread = 0;
	dev->transfer = NULL;
	dev->input_reports = NULL;
	
	pthread_mutex_init(&dev->mutex, NULL);
	pthread_cond_init(&dev->condition, NULL);
	pthread_barrier_init(&dev->barrier, NULL, 2);
	
	return dev;
}

static void free_hid_device(hid_device *dev)
{
	/* Clean up the thread objects */
	pthread_barrier_destroy(&dev->barrier);
	pthread_cond_destroy(&dev->condition);
	pthread_mutex_destroy(&dev->mutex);

	/* Free the device itself */
	free(dev);
}

#if 0
//TODO: Implement this funciton on Linux.
static void register_error(hid_device *device, const char *op)
{

}
#endif

#ifdef INVASIVE_GET_USAGE
/* Get bytes from a HID Report Descriptor.
   Only call with a num_bytes of 0, 1, 2, or 4. */
static uint32_t get_bytes(uint8_t *rpt, size_t len, size_t num_bytes, size_t cur)
{
	/* Return if there aren't enough bytes. */
	if (cur + num_bytes >= len)
		return 0;

	if (num_bytes == 0)
		return 0;
	else if (num_bytes == 1) {
		return rpt[cur+1];
	}
	else if (num_bytes == 2) {
		return (rpt[cur+2] * 256 + rpt[cur+1]);
	}
	else if (num_bytes == 4) {
		return (rpt[cur+4] * 0x01000000 +
		        rpt[cur+3] * 0x00010000 +
		        rpt[cur+2] * 0x00000100 +
		        rpt[cur+1] * 0x00000001);
	}
	else
		return 0;
}

/* Retrieves the device's Usage Page and Usage from the report
   descriptor. The algorithm is simple, as it just returns the first
   Usage and Usage Page that it finds in the descriptor.
   The return value is 0 on success and -1 on failure. */
static int get_usage(uint8_t *report_descriptor, size_t size,
                     unsigned short *usage_page, unsigned short *usage)
{
	int i = 0;
	int size_code;
	int data_len, key_size;
	int usage_found = 0, usage_page_found = 0;
	
	while (i < size) {
		int key = report_descriptor[i];
		int key_cmd = key & 0xfc;

		//printf("key: %02hhx\n", key);
		
		if ((key & 0xf0) == 0xf0) {
			/* This is a Long Item. The next byte contains the
			   length of the data section (value) for this key.
			   See the HID specification, version 1.11, section
			   6.2.2.3, titled "Long Items." */
			if (i+1 < size)
				data_len = report_descriptor[i+1];
			else
				data_len = 0; /* malformed report */
			key_size = 3;
		}
		else {
			/* This is a Short Item. The bottom two bits of the
			   key contain the size code for the data section
			   (value) for this key.  Refer to the HID
			   specification, version 1.11, section 6.2.2.2,
			   titled "Short Items." */
			size_code = key & 0x3;
			switch (size_code) {
			case 0:
			case 1:
			case 2:
				data_len = size_code;
				break;
			case 3:
				data_len = 4;
				break;
			default:
				/* Can't ever happen since size_code is & 0x3 */
				data_len = 0;
				break;
			};
			key_size = 1;
		}
		
		if (key_cmd == 0x4) {
			*usage_page  = get_bytes(report_descriptor, size, data_len, i);
			usage_page_found = 1;
			//printf("Usage Page: %x\n", (uint32_t)*usage_page);
		}
		if (key_cmd == 0x8) {
			*usage = get_bytes(report_descriptor, size, data_len, i);
			usage_found = 1;
			//printf("Usage: %x\n", (uint32_t)*usage);
		}

		if (usage_page_found && usage_found)
			return 0; /* success */
		
		/* Skip over this key and it's associated data */
		i += data_len + key_size;
	}
	
	return -1; /* failure */
}
#endif // INVASIVE_GET_USAGE


/* Get the first language the device says it reports. This comes from
   USB string #0. */
static uint16_t get_first_language(libusb_device_handle *dev)
{
	uint16_t buf[32];
	int len;
	
	/* Get the string from libusb. */
	len = libusb_get_string_descriptor(dev,
			0x0, /* String ID */
			0x0, /* Language */
			(unsigned char*)buf,
			sizeof(buf));
	if (len < 4)
		return 0x0;
	
	return buf[1]; // First two bytes are len and descriptor type.
}

static int is_language_supported(libusb_device_handle *dev, uint16_t lang)
{
	uint16_t buf[32];
	int len;
	int i;
	
	/* Get the string from libusb. */
	len = libusb_get_string_descriptor(dev,
			0x0, /* String ID */
			0x0, /* Language */
			(unsigned char*)buf,
			sizeof(buf));
	if (len < 4)
		return 0x0;
	
	
	len /= 2; /* language IDs are two-bytes each. */
	/* Start at index 1 because there are two bytes of protocol data. */
	for (i = 1; i < len; i++) {
		if (buf[i] == lang)
			return 1;
	}

	return 0;
}


/* This function returns a newly allocated wide string containing the USB
   device string numbered by the index. The returned string must be freed
   by using free(). */
static wchar_t *get_usb_string(libusb_device_handle *dev, uint8_t idx)
{
	char buf[512];
	int len;
	wchar_t *str = NULL;
	wchar_t wbuf[256];

	/* iconv variables */
	iconv_t ic;
	size_t inbytes;
	size_t outbytes;
	size_t res;
	char *inptr;
	char *outptr;

	/* Determine which language to use. */
	uint16_t lang;
	lang = get_usb_code_for_current_locale();
	if (!is_language_supported(dev, lang))
		lang = get_first_language(dev);
		
	/* Get the string from libusb. */
	len = libusb_get_string_descriptor(dev,
			idx,
			lang,
			(unsigned char*)buf,
			sizeof(buf));
	if (len < 0)
		return NULL;
	
	buf[sizeof(buf)-1] = '\0';
	
	if (len+1 < sizeof(buf))
		buf[len+1] = '\0';
	
	/* Initialize iconv. */
	ic = iconv_open("UTF-32", "UTF-16");
	if (ic == (iconv_t)-1)
		return NULL;
	
	/* Convert to UTF-32 (wchar_t on glibc systems).
	   Skip the first character (2-bytes). */
	inptr = buf+2;
	inbytes = len-2;
	outptr = (char*) wbuf;
	outbytes = sizeof(wbuf);
	res = iconv(ic, &inptr, &inbytes, &outptr, &outbytes);
	if (res == (size_t)-1)
		goto err;

	/* Write the terminating NULL. */
	wbuf[sizeof(wbuf)/sizeof(wbuf[0])-1] = 0x00000000;
	if (outbytes >= sizeof(wbuf[0]))
		*((wchar_t*)outptr) = 0x00000000;
	
	/* Allocate and copy the string. */
	str = wcsdup(wbuf+1);

err:
	iconv_close(ic);
	
	return str;
}

static char *make_path(libusb_device *dev, int interface_number)
{
	char str[64];
	snprintf(str, sizeof(str), "%04x:%04x:%02x",
		libusb_get_bus_number(dev),
		libusb_get_device_address(dev),
		interface_number);
	str[sizeof(str)-1] = '\0';
	
	return strdup(str);
}

struct hid_device_info  HID_API_EXPORT *hid_enumerate(unsigned short vendor_id, unsigned short product_id)
{
	libusb_device **devs;
	libusb_device *dev;
	libusb_device_handle *handle;
	ssize_t num_devs;
	int i = 0;
	
	struct hid_device_info *root = NULL; // return object
	struct hid_device_info *cur_dev = NULL;
	
	setlocale(LC_ALL,"");
	
	if (!initialized) {
		libusb_init(NULL);
		initialized = 1;
	}
	
	num_devs = libusb_get_device_list(NULL, &devs);
	if (num_devs < 0)
		return NULL;
	while ((dev = devs[i++]) != NULL) {
		struct libusb_device_descriptor desc;
		struct libusb_config_descriptor *conf_desc = NULL;
		int j, k;
		int interface_num = 0;

		int res = libusb_get_device_descriptor(dev, &desc);
		unsigned short dev_vid = desc.idVendor;
		unsigned short dev_pid = desc.idProduct;
		
		/* HID's are defined at the interface level. */
		if (desc.bDeviceClass != LIBUSB_CLASS_PER_INTERFACE)
			continue;

		res = libusb_get_active_config_descriptor(dev, &conf_desc);
		if (res < 0)
			libusb_get_config_descriptor(dev, 0, &conf_desc);
		if (conf_desc) {
			for (j = 0; j < conf_desc->bNumInterfaces; j++) {
				const struct libusb_interface *intf = &conf_desc->interface[j];
				for (k = 0; k < intf->num_altsetting; k++) {
					const struct libusb_interface_descriptor *intf_desc;
					intf_desc = &intf->altsetting[k];
					if (intf_desc->bInterfaceClass == LIBUSB_CLASS_HID) {
						interface_num = intf_desc->bInterfaceNumber;

						/* Check the VID/PID against the arguments */
						if ((vendor_id == 0x0 && product_id == 0x0) ||
						    (vendor_id == dev_vid && product_id == dev_pid)) {
							struct hid_device_info *tmp;

							/* VID/PID match. Create the record. */
							tmp = calloc(1, sizeof(struct hid_device_info));
							if (cur_dev) {
								cur_dev->next = tmp;
							}
							else {
								root = tmp;
							}
							cur_dev = tmp;
							
							/* Fill out the record */
							cur_dev->next = NULL;
							cur_dev->path = make_path(dev, interface_num);
							
							res = libusb_open(dev, &handle);

							if (res >= 0) {
								/* Serial Number */
								if (desc.iSerialNumber > 0)
									cur_dev->serial_number =
										get_usb_string(handle, desc.iSerialNumber);

								/* Manufacturer and Product strings */
								if (desc.iManufacturer > 0)
									cur_dev->manufacturer_string =
										get_usb_string(handle, desc.iManufacturer);
								if (desc.iProduct > 0)
									cur_dev->product_string =
										get_usb_string(handle, desc.iProduct);

#ifdef INVASIVE_GET_USAGE
							/*
							This section is removed because it is too
							invasive on the system. Getting a Usage Page
							and Usage requires parsing the HID Report
							descriptor. Getting a HID Report descriptor
							involves claiming the interface. Claiming the
							interface involves detaching the kernel driver.
							Detaching the kernel driver is hard on the system
							because it will unclaim interfaces (if another
							app has them claimed) and the re-attachment of
							the driver will sometimes change /dev entry names.
							It is for these reasons that this section is
							#if 0. For composite devices, use the interface
							field in the hid_device_info struct to distinguish
							between interfaces. */
								int detached = 0;
								unsigned char data[256];
							
								/* Usage Page and Usage */
								res = libusb_kernel_driver_active(handle, interface_num);
								if (res == 1) {
									res = libusb_detach_kernel_driver(handle, interface_num);
									if (res < 0)
										LOG("Couldn't detach kernel driver, even though a kernel driver was attached.");
									else
										detached = 1;
								}
								res = libusb_claim_interface(handle, interface_num);
								if (res >= 0) {
									/* Get the HID Report Descriptor. */
									res = libusb_control_transfer(handle, LIBUSB_ENDPOINT_IN|LIBUSB_RECIPIENT_INTERFACE, LIBUSB_REQUEST_GET_DESCRIPTOR, (LIBUSB_DT_REPORT << 8)|interface_num, 0, data, sizeof(data), 5000);
									if (res >= 0) {
										unsigned short page=0, usage=0;
										/* Parse the usage and usage page
										   out of the report descriptor. */
										get_usage(data, res,  &page, &usage);
										cur_dev->usage_page = page;
										cur_dev->usage = usage;
									}
									else
										LOG("libusb_control_transfer() for getting the HID report failed with %d\n", res);

									/* Release the interface */
									res = libusb_release_interface(handle, interface_num);
									if (res < 0)
										LOG("Can't release the interface.\n");
								}
								else
									LOG("Can't claim interface %d\n", res);

								/* Re-attach kernel driver if necessary. */
								if (detached) {
									res = libusb_attach_kernel_driver(handle, interface_num);
									if (res < 0)
										LOG("Couldn't re-attach kernel driver.\n");
								}
#endif /*******************/

								libusb_close(handle);
							}
							/* VID/PID */
							cur_dev->vendor_id = dev_vid;
							cur_dev->product_id = dev_pid;

							/* Release Number */
							cur_dev->release_number = desc.bcdDevice;
							
							/* Interface Number */
							cur_dev->interface_number = interface_num;
						}
					}
				} /* altsettings */
			} /* interfaces */
			libusb_free_config_descriptor(conf_desc);
		}
	}

	libusb_free_device_list(devs, 1);

	return root;
}

void  HID_API_EXPORT hid_free_enumeration(struct hid_device_info *devs)
{
	struct hid_device_info *d = devs;
	while (d) {
		struct hid_device_info *next = d->next;
		free(d->path);
		free(d->serial_number);
		free(d->manufacturer_string);
		free(d->product_string);
		free(d);
		d = next;
	}
}

hid_device * hid_open(unsigned short vendor_id, unsigned short product_id, wchar_t *serial_number)
{
	struct hid_device_info *devs, *cur_dev;
	const char *path_to_open = NULL;
	hid_device *handle = NULL;
	
	devs = hid_enumerate(vendor_id, product_id);
	cur_dev = devs;
	while (cur_dev) {
		if (cur_dev->vendor_id == vendor_id &&
		    cur_dev->product_id == product_id) {
			if (serial_number) {
				if (wcscmp(serial_number, cur_dev->serial_number) == 0) {
					path_to_open = cur_dev->path;
					break;
				}
			}
			else {
				path_to_open = cur_dev->path;
				break;
			}
		}
		cur_dev = cur_dev->next;
	}

	if (path_to_open) {
		/* Open the device */
		handle = hid_open_path(path_to_open);
	}

	hid_free_enumeration(devs);
	
	return handle;
}

static void read_callback(struct libusb_transfer *transfer)
{
	hid_device *dev = transfer->user_data;
	
	if (transfer->status == LIBUSB_TRANSFER_COMPLETED) {

		struct input_report *rpt = malloc(sizeof(*rpt));
		rpt->data = malloc(transfer->actual_length);
		memcpy(rpt->data, transfer->buffer, transfer->actual_length);
		rpt->len = transfer->actual_length;
		rpt->next = NULL;

		pthread_mutex_lock(&dev->mutex);

		/* Attach the new report object to the end of the list. */
		if (dev->input_reports == NULL) {
			/* The list is empty. Put it at the root. */
			dev->input_reports = rpt;
			pthread_cond_signal(&dev->condition);
		}
		else {
			/* Find the end of the list and attach. */
			struct input_report *cur = dev->input_reports;
			int num_queued = 0;
			while (cur->next != NULL) {
				cur = cur->next;
				num_queued++;
			}
			cur->next = rpt;
			
			/* Pop one off if we've reached 30 in the queue. This
			   way we don't grow forever if the user never reads
			   anything from the device. */
			if (num_queued > 30) {
				return_hid_data(dev, NULL, 0);
			}			
		}
		pthread_mutex_unlock(&dev->mutex);
	}
	else if (transfer->status == LIBUSB_TRANSFER_CANCELLED) {
		dev->shutdown_thread = 1;
		return;
	}
	else if (transfer->status == LIBUSB_TRANSFER_NO_DEVICE) {
		dev->shutdown_thread = 1;
		return;
	}
	else if (transfer->status == LIBUSB_TRANSFER_TIMED_OUT) {
		//LOG("Timeout (normal)\n");
	}
	else {
		LOG("Unknown transfer code: %d\n", transfer->status);
	}
	
	/* Re-submit the transfer object. */
	libusb_submit_transfer(transfer);
}


static void *read_hid_thread(void *param)
{
	hid_device *dev = param;
	unsigned char *buf;
	const size_t length = dev->input_ep_max_packet_size;

	/* Set up the transfer object. */
	buf = malloc(length);
	dev->transfer = libusb_alloc_transfer(0);
	libusb_fill_interrupt_transfer(dev->transfer,
		dev->device_handle,
		dev->input_endpoint,
		buf,
		length,
		read_callback,
		dev,
		5000/*timeout*/);
	
	/* Make the first submission. Further submissions are made
	   from inside read_callback() */
	libusb_submit_transfer(dev->transfer);

	// Notify the main thread that the read thread is up and running.
	pthread_barrier_wait(&dev->barrier);
	
	/* Handle all the events. */
	while (!dev->shutdown_thread) {
		int res;
		res = libusb_handle_events(NULL);
		if (res < 0) {
			/* There was an error. Break out of this loop. */
			break;
		}
	}
	
	/* Cancel any transfer that may be pending. This call will fail
	   if no transfers are pending, but that's OK. */
	if (libusb_cancel_transfer(dev->transfer) == 0) {
		/* The transfer was cancelled, so wait for its completion. */
		libusb_handle_events(NULL);
	}
	
	/* Now that the read thread is stopping, Wake any threads which are
	   waiting on data (in hid_read_timeout()). Do this under a mutex to
	   make sure that a thread which is about to go to sleep waiting on
	   the condition acutally will go to sleep before the condition is
	   signaled. */
	pthread_mutex_lock(&dev->mutex);
	pthread_cond_broadcast(&dev->condition);
	pthread_mutex_unlock(&dev->mutex);

	/* The dev->transfer->buffer and dev->transfer objects are cleaned up
	   in hid_close(). They are not cleaned up here because this thread
	   could end either due to a disconnect or due to a user
	   call to hid_close(). In both cases the objects can be safely
	   cleaned up after the call to pthread_join() (in hid_close()), but
	   since hid_close() calls libusb_cancel_transfer(), on these objects,
	   they can not be cleaned up here. */
	
	return NULL;
}


hid_device * HID_API_EXPORT hid_open_path(const char *path)
{
	hid_device *dev = NULL;

	dev = new_hid_device();

	libusb_device **devs;
	libusb_device *usb_dev;
	ssize_t num_devs;
	int res;
	int d = 0;
	int good_open = 0;
	
	setlocale(LC_ALL,"");
	
	if (!initialized) {
		libusb_init(NULL);
		initialized = 1;
	}
	
	num_devs = libusb_get_device_list(NULL, &devs);
	while ((usb_dev = devs[d++]) != NULL) {
		struct libusb_device_descriptor desc;
		struct libusb_config_descriptor *conf_desc = NULL;
		int i,j,k;
		libusb_get_device_descriptor(usb_dev, &desc);

		if (libusb_get_active_config_descriptor(usb_dev, &conf_desc) < 0)
			continue;
		for (j = 0; j < conf_desc->bNumInterfaces; j++) {
			const struct libusb_interface *intf = &conf_desc->interface[j];
			for (k = 0; k < intf->num_altsetting; k++) {
				const struct libusb_interface_descriptor *intf_desc;
				intf_desc = &intf->altsetting[k];
				if (intf_desc->bInterfaceClass == LIBUSB_CLASS_HID) {
					char *dev_path = make_path(usb_dev, intf_desc->bInterfaceNumber);
					if (!strcmp(dev_path, path)) {
						/* Matched Paths. Open this device */

						// OPEN HERE //
						res = libusb_open(usb_dev, &dev->device_handle);
						if (res < 0) {
							LOG("can't open device\n");
							free(dev_path);
 							break;
						}
						good_open = 1;
						
						/* Detach the kernel driver, but only if the
						   device is managed by the kernel */
						if (libusb_kernel_driver_active(dev->device_handle, intf_desc->bInterfaceNumber) == 1) {
							res = libusb_detach_kernel_driver(dev->device_handle, intf_desc->bInterfaceNumber);
							if (res < 0) {
								libusb_close(dev->device_handle);
								LOG("Unable to detach Kernel Driver\n");
								free(dev_path);
								good_open = 0;
								break;
							}
						}
						
						res = libusb_claim_interface(dev->device_handle, intf_desc->bInterfaceNumber);
						if (res < 0) {
							LOG("can't claim interface %d: %d\n", intf_desc->bInterfaceNumber, res);
							free(dev_path);
							libusb_close(dev->device_handle);
							good_open = 0;
							break;
						}

						/* Store off the string descriptor indexes */
						dev->manufacturer_index = desc.iManufacturer;
						dev->product_index      = desc.iProduct;
						dev->serial_index       = desc.iSerialNumber;

						/* Store off the interface number */
						dev->interface = intf_desc->bInterfaceNumber;
												
						/* Find the INPUT and OUTPUT endpoints. An
						   OUTPUT endpoint is not required. */
						for (i = 0; i < intf_desc->bNumEndpoints; i++) {
							const struct libusb_endpoint_descriptor *ep
								= &intf_desc->endpoint[i];

							/* Determine the type and direction of this
							   endpoint. */
							int is_interrupt =
								(ep->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK)
							      == LIBUSB_TRANSFER_TYPE_INTERRUPT;
							int is_output = 
								(ep->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK)
							      == LIBUSB_ENDPOINT_OUT;
							int is_input = 
								(ep->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK)
							      == LIBUSB_ENDPOINT_IN;

							/* Decide whether to use it for intput or output. */
							if (dev->input_endpoint == 0 &&
							    is_interrupt && is_input) {
								/* Use this endpoint for INPUT */
								dev->input_endpoint = ep->bEndpointAddress;
								dev->input_ep_max_packet_size = ep->wMaxPacketSize;
							}
							if (dev->output_endpoint == 0 &&
							    is_interrupt && is_output) {
								/* Use this endpoint for OUTPUT */
								dev->output_endpoint = ep->bEndpointAddress;
							}
						}
						
						pthread_create(&dev->thread, NULL, read_hid_thread, dev);
						
						// Wait here for the read thread to be initialized.
						pthread_barrier_wait(&dev->barrier);
						
					}
					free(dev_path);
				}
			}
		}
		libusb_free_config_descriptor(conf_desc);

	}

	libusb_free_device_list(devs, 1);
	
	// If we have a good handle, return it.
	if (good_open) {
		return dev;
	}
	else {
		// Unable to open any devices.
		free_hid_device(dev);
		return NULL;
	}
}


int HID_API_EXPORT hid_write(hid_device *dev, const unsigned char *data, size_t length)
{
	int res;
	int report_number = data[0];
	int skipped_report_id = 0;

	if (report_number == 0x0) {
		data++;
		length--;
		skipped_report_id = 1;
	}


	if (dev->output_endpoint <= 0) {
		/* No interrput out endpoint. Use the Control Endpoint */
		res = libusb_control_transfer(dev->device_handle,
			LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE|LIBUSB_ENDPOINT_OUT,
			0x09/*HID Set_Report*/,
			(2/*HID output*/ << 8) | report_number,
			dev->interface,
			(unsigned char *)data, length,
			1000/*timeout millis*/);
		
		if (res < 0)
			return -1;
		
		if (skipped_report_id)
			length++;
		
		return length;
	}
	else {
		/* Use the interrupt out endpoint */
		int actual_length;
		res = libusb_interrupt_transfer(dev->device_handle,
			dev->output_endpoint,
			(unsigned char*)data,
			length,
			&actual_length, 1000);
		
		if (res < 0)
			return -1;
		
		if (skipped_report_id)
			actual_length++;
		
		return actual_length;
	}
}

/* Helper function, to simplify hid_read().
   This should be called with dev->mutex locked. */
static int return_hid_data(hid_device *dev, unsigned char *data, size_t length)
{
	/* Copy the data out of the linked list item (rpt) into the
	   return buffer (data), and delete the liked list item. */
	struct input_report *rpt = dev->input_reports;
	size_t len = (length < rpt->len)? length: rpt->len;
	if (len > 0)
		memcpy(data, rpt->data, len);
	dev->input_reports = rpt->next;
	free(rpt->data);
	free(rpt);
	return len;
}

static void cleanup_hid_mutex(void *param)
{
	hid_device *dev = param;
	pthread_mutex_unlock(&dev->mutex);
}


int HID_API_EXPORT hid_read_timeout(hid_device *dev, unsigned char *data, size_t length, int milliseconds)
{
	int bytes_read = -1;

#if 0
	int transferred;
	int res = libusb_interrupt_transfer(dev->device_handle, dev->input_endpoint, data, length, &transferred, 5000);
	LOG("transferred: %d\n", transferred);
	return transferred;
#endif

	pthread_mutex_lock(&dev->mutex);
	pthread_cleanup_push(&cleanup_hid_mutex, dev);

	/* There's an input report queued up. Return it. */
	if (dev->input_reports) {
		/* Return the first one */
		bytes_read = return_hid_data(dev, data, length);
		goto ret;
	}
	
	if (dev->shutdown_thread) {
		/* This means the device has been disconnected.
		   An error code of -1 should be returned. */
		bytes_read = -1;
		goto ret;
	}
	
	if (milliseconds == -1) {
		/* Blocking */
		while (!dev->input_reports && !dev->shutdown_thread) {
			pthread_cond_wait(&dev->condition, &dev->mutex);
		}
		if (dev->input_reports) {
			bytes_read = return_hid_data(dev, data, length);
		}
	}
	else if (milliseconds > 0) {
		/* Non-blocking, but called with timeout. */
		int res;
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += milliseconds / 1000;
		ts.tv_nsec += (milliseconds % 1000) * 1000000;
		if (ts.tv_nsec >= 1000000000L) {
			ts.tv_sec++;
			ts.tv_nsec -= 1000000000L;
		}
		
		while (!dev->input_reports && !dev->shutdown_thread) {
			res = pthread_cond_timedwait(&dev->condition, &dev->mutex, &ts);
			if (res == 0) {
				if (dev->input_reports) {
					bytes_read = return_hid_data(dev, data, length);
					break;
				}
				
				/* If we're here, there was a spurious wake up
				   or the read thread was shutdown. Run the
				   loop again (ie: don't break). */
			}
			else if (res == ETIMEDOUT) {
				/* Timed out. */
				bytes_read = 0;
				break;
			}
			else {
				/* Error. */
				bytes_read = -1;
				break;
			}
		}
	}
	else {
		/* Purely non-blocking */
		bytes_read = 0;
	}

ret:
	pthread_mutex_unlock(&dev->mutex);
	pthread_cleanup_pop(0);

	return bytes_read;
}

int HID_API_EXPORT hid_read(hid_device *dev, unsigned char *data, size_t length)
{
	return hid_read_timeout(dev, data, length, dev->blocking ? -1 : 0);
}

int HID_API_EXPORT hid_set_nonblocking(hid_device *dev, int nonblock)
{
	dev->blocking = !nonblock;
	
	return 0;
}


int HID_API_EXPORT hid_send_feature_report(hid_device *dev, const unsigned char *data, size_t length)
{
	int res = -1;
	int skipped_report_id = 0;
	int report_number = data[0];

	if (report_number == 0x0) {
		data++;
		length--;
		skipped_report_id = 1;
	}

	res = libusb_control_transfer(dev->device_handle,
		LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE|LIBUSB_ENDPOINT_OUT,
		0x09/*HID set_report*/,
		(3/*HID feature*/ << 8) | report_number,
		dev->interface,
		(unsigned char *)data, length,
		1000/*timeout millis*/);
	
	if (res < 0)
		return -1;
	
	/* Account for the report ID */
	if (skipped_report_id)
		length++;
	
	return length;
}

int HID_API_EXPORT hid_get_feature_report(hid_device *dev, unsigned char *data, size_t length)
{
	int res = -1;
	int skipped_report_id = 0;
	int report_number = data[0];

	if (report_number == 0x0) {
		/* Offset the return buffer by 1, so that the report ID
		   will remain in byte 0. */
		data++;
		length--;
		skipped_report_id = 1;
	}
	res = libusb_control_transfer(dev->device_handle,
		LIBUSB_REQUEST_TYPE_CLASS|LIBUSB_RECIPIENT_INTERFACE|LIBUSB_ENDPOINT_IN,
		0x01/*HID get_report*/,
		(3/*HID feature*/ << 8) | report_number,
		dev->interface,
		(unsigned char *)data, length,
		1000/*timeout millis*/);
	
	if (res < 0)
		return -1;

	if (skipped_report_id)
		res++;
	
	return res;
}


void HID_API_EXPORT hid_close(hid_device *dev)
{
	if (!dev)
		return;
	
	/* Cause read_hid_thread() to stop. */
	dev->shutdown_thread = 1;
	libusb_cancel_transfer(dev->transfer);

	/* Wait for read_thread() to end. */
	pthread_join(dev->thread, NULL);
	
	/* Clean up the Transfer objects allocated in read_hid_thread(). */
	free(dev->transfer->buffer);
	libusb_free_transfer(dev->transfer);
	
	/* release the interface */
	libusb_release_interface(dev->device_handle, dev->interface);
	
	/* Close the handle */
	libusb_close(dev->device_handle);
	
	/* Clear out the queue of received reports. */
	pthread_mutex_lock(&dev->mutex);
	while (dev->input_reports) {
		return_hid_data(dev, NULL, 0);
	}
	pthread_mutex_unlock(&dev->mutex);
	
	free_hid_device(dev);
}


int HID_API_EXPORT_CALL hid_get_manufacturer_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
	return hid_get_indexed_string(dev, dev->manufacturer_index, string, maxlen);
}

int HID_API_EXPORT_CALL hid_get_product_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
	return hid_get_indexed_string(dev, dev->product_index, string, maxlen);
}

int HID_API_EXPORT_CALL hid_get_serial_number_string(hid_device *dev, wchar_t *string, size_t maxlen)
{
	return hid_get_indexed_string(dev, dev->serial_index, string, maxlen);
}

int HID_API_EXPORT_CALL hid_get_indexed_string(hid_device *dev, int string_index, wchar_t *string, size_t maxlen)
{
	wchar_t *str;

	str = get_usb_string(dev->device_handle, string_index);
	if (str) {
		wcsncpy(string, str, maxlen);
		string[maxlen-1] = L'\0';
		free(str);
		return 0;
	}
	else
		return -1;
}


HID_API_EXPORT const wchar_t * HID_API_CALL  hid_error(hid_device *dev)
{
	return NULL;
}


struct lang_map_entry {
	const char *name;
	const char *string_code;
	uint16_t usb_code;
};

#define LANG(name,code,usb_code) { name, code, usb_code }
static struct lang_map_entry lang_map[] = {
	LANG("Afrikaans", "af", 0x0436),
	LANG("Albanian", "sq", 0x041C),
	LANG("Arabic - United Arab Emirates", "ar_ae", 0x3801),
	LANG("Arabic - Bahrain", "ar_bh", 0x3C01),
	LANG("Arabic - Algeria", "ar_dz", 0x1401),
	LANG("Arabic - Egypt", "ar_eg", 0x0C01),
	LANG("Arabic - Iraq", "ar_iq", 0x0801),
	LANG("Arabic - Jordan", "ar_jo", 0x2C01),
	LANG("Arabic - Kuwait", "ar_kw", 0x3401),
	LANG("Arabic - Lebanon", "ar_lb", 0x3001),
	LANG("Arabic - Libya", "ar_ly", 0x1001),
	LANG("Arabic - Morocco", "ar_ma", 0x1801),
	LANG("Arabic - Oman", "ar_om", 0x2001),
	LANG("Arabic - Qatar", "ar_qa", 0x4001),
	LANG("Arabic - Saudi Arabia", "ar_sa", 0x0401),
	LANG("Arabic - Syria", "ar_sy", 0x2801),
	LANG("Arabic - Tunisia", "ar_tn", 0x1C01),
	LANG("Arabic - Yemen", "ar_ye", 0x2401),
	LANG("Armenian", "hy", 0x042B),
	LANG("Azeri - Latin", "az_az", 0x042C),
	LANG("Azeri - Cyrillic", "az_az", 0x082C),
	LANG("Basque", "eu", 0x042D),
	LANG("Belarusian", "be", 0x0423),
	LANG("Bulgarian", "bg", 0x0402),
	LANG("Catalan", "ca", 0x0403),
	LANG("Chinese - China", "zh_cn", 0x0804),
	LANG("Chinese - Hong Kong SAR", "zh_hk", 0x0C04),
	LANG("Chinese - Macau SAR", "zh_mo", 0x1404),
	LANG("Chinese - Singapore", "zh_sg", 0x1004),
	LANG("Chinese - Taiwan", "zh_tw", 0x0404),
	LANG("Croatian", "hr", 0x041A),
	LANG("Czech", "cs", 0x0405),
	LANG("Danish", "da", 0x0406),
	LANG("Dutch - Netherlands", "nl_nl", 0x0413),
	LANG("Dutch - Belgium", "nl_be", 0x0813),
	LANG("English - Australia", "en_au", 0x0C09),
	LANG("English - Belize", "en_bz", 0x2809),
	LANG("English - Canada", "en_ca", 0x1009),
	LANG("English - Caribbean", "en_cb", 0x2409),
	LANG("English - Ireland", "en_ie", 0x1809),
	LANG("English - Jamaica", "en_jm", 0x2009),
	LANG("English - New Zealand", "en_nz", 0x1409),
	LANG("English - Phillippines", "en_ph", 0x3409),
	LANG("English - Southern Africa", "en_za", 0x1C09),
	LANG("English - Trinidad", "en_tt", 0x2C09),
	LANG("English - Great Britain", "en_gb", 0x0809),
	LANG("English - United States", "en_us", 0x0409),
	LANG("Estonian", "et", 0x0425),
	LANG("Farsi", "fa", 0x0429),
	LANG("Finnish", "fi", 0x040B),
	LANG("Faroese", "fo", 0x0438),
	LANG("French - France", "fr_fr", 0x040C),
	LANG("French - Belgium", "fr_be", 0x080C),
	LANG("French - Canada", "fr_ca", 0x0C0C),
	LANG("French - Luxembourg", "fr_lu", 0x140C),
	LANG("French - Switzerland", "fr_ch", 0x100C),
	LANG("Gaelic - Ireland", "gd_ie", 0x083C),
	LANG("Gaelic - Scotland", "gd", 0x043C),
	LANG("German - Germany", "de_de", 0x0407),
	LANG("German - Austria", "de_at", 0x0C07),
	LANG("German - Liechtenstein", "de_li", 0x1407),
	LANG("German - Luxembourg", "de_lu", 0x1007),
	LANG("German - Switzerland", "de_ch", 0x0807),
	LANG("Greek", "el", 0x0408),
	LANG("Hebrew", "he", 0x040D),
	LANG("Hindi", "hi", 0x0439),
	LANG("Hungarian", "hu", 0x040E),
	LANG("Icelandic", "is", 0x040F),
	LANG("Indonesian", "id", 0x0421),
	LANG("Italian - Italy", "it_it", 0x0410),
	LANG("Italian - Switzerland", "it_ch", 0x0810),
	LANG("Japanese", "ja", 0x0411),
	LANG("Korean", "ko", 0x0412),
	LANG("Latvian", "lv", 0x0426),
	LANG("Lithuanian", "lt", 0x0427),
	LANG("F.Y.R.O. Macedonia", "mk", 0x042F),
	LANG("Malay - Malaysia", "ms_my", 0x043E),
	LANG("Malay – Brunei", "ms_bn", 0x083E),
	LANG("Maltese", "mt", 0x043A),
	LANG("Marathi", "mr", 0x044E),
	LANG("Norwegian - Bokml", "no_no", 0x0414),
	LANG("Norwegian - Nynorsk", "no_no", 0x0814),
	LANG("Polish", "pl", 0x0415),
	LANG("Portuguese - Portugal", "pt_pt", 0x0816),
	LANG("Portuguese - Brazil", "pt_br", 0x0416),
	LANG("Raeto-Romance", "rm", 0x0417),
	LANG("Romanian - Romania", "ro", 0x0418),
	LANG("Romanian - Republic of Moldova", "ro_mo", 0x0818),
	LANG("Russian", "ru", 0x0419),
	LANG("Russian - Republic of Moldova", "ru_mo", 0x0819),
	LANG("Sanskrit", "sa", 0x044F),
	LANG("Serbian - Cyrillic", "sr_sp", 0x0C1A),
	LANG("Serbian - Latin", "sr_sp", 0x081A),
	LANG("Setsuana", "tn", 0x0432),
	LANG("Slovenian", "sl", 0x0424),
	LANG("Slovak", "sk", 0x041B),
	LANG("Sorbian", "sb", 0x042E),
	LANG("Spanish - Spain (Traditional)", "es_es", 0x040A),
	LANG("Spanish - Argentina", "es_ar", 0x2C0A),
	LANG("Spanish - Bolivia", "es_bo", 0x400A),
	LANG("Spanish - Chile", "es_cl", 0x340A),
	LANG("Spanish - Colombia", "es_co", 0x240A),
	LANG("Spanish - Costa Rica", "es_cr", 0x140A),
	LANG("Spanish - Dominican Republic", "es_do", 0x1C0A),
	LANG("Spanish - Ecuador", "es_ec", 0x300A),
	LANG("Spanish - Guatemala", "es_gt", 0x100A),
	LANG("Spanish - Honduras", "es_hn", 0x480A),
	LANG("Spanish - Mexico", "es_mx", 0x080A),
	LANG("Spanish - Nicaragua", "es_ni", 0x4C0A),
	LANG("Spanish - Panama", "es_pa", 0x180A),
	LANG("Spanish - Peru", "es_pe", 0x280A),
	LANG("Spanish - Puerto Rico", "es_pr", 0x500A),
	LANG("Spanish - Paraguay", "es_py", 0x3C0A),
	LANG("Spanish - El Salvador", "es_sv", 0x440A),
	LANG("Spanish - Uruguay", "es_uy", 0x380A),
	LANG("Spanish - Venezuela", "es_ve", 0x200A),
	LANG("Southern Sotho", "st", 0x0430),
	LANG("Swahili", "sw", 0x0441),
	LANG("Swedish - Sweden", "sv_se", 0x041D),
	LANG("Swedish - Finland", "sv_fi", 0x081D),
	LANG("Tamil", "ta", 0x0449),
	LANG("Tatar", "tt", 0X0444),
	LANG("Thai", "th", 0x041E),
	LANG("Turkish", "tr", 0x041F),
	LANG("Tsonga", "ts", 0x0431),
	LANG("Ukrainian", "uk", 0x0422),
	LANG("Urdu", "ur", 0x0420),
	LANG("Uzbek - Cyrillic", "uz_uz", 0x0843),
	LANG("Uzbek – Latin", "uz_uz", 0x0443),
	LANG("Vietnamese", "vi", 0x042A),
	LANG("Xhosa", "xh", 0x0434),
	LANG("Yiddish", "yi", 0x043D),
	LANG("Zulu", "zu", 0x0435),
	LANG(NULL, NULL, 0x0),	
};

uint16_t get_usb_code_for_current_locale(void)
{
	char *locale;
	char search_string[64];
	char *ptr;
	
	/* Get the current locale. */
	locale = setlocale(0, NULL);
	if (!locale)
		return 0x0;
	
	/* Make a copy of the current locale string. */
	strncpy(search_string, locale, sizeof(search_string));
	search_string[sizeof(search_string)-1] = '\0';
	
	/* Chop off the encoding part, and make it lower case. */
	ptr = search_string;
	while (*ptr) {
		*ptr = tolower(*ptr);
		if (*ptr == '.') {
			*ptr = '\0';
			break;
		}
		ptr++;
	}

	/* Find the entry which matches the string code of our locale. */
	struct lang_map_entry *lang = lang_map;
	while (lang->string_code) {
		if (!strcmp(lang->string_code, search_string)) {
			return lang->usb_code;
		}	
		lang++;
	}
	
	/* There was no match. Find with just the language only. */
	/* Chop off the variant. Chop it off at the '_'. */
	ptr = search_string;
	while (*ptr) {
		*ptr = tolower(*ptr);
		if (*ptr == '_') {
			*ptr = '\0';
			break;
		}
		ptr++;
	}
	
#if 0 // TODO: Do we need this?
	/* Find the entry which matches the string code of our language. */
	lang = lang_map;
	while (lang->string_code) {
		if (!strcmp(lang->string_code, search_string)) {
			return lang->usb_code;
		}	
		lang++;
	}
#endif
	
	/* Found nothing. */
	return 0x0;
}

#ifdef __cplusplus
}
#endif


struct report {
	int length;
	char buffer[REPORT_SIZE];
};

struct pie_device {
	int handle;

	/* HIDAPI objects */
	hid_device *dev;
	char *path;
	
	/* PieHid Configuration Options */
	int suppress_duplicate_reports;
	int disable_data_callback;
	
	/* Thread Objects and data */
	pthread_t read_thread;
	pthread_t callback_thread;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	volatile int shutdown;
	
	/* Data Ring Buffer */
	struct report *buffer;
	int front_of_buffer; /* next report to give to the application */
	int back_of_buffer;  /* points to one slot after the last report read from hardware */

	/* The last report received */
	struct report last_report;

	/* Callbacks */
	PHIDDataEvent data_event_callback;
	PHIDErrorEvent error_event_callback;
};

static struct pie_device pie_devices[MAX_XKEY_DEVICES];

static int cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime, const struct pie_device *pd);
static int return_data(struct pie_device *pd, unsigned char *data);

struct device_map_entry {
    unsigned short vid;
    unsigned short pid;
    int interface_number;
    unsigned short usage_page;
    unsigned short usage;
};

static bool get_usage(unsigned short vid, unsigned short pid,
                      int interface_number,
                      unsigned short *usage_page,
                      unsigned short *usage);


unsigned int PIE_HID_CALL EnumeratePIE(long VID, TEnumHIDInfo *info, long *count)
{
	struct hid_device_info *cur;
	struct hid_device_info *hi;
	int i;

	/* Clear out the devices array */
	for (i = 0; i < MAX_XKEY_DEVICES; i++) {
		struct pie_device *pd = &pie_devices[i];
		if (pd->dev) {
			CloseInterface(i);
			hid_close(pd->dev);
		}
		free(pd->path);		
	}
	memset(&pie_devices, 0, sizeof(pie_devices));
	for (i = 0; i < MAX_XKEY_DEVICES; i++) {
		struct pie_device *pd = &pie_devices[i];
		pd->handle = i;
	}
	
		
	hi = hid_enumerate(0x0, 0x0);
	
	*count = 0;

	/* Pack the return data, and set up our pie_devices array. */
	cur = hi;
	while (cur && *count < MAX_XKEY_DEVICES) {
		if (cur->vendor_id != PI_VID) {
			printf("Continuing, vid: %hx pivid: %hx\n", cur->vendor_id, (unsigned short)PI_VID);
			cur = cur->next;
			continue;
		}
		
		/* Get the Usage and Usage Page from a table. This is because
		   it's not possible to get this information on all recent
		   versions of Linux without claiming an interface, and thus
		   severely disrupting the system. */
		unsigned short usage_page = -1;
		unsigned short usage = -1;
		bool res = get_usage(PI_VID, cur->product_id,
		                     cur->interface_number,
		                     &usage_page, &usage);
		if (!res) {
			usage_page = -1;
			usage = -1;
		}

		TEnumHIDInfo *inf = &info[*count];
		inf->PID = cur->product_id;
		inf->Usage = usage;
		inf->UP = usage_page;
		inf->readSize = 33;
		inf->writeSize = 36;
		strncpy(inf->DevicePath, cur->path, sizeof(inf->DevicePath));
		inf->DevicePath[sizeof(inf->DevicePath)-1] = '\0';
		inf->Handle = *count;
		inf->Version = cur->release_number;
		inf->ManufacturerString[0] = '\0';
		inf->ProductString[0] = '\0';

		struct pie_device *pd = &pie_devices[*count];
		pd->path = cur->path;
		(*count)++;
		cur = cur->next;
	}

	return 0;
}


unsigned int PIE_HID_CALL GetXKeyVersion(long hnd)
{
	return 0;
}


/* Make a timespec for the specified number of milliseconds in the future. */
static void make_timeout(struct timespec *ts, int milliseconds)
{
	clock_gettime(CLOCK_REALTIME, ts);
	ts->tv_sec += milliseconds / 1000;
	ts->tv_nsec += (milliseconds % 1000) * 1000000; //convert to ns
	if (ts->tv_nsec >= 1000000000L) {
		ts->tv_nsec -= 1000000000L;
		ts->tv_sec += 1;
	}
}

static void cleanup_mutex(void *param)
{
	struct pie_device *pd = param;
	pthread_mutex_unlock(&pd->mutex);
}

static void *read_thread(void *param)
{
	struct pie_device *pd = param;
	char buf[80];
	buf[0] = 0x0;
	
	while (!pd->shutdown) {
		int res = hid_read(pd->dev, (unsigned char*)buf, sizeof(buf));
		if (res > 0) {
			int is_empty = 0;
			int wake_up_waiters = 0;
			int skip = 0;
			
			pthread_mutex_lock(&pd->mutex);
			pthread_cleanup_push(&cleanup_mutex, pd)
			
			/* Check if this is the same as the last report
			   received (ie: if it's a duplicate). */
			if (res == pd->last_report.length &&
			    memcmp(buf, pd->last_report.buffer, res) == 0)
			{
				if (pd->suppress_duplicate_reports)
					skip = 1;
			}
			
			if (!skip) {
				/* See if this is going into an empty buffer */
				if (pd->front_of_buffer == pd->back_of_buffer)
					wake_up_waiters = 1;
					
				/* Put this report at the end of the buffer
				   Add an extra byte at the beginning for the
				   report number. */
				int new_position = pd->back_of_buffer;
				struct report *rpt = &pd->buffer[new_position];
				memcpy(rpt->buffer+1, buf, res);
				rpt->length = res+1;

				/* Increment the back-of-buffer pointer, moving
				   the front-of-buffer pointer if we've overflowed. */
				new_position += 1;
				new_position %= BUFFER_LENGTH;
				if (new_position == pd->front_of_buffer) {
					/* Buffer is full. Lose the first one, and
					   consider the next one the front. */
					pd->front_of_buffer++;
					pd->front_of_buffer %= BUFFER_LENGTH;
				}
				pd->back_of_buffer = new_position;
				
				/* If the buffer was empty, wake up any waiting
				   threads which may be waiting on data. */
				if (wake_up_waiters) {
					pthread_cond_signal(&pd->cond);
				}
				
				/* Save this report as the last one received. */
				memcpy(pd->last_report.buffer, buf, res);
				pd->last_report.length = res;
			}

			pthread_mutex_unlock(&pd->mutex);
			pthread_cleanup_pop(0);
			
		}
		else if (res < 0) {
			/* An error occurred, possibly a device disconnect,
			   or the handle was closed from a different thread.
			   Break out of this loop and end this thread. */
			
			if (pd->error_event_callback) {
				pd->error_event_callback(pd->handle, PIE_HID_READ_BAD_INTERFACE_HANDLE);
			}
			
			/* Break out of this loop. */
			pd->shutdown = 1;
		}
	}

	/* Wake up anyone waiting on data. Do this under a mutex so that
	   any thread which may be about to sleep will actually go to sleep
	   before the broadcast is called here to wake them up. */
	pthread_mutex_lock(&pd->mutex);
	pthread_cond_broadcast(&pd->cond);
	pthread_mutex_unlock(&pd->mutex);
	
	return NULL;
}

static void *callback_thread(void *param)
{
	struct pie_device *pd = param;
	char buf[80];
	
	while (!pd->shutdown) {
		/* Wait for data to become available. */
		pthread_mutex_lock(&pd->mutex);
		pthread_cleanup_push(&cleanup_mutex, pd);
		while (pd->front_of_buffer == pd->back_of_buffer) {
			/* No data available. Sleep until there is. */
			int res = pthread_cond_wait(&pd->cond, &pd->mutex);
			if (res != 0) {
				if (pd->error_event_callback)
					pd->error_event_callback(pd->handle, PIE_HID_WRITE_UNABLE_TO_ACQUIRE_MUTEX);
				
				/* Something failed. Re-acquire the
				   mutex and try again. This is a pretty
				   serious error and will probably never
				   happen. */
				pthread_mutex_lock(&pd->mutex);
			}
			
			if (pd->shutdown)
				break;

			/* If we're here, then there is either data, or
			   there was a spurious wakeup, or there was an
			   error. Either way, try to run the loop again.
			   The loop will fall out if there is data. */
		}

		/* We came out of the wait, so there either data
		   available or a shutdown was called for. */

		if (!pd->shutdown && pd->data_event_callback && !pd->disable_data_callback) {
			if (pd->front_of_buffer != pd->back_of_buffer) {
				/* There is data available. Copy it to buf. */
				return_data(pd, buf);

				/* Call the callback. */
				pd->data_event_callback(buf, pd->handle, 0);
			}
		}

		pthread_mutex_unlock(&pd->mutex);
		pthread_cleanup_pop(0);
	}
	
	return NULL;
}

unsigned int PIE_HID_CALL SetupInterfaceEx(long hnd)
{
	int res;
	int ret_val = 0;
	
	if (hnd >= MAX_XKEY_DEVICES)
		return PIE_HID_SETUP_BAD_HANDLE;
	
	struct pie_device *pd = &pie_devices[hnd];

	/* Open the device */
	pd->dev = hid_open_path(pd->path);
	if (!pd->dev) {
		ret_val = PIE_HID_SETUP_CANNOT_OPEN_READ_HANDLE;
		goto err_open_path;
	}
	
	/* Create the buffer */
	pd->buffer = calloc(BUFFER_LENGTH, sizeof(struct report));
	if (!pd->buffer) {
		ret_val = PIE_HID_SETUP_CANNOT_ALLOCATE_MEM_FOR_RING;
		goto err_alloc_buffer;
	}
	
	/* Create the mutex */
	res = pthread_mutex_init(&pd->mutex, NULL);
	if (res != 0) {
		ret_val = PIE_HID_SETUP_CANNOT_CREATE_MUTEX;
		goto err_create_mutex;
	}
	
	/* Create the condition */
	res = pthread_cond_init(&pd->cond, NULL);
	if (res != 0) {
		ret_val = PIE_HID_SETUP_CANNOT_CREATE_MUTEX;
		goto err_create_cond;
	}
	
	/* Start the Read thread */
	res = pthread_create(&pd->read_thread, NULL, &read_thread, pd);
	if (res != 0) {
		ret_val = PIE_HID_SETUP_CANNOT_CREATE_READ_THREAD;
		goto err_create_read_thread;
	}

	/* Start the Callback thread */
	res = pthread_create(&pd->callback_thread, NULL, &callback_thread, pd);
	if (res != 0) {
		ret_val = PIE_HID_SETUP_CANNOT_CREATE_READ_THREAD;
		goto err_create_callback_thread;
	}
	
	/* Set Default parameters */
	pd->suppress_duplicate_reports = true;
	pd->disable_data_callback = false;
	
	return ret_val;
	
	
err_create_callback_thread:
	pd->shutdown = 1;
	pthread_join(pd->read_thread, NULL);
err_create_read_thread:
	pthread_cond_destroy(&pd->cond);
err_create_cond:
	pthread_mutex_destroy(&pd->mutex);
err_create_mutex:
	free(pd->buffer);
err_alloc_buffer:
	hid_close(pd->dev);
err_open_path:

	return ret_val;
}

void  PIE_HID_CALL CloseInterface(long hnd)
{
	if (hnd >= MAX_XKEY_DEVICES)
		return;
	
	struct pie_device *pd = &pie_devices[hnd];

	/* Stop the threads. pthread_cancel will stop the threads once
	   they get to a cancellation point. In this case the
	   pthread_cond_*wait() function (inside hid-libusb.c) is where
	   they will be cancelled. Once stopped, they will call their
	   respective cancellation handlers which will release the mutexes
	   if necessary. */
	pd->shutdown = 1;
	pthread_cancel(pd->callback_thread);
	pthread_cancel(pd->read_thread);

	/* Wait for the threds to stop */
	pthread_join(pd->callback_thread, NULL);
	pthread_join(pd->read_thread, NULL);
	
	/* Destroy the condition */
	pthread_cond_destroy(&pd->cond);

	/* Destroy the mutex */
	pthread_mutex_destroy(&pd->mutex);
	
	/* Close the device handle */
	hid_close(pd->dev);
	pd->dev = NULL;

	/* Free the buffer */
	free(pd->buffer);
	pd->buffer = NULL;
}

void  PIE_HID_CALL CleanupInterface(long hnd)
{
	CloseInterface(hnd);
}

static int return_data(struct pie_device *pd, unsigned char *data)
{
	/* Return the first report in the queue. */
	struct report *rpt = &pd->buffer[pd->front_of_buffer];
	memcpy(data, rpt->buffer, rpt->length);
	
	/* Increment the front of buffer pointer. */
	pd->front_of_buffer++;
	if (pd->front_of_buffer >= BUFFER_LENGTH)
		pd->front_of_buffer = 0;
}

unsigned int PIE_HID_CALL ReadData(long hnd, unsigned char *data)
{
	if (hnd >= MAX_XKEY_DEVICES)
		return PIE_HID_READ_BAD_INTERFACE_HANDLE;
	
	struct pie_device *pd = &pie_devices[hnd];
	
	pthread_mutex_lock(&pd->mutex);
	
	/* Return early if there is no data available */
	if (pd->front_of_buffer == pd->back_of_buffer) {
		/* No data available. */
		pthread_mutex_unlock(&pd->mutex);
		return PIE_HID_READ_INSUFFICIENT_DATA;
	}

	return_data(pd, data);

	pthread_mutex_unlock(&pd->mutex);
	
	return 0;	
}

static int cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *abstime, const struct pie_device *pd)
{
	while (pd->front_of_buffer == pd->back_of_buffer && !pd->shutdown) {
		int res = pthread_cond_timedwait(cond, mutex, abstime);
		if (res == ETIMEDOUT)
			return res;
		if (res != 0)
			return res;
		/* A res of 0 means we may have been signaled or it may
		   be a spurious wakeup. Check to see that there's acutally
		   data in the queue before returning, and if not, go back
		   to sleep. See the pthread_cond_timedwait() man page for
		   details. */
	}
	
	return 0;
}

unsigned int PIE_HID_CALL BlockingReadData(long hnd, unsigned char *data, int maxMillis)
{
	if (hnd >= MAX_XKEY_DEVICES)
		return PIE_HID_READ_BAD_INTERFACE_HANDLE;
	
	struct pie_device *pd = &pie_devices[hnd];
	
	pthread_mutex_lock(&pd->mutex);
	
	/* Go to sleep if there is no data available */
	if (pd->front_of_buffer == pd->back_of_buffer) {
		/* No data available. Sleep until there is. */
		struct timespec abstime;
		make_timeout(&abstime, maxMillis);
		
		int res = cond_timedwait(&pd->cond, &pd->mutex, &abstime, pd);
		if (res == ETIMEDOUT) {
			pthread_mutex_unlock(&pd->mutex);
			return PIE_HID_READ_INSUFFICIENT_DATA;
		}
		else if (res != 0) {
			return PIE_HID_READ_CANNOT_ACQUIRE_MUTEX;
		}
	}

	/* If we got to this point, there is either data here or there was
	   an error. In either case, this thread is holding the mutex. */
	   
	if (pd->front_of_buffer != pd->back_of_buffer)
		return_data(pd, data);
        
	pthread_mutex_unlock(&pd->mutex);
	
	return 0;
}

unsigned int PIE_HID_CALL WriteData(long hnd, unsigned char *data)
{
	if (hnd >= MAX_XKEY_DEVICES)
		return PIE_HID_WRITE_BAD_HANDLE;
	
	struct pie_device *pd = &pie_devices[hnd];
	
	int res = hid_write(pd->dev, data, GetWriteLength(hnd));
	if (res < 0)
		return PIE_HID_WRITE_FAILED;
	if (res != GetWriteLength(hnd))
		return PIE_HID_WRITE_INCOMPLETE;
	
	return 0;
}

unsigned int PIE_HID_CALL FastWrite(long hnd, unsigned char *data)
{
	return WriteData(hnd, data);
}

unsigned int PIE_HID_CALL ReadLast(long hnd, unsigned char *data)
{
	if (hnd >= MAX_XKEY_DEVICES)
		return PIE_HID_READ_BAD_INTERFACE_HANDLE;

	struct pie_device *pd = &pie_devices[hnd];
	
	pthread_mutex_lock(&pd->mutex);

	/* If the buffer is empty, return insufficient data. */
	if (pd->front_of_buffer == pd->back_of_buffer) {
		pthread_mutex_unlock(&pd->mutex);
		return PIE_HID_READ_INSUFFICIENT_DATA;
	}
	
	/* Find the last item in the buffer. */
	int last = pd->back_of_buffer - 1;
	if (last < 0)
		last = BUFFER_LENGTH -1;
	
	/* Return the first report in the queue. */
	struct report *rpt = &pd->buffer[last];
	memcpy(data, rpt->buffer, rpt->length);
	
	pthread_mutex_unlock(&pd->mutex);
	
	return 0;
}

unsigned int PIE_HID_CALL ClearBuffer(long hnd)
{
	if (hnd >= MAX_XKEY_DEVICES)
		return PIE_HID_CLEARBUFFER_BAD_HANDLE;

	struct pie_device *pd = &pie_devices[hnd];

	pthread_mutex_lock(&pd->mutex);
	pd->front_of_buffer = 0;
	pd->back_of_buffer = 0;
	pthread_mutex_unlock(&pd->mutex);
}


unsigned int PIE_HID_CALL GetReadLength(long hnd)
{
	return 33;
}

unsigned int PIE_HID_CALL GetWriteLength(long hnd)
{
	return 36;
}
unsigned int PIE_HID_CALL SetDataCallback(long hnd, PHIDDataEvent pDataEvent)
{
	if (hnd >= MAX_XKEY_DEVICES)
		return PIE_HID_DATACALLBACK_BAD_HANDLE;
	
	struct pie_device *pd = &pie_devices[hnd];
	
	pd->data_event_callback = pDataEvent;	
	
	return 0;
}

unsigned int PIE_HID_CALL SetErrorCallback(long hnd, PHIDErrorEvent pErrorCall)
{
	if (hnd >= MAX_XKEY_DEVICES)
		return PIE_HID_ERRORCALLBACK_BAD_HANDLE;
	
	struct pie_device *pd = &pie_devices[hnd];
	
	pd->error_event_callback = pErrorCall;

	return 0;
}

void PIE_HID_CALL SuppressDuplicateReports(long hnd,bool supp)
{
	if (hnd >= MAX_XKEY_DEVICES)
		return;

	struct pie_device *pd = &pie_devices[hnd];
	
	pd->suppress_duplicate_reports = supp;
}

void PIE_HID_CALL DisableDataCallback(long hnd,bool disable)
{
	if (hnd >= MAX_XKEY_DEVICES)
		return;

	struct pie_device *pd = &pie_devices[hnd];
	
	pd->disable_data_callback = disable;
}

bool PIE_HID_CALL IsDataCallbackDisabled(long hnd)
{
	if (hnd >= MAX_XKEY_DEVICES)
		return false;

	struct pie_device *pd = &pie_devices[hnd];
	
	return pd->disable_data_callback;
}

bool PIE_HID_CALL GetSuppressDuplicateReports(long hnd)
{
	if (hnd >= MAX_XKEY_DEVICES)
		return false;
	
	struct pie_device *pd = &pie_devices[hnd];
	
	return pd->suppress_duplicate_reports;
}


void PIE_HID_CALL GetErrorString(int err, char* out_str, int size)
{
	const char *str = NULL;

	switch (err) {
	case PIE_HID_ENUMERATE_BAD_HID_DEVICE:
		str = "101 Bad HID device information set handle";
		break;
	case PIE_HID_ENUMERATE_NO_DEVICES_FOUND:
		str = "102 No devices found.";
		break;
	case PIE_HID_ENUMERATE_OTHER_ENUM_ERROR:
		str = "103 Bad error";
		break;
	case PIE_HID_ENUMERATE_ERROR_GETTING_DEVICE_DETAIL:
		str = "104 Error interface detail (required size)";
		break;
	case PIE_HID_ENUMERATE_ERROR_GETTING_DEVICE_DETATIL2:
		str = "105 Error getting device interface detail.";
		break;
	case PIE_HID_ENUMERATE_UNABLE_TO_OPEN_HANDLE:
		str = "106 CreateFile error.";
		break;
	case PIE_HID_ENUMERATE_GET_ATTRIBUTES_ERROR:
		str = "107 HidD_GetAttributes error";
		break;
	case PIE_HID_ENUMERATE_VENDOR_ID_ERROR:
		str = "108 VendorID not VID";
		break;
	case PIE_HID_ENUMERATE_GET_PREPARSED_DATA_ERROR:
		str = "109 HidD_GetPreparsedData error";
		break;
	case PIE_HID_ENUMERATE_GET_CAPS:
		str = "110 HidP_GetCaps error";
		break;
	case PIE_HID_ENUMERATE_GET_MANUFACTURER_STRING:
		str = "111 HidD_GetManufacturerString error";
		break;
	case PIE_HID_ENUMERATE_GET_PRODUCT_STRING:
		str = "112 HidD_GetProductString error";
		break;
	case PIE_HID_SETUP_BAD_HANDLE:
		str = "201 Bad interface handle";
		break;
	case PIE_HID_SETUP_CANNOT_ALLOCATE_MEM_FOR_RING:
		str = "202 Interface Already Set";
		break;
	case PIE_HID_SETUP_CANNOT_CREATE_MUTEX:
		str = "203 Cannot Create Mutex";
		break;
	case PIE_HID_SETUP_CANNOT_CREATE_READ_THREAD:
		str = "204 Cannot Create Read Thread";
		break;
	case PIE_HID_SETUP_CANNOT_OPEN_READ_HANDLE:
		str = "205 Cannot open read handle";
		break;
	case PIE_HID_SETUP_CANNOT_OPEN_READ_HANDLE_ACCESS_DENIED:
		str = "206 No read handle - Access Denied";
		break;
	case PIE_HID_SETUP_CANNOT_OPEN_READ_HANDLE_BAD_PATH:
		str = "207 No read handle - bad DevicePath"; 
		break;
	case PIE_HID_SETUP_CANNOT_OPEN_WRITE_HANDLE:
		str = "208 Cannot open write handle";
		break;
	case PIE_HID_SETUP_CANNOT_OPEN_WRITE_HANDLE_ACCESS_DENIED:
		str = "209 No write handle - Access Denied";
		break;
	case PIE_HID_SETUP_CANNOT_OPEN_WRITE_HANDLE_BAD_PATH:
		str = "210 No write handle - bad DevicePath"; 
		break;
	case PIE_HID_READ_BAD_INTERFACE_HANDLE:
		str = "301 Bad interface handle";
		break;
	case PIE_HID_READ_LENGTH_ZERO:
		str = "302 readSize is zero";
		break;
	case PIE_HID_READ_CANNOT_ACQUIRE_MUTEX:
		str = "303 Interface not valid";
		break;
	case PIE_HID_READ_INSUFFICIENT_DATA:
		str = "304 Ring buffer empty.";
		break;
	case PIE_HID_READ_CANNOT_RELEASE_MUTEX:
		str = "305 Cannot Release Mutex.";
		break;
	case PIE_HID_READ_CANNOT_RELEASE_MUTEX2:
		str = "306 Cannot Release Mutex.";
		break;
	case PIE_HID_READ_INVALID_HANDLE:
		str = "307 Invalid Handle.";
		break;
	case PIE_HID_READ_DEVICE_DISCONNECTED:
		str = "308 Device disconnected";
		break;
	case PIE_HID_READ_READ_ERROR:
		str = "309 Read error. ( unplugged )";
		break;
	case PIE_HID_READ_BYTES_NOT_EQUAL_READSIZE:
		str = "310 Bytes read not equal readSize";
		break;
	case PIE_HID_READ_BLOCKING_READ_DATA_TIMED_OUT:
		str = "311 BlockingReadData timed out.";
		break;
	case PIE_HID_WRITE_BAD_HANDLE:
		str = "401 Bad interface handle";
		break;
	case PIE_HID_WRITE_LENGTH_ZERO:
		str = "402 Write length is zero";
		break;
	case PIE_HID_WRITE_FAILED:
		str = "403 Bad internal interface handle ";
		break;
	case PIE_HID_WRITE_INCOMPLETE:
		str = "404 Write Incomplete";
		break;
	case PIE_HID_WRITE_UNABLE_TO_ACQUIRE_MUTEX:
		str = "405 No write buffer";
		break;
	case PIE_HID_WRITE_UNABLE_TO_RELEASE_MUTEX:
		str = "406 Write size equals zero";
		break;
	case PIE_HID_WRITE_HANDLE_INVALID:
		str = "407 No writeBuffer";
		break;
	case PIE_HID_WRITE_BUFFER_FULL:
		str = "408 Write buffer full";
		break;
	case PIE_HID_WRITE_PREV_WRITE_FAILED:
		str = "409 Previous Write Failed";
		break;
	case PIE_HID_WRITE_PREV_WRITE_WRONG_NUMBER:
		str = "410 byteCount != writeSize";
		break;
	case PIE_HID_WRITE_TIMER_FAILED:
		str = "411 Timed out in write.";
		break;
	case PIE_HID_WRITE_PREV_WRITE_UNABLE_TO_RELEASE_MUTEX:
		str = "412 Unable to Release Mutex";
		break;
	case PIE_HID_WRITE_BUFFER_FULL2:
		str = "413 Write Buffer Full";
		break;
	case PIE_HID_WRITE_FAST_WRITE_ERROR:
		str = "414 Fast Write Error";
		break;
	case PIE_HID_READLAST_BAD_HANDLE:
		str = "501 Bad interface handle";
		break;
	case PIE_HID_READLAST_LENGTH_ZERO:
		str = "502 Read length is zero";
		break;
	case PIE_HID_READLAST_UNABLE_TO_ACQUIRE_MUTEX:
		str = "503 Unable to acquire mutex";
		break;
	case PIE_HID_READLAST_INSUFFICIENT_DATA:
		str = "504 No data yet.";
		break;
	case PIE_HID_READLAST_UNABLE_TO_RELEASE_MUTEX:
		str = "505 Unable to release Mutex";
		break;
	case PIE_HID_READLAST_UNABLE_TO_RELEASE_MUTEX2:
		str = "506 Unable to release Mutex";
		break;
	case PIE_HID_READLAST_INVALID_HANDLE:
		str = "507 ReadLast() Invalid Handle";
		break;
	case PIE_HID_CLEARBUFFER_BAD_HANDLE:
		str = "601 Bad interface handle";
		break;
	case PIE_HID_CLEARBUFFER_UNABLE_TO_RELEASE_MUTEX:
		str = "602 Unable to release mutex";
		break;
	case PIE_HID_CLEARBUFFER_UNABLE_TO_ACQUIRE_MUTEX:
		str = "603 Unable to acquire mutex.";
		break;
	case PIE_HID_DATACALLBACK_BAD_HANDLE:
		str = "701 Bad interface handle";
		break;
	case PIE_HID_DATACALLBACK_INVALID_INTERFACE:
		str = "702 Interface not valid";
		break;
	case PIE_HID_DATACALLBACK_CANNOT_CREATE_CALLBACK_THREAD:
		str = "703 Could not create event thread.";
		break;
	case PIE_HID_DATACALLBACK_CALLBACK_ALREADY_SET:
		str = "704 Callback already set.";
		break;
	case PIE_HID_ERRORCALLBACK_BAD_HANDLE:
		str = "801 Bad interface handle";
		break;
	case PIE_HID_ERRORCALLBACK_INVALID_INTERFACE:
		str = "802 Interface not valid";
		break;
	case PIE_HID_ERRORCALLBACK_CANNOT_CREATE_ERROR_THREAD:
		str = "803 Could not create error thread.";
		break;
	case PIE_HID_ERRORCALLBACK_ERROR_THREAD_ALREADY_CREATED:
		str = "1804 Error thread already created";
		break;
	default:
		str = "Unknown error code";
		break;
	}

	strncpy(out_str, str, size);
	out_str[size-1] = '\0';
}


#define DEVICE_MAP_ENTRY(vid, pid, interface, usage_page, usage) \
    { vid, pid, interface, usage_page, usage,},

static const struct device_map_entry device_map[] = {
	DEVICE_MAP_ENTRY(PI_VID, 0x0405, 0, 0x000c, 0x0001) /* XK-24 splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0405, 1, 0x0001, 0x0006) /* XK-24 keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0405, 2, 0x0001, 0x0002) /* XK-24 mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0404, 0, 0x000c, 0x0001) /* XK-24 splat write only*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0404, 1, 0x0001, 0x0006) /* XK-24 keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0404, 2, 0x0001, 0x0004) /* XK-24 joystick*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0404, 3, 0x0001, 0x0002) /* XK-24 mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0403, 0, 0x000c, 0x0001) /* XK-24 splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0403, 1, 0x0001, 0x0006) /* XK-24 keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0403, 2, 0x0001, 0x0004) /* XK-24 joystick*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0406, 0, 0x000c, 0x0001) /* Pi3 Matrix Board splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0406, 1, 0x0001, 0x0006) /* Pi3 Matrix Board keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0406, 2, 0x0001, 0x0002) /* Pi3 Matrix Board mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0407, 0, 0x000c, 0x0001) /* Pi3 Matrix Board splat write only*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0407, 1, 0x0001, 0x0006) /* Pi3 Matrix Board keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0407, 2, 0x0001, 0x0004) /* Pi3 Matrix Board joystick*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0407, 3, 0x0001, 0x0002) /* Pi3 Matrix Board mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0408, 0, 0x000c, 0x0001) /* Pi3 Matrix Board splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0408, 1, 0x0001, 0x0006) /* Pi3 Matrix Board keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0408, 2, 0x0001, 0x0004) /* Pi3 Matrix Board joystick*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0410, 0, 0x000c, 0x0001) /* MultiBoard 192 splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0410, 1, 0x0001, 0x0006) /* MultiBoard 192 keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0410, 2, 0x0001, 0x0002) /* MultiBoard 192 mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0411, 0, 0x000c, 0x0001) /* MultiBoard 192 splat write only*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0411, 1, 0x0001, 0x0006) /* MultiBoard 192 keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0411, 2, 0x0001, 0x0004) /* MultiBoard 192 joystick*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0411, 3, 0x0001, 0x0002) /* MultiBoard 192 mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0412, 0, 0x000c, 0x0001) /* MultiBoard 192 splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0412, 1, 0x0001, 0x0006) /* MultiBoard 192 keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0412, 2, 0x0001, 0x0004) /* MultiBoard 192 joystick*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0413, 0, 0x000c, 0x0001) /* MultiBoard 256 splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0413, 1, 0x0001, 0x0006) /* MultiBoard 256 keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0413, 2, 0x0001, 0x0002) /* MultiBoard 256 mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0414, 0, 0x000c, 0x0001) /* MultiBoard 256 splat write only*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0414, 1, 0x0001, 0x0006) /* MultiBoard 256 keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0414, 2, 0x0001, 0x0004) /* MultiBoard 256 joystick*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0414, 3, 0x0001, 0x0002) /* MultiBoard 256 mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0415, 0, 0x000c, 0x0001) /* MultiBoard 256 splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0415, 1, 0x0001, 0x0006) /* MultiBoard 256 keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0415, 2, 0x0001, 0x0004) /* MultiBoard 256 joystick*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0419, 0, 0x000c, 0x0001) /* XK-16 splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0419, 1, 0x0001, 0x0006) /* XK-16 keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0419, 2, 0x0001, 0x0002) /* XK-16 mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x041A, 0, 0x000c, 0x0001) /* XK-16 splat write only*/
	DEVICE_MAP_ENTRY(PI_VID, 0x041A, 1, 0x0001, 0x0006) /* XK-16 keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x041A, 2, 0x0001, 0x0004) /* XK-16 joystick*/
	DEVICE_MAP_ENTRY(PI_VID, 0x041A, 3, 0x0001, 0x0002) /* XK-16 mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x041B, 0, 0x000c, 0x0001) /* XK-16 splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x041B, 1, 0x0001, 0x0006) /* XK-16 keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x041B, 2, 0x0001, 0x0004) /* XK-16 joystick*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x041F, 0, 0x000c, 0x0001) /* ShipDriver read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x041F, 1, 0x0001, 0x0006) /* ShipDriver keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x041F, 2, 0x0001, 0x0004) /* ShipDriver joystick*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0423, 0, 0x000c, 0x0001) /* XK-128 splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0423, 1, 0x0001, 0x0006) /* XK-128 keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0423, 2, 0x0001, 0x0002) /* XK-128 mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0424, 0, 0x000c, 0x0001) /* XK-128 splat write only*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0424, 1, 0x0001, 0x0006) /* XK-128 keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0424, 2, 0x0001, 0x0004) /* XK-128 joystick*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0424, 3, 0x0001, 0x0002) /* XK-128 mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0425, 0, 0x000c, 0x0001) /* XK-128 read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0425, 1, 0x0001, 0x0006) /* XK-128 keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0425, 2, 0x0001, 0x0004) /* XK-128 joystick*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0426, 0, 0x000c, 0x0001) /* XK-12 Jog & Shuttle splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0426, 1, 0x0001, 0x0006) /* XK-12 Jog & Shuttle keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0426, 2, 0x0001, 0x0002) /* XK-12 Jog & Shuttle mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0427, 0, 0x000c, 0x0001) /* XK-12 Jog & Shuttle splat write only*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0427, 1, 0x0001, 0x0006) /* XK-12 Jog & Shuttle keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0427, 2, 0x0001, 0x0004) /* XK-12 Jog & Shuttle joystick*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0427, 3, 0x0001, 0x0002) /* XK-12 Jog & Shuttle mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0428, 0, 0x000c, 0x0001) /* XK-12 Jog & Shuttle read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0428, 1, 0x0001, 0x0006) /* XK-12 Jog & Shuttle keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0428, 2, 0x0001, 0x0004) /* XK-12 Jog & Shuttle joystick*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0429, 0, 0x000c, 0x0001) /* XK-12 Joystick splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0429, 1, 0x0001, 0x0006) /* XK-12 Joystick keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0429, 2, 0x0001, 0x0004) /* XK-12 Joystick joystick*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x042A, 0, 0x000c, 0x0001) /* XK-12 Joystick splat write only*/
	DEVICE_MAP_ENTRY(PI_VID, 0x042A, 1, 0x0001, 0x0006) /* XK-12 Joystick keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x042A, 2, 0x0001, 0x0004) /* XK-12 Joystick joystick*/
	DEVICE_MAP_ENTRY(PI_VID, 0x042A, 3, 0x0001, 0x0002) /* XK-12 Joystick mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x042B, 0, 0x000c, 0x0001) /* XK-12 Joystick read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x042B, 1, 0x0001, 0x0006) /* XK-12 Joystick keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x042B, 2, 0x0001, 0x0002) /* XK-12 Joystick mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x042C, 0, 0x000c, 0x0001) /* XK-3 Front Hinged Footpedal splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x042C, 1, 0x0001, 0x0006) /* XK-3 Front Hinged Footpedal keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x042C, 2, 0x0001, 0x0002) /* XK-3 Front Hinged Footpedal mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x042D, 0, 0x000c, 0x0001) /* XK-3 Front Hinged Footpedal splat write only*/
	DEVICE_MAP_ENTRY(PI_VID, 0x042D, 1, 0x0001, 0x0006) /* XK-3 Front Hinged Footpedal keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x042D, 2, 0x0001, 0x0004) /* XK-3 Front Hinged Footpedal joystick*/
	DEVICE_MAP_ENTRY(PI_VID, 0x042D, 3, 0x0001, 0x0002) /* XK-3 Front Hinged Footpedal mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x042E, 0, 0x000c, 0x0001) /* XK-3 Front Hinged Footpedal read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x042E, 1, 0x0001, 0x0006) /* XK-3 Front Hinged Footpedal keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x042E, 2, 0x0001, 0x0004) /* XK-3 Front Hinged Footpedal joystick*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0432, 0, 0x000c, 0x0001) /* XK-12 Touch splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0432, 1, 0x0001, 0x0006) /* XK-12 Touch keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0432, 2, 0x0001, 0x0002) /* XK-12 Touch mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0433, 0, 0x000c, 0x0001) /* XK-12 Touch splat write only*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0433, 1, 0x0001, 0x0006) /* XK-12 Touch keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0433, 2, 0x0001, 0x0004) /* XK-12 Touch joystick*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0433, 3, 0x0001, 0x0002) /* XK-12 Touch mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0434, 0, 0x000c, 0x0001) /* XK-12 Touch read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0434, 1, 0x0001, 0x0006) /* XK-12 Touch keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0434, 2, 0x0001, 0x0004) /* XK-12 Touch joystick*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0435, 0, 0x000c, 0x0001) /* XK-12 Trackball splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0435, 1, 0x0001, 0x0006) /* XK-12 Trackball keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0435, 2, 0x0001, 0x0002) /* XK-12 Trackball mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0436, 0, 0x000c, 0x0001) /* XK-12 Trackball splat write only*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0436, 1, 0x0001, 0x0006) /* XK-12 Trackball keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0436, 2, 0x0001, 0x0004) /* XK-12 Trackball joystick*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0436, 3, 0x0001, 0x0002) /* XK-12 Trackball mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0437, 0, 0x000c, 0x0001) /* XK-12 Trackball read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0437, 1, 0x0001, 0x0006) /* XK-12 Trackball keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0437, 2, 0x0001, 0x0004) /* XK-12 Trackball joystick*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0438, 0, 0x000c, 0x0001) /* XK-3 Rear Hinged Footpedal splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0438, 1, 0x0001, 0x0006) /* XK-3 Rear Hinged Footpedal keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0438, 2, 0x0001, 0x0002) /* XK-3 Rear Hinged Footpedal mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0439, 0, 0x000c, 0x0001) /* XK-3 Rear Hinged Footpedal splat write only*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0439, 1, 0x0001, 0x0006) /* XK-3 Rear Hinged Footpedal keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0439, 2, 0x0001, 0x0004) /* XK-3 Rear Hinged Footpedal joystick*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0439, 3, 0x0001, 0x0002) /* XK-3 Rear Hinged Footpedal mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x043A, 0, 0x000c, 0x0001) /* XK-3 Rear Hinged Footpedal splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x043A, 1, 0x0001, 0x0006) /* XK-3 Rear Hinged Footpedal keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x043A, 2, 0x0001, 0x0004) /* XK-3 Rear Hinged Footpedal joystick*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x043B, 0, 0x000c, 0x0001) /* ADC-888 splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x043B, 1, 0x0001, 0x0006) /* ADC-888 Touch keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x043B, 2, 0x0001, 0x0004) /* ADC-888 Touch joystick*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x043C, 0, 0x000c, 0x0001) /* HiRes splat read and write*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0440, 0, 0x000c, 0x0001) /* Foxboro splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0440, 1, 0x0001, 0x0006) /* Foxboro keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0440, 2, 0x0001, 0x0002) /* Foxboro mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0441, 0, 0x000c, 0x0001) /* XK-80/60 splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0441, 1, 0x0001, 0x0006) /* XK-80/60 keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0441, 2, 0x0001, 0x0002) /* XK-80/60 mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0442, 0, 0x000c, 0x0001) /* XK-80/60 splat write only*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0442, 1, 0x0001, 0x0006) /* XK-80/60 keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0442, 2, 0x0001, 0x0004) /* XK-80/60 joystick*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0442, 3, 0x0001, 0x0002) /* XK-80/60 mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0443, 0, 0x000c, 0x0001) /* XK-80/60 splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0443, 1, 0x0001, 0x0006) /* XK-80/60 keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0443, 2, 0x0001, 0x0004) /* XK-80/60 joystick*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0444, 0, 0x000c, 0x0001) /* LGZ splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0444, 1, 0x0001, 0x0006) /* LGZ keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0444, 2, 0x0001, 0x0002) /* LGZ mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0445, 0, 0x000c, 0x0001) /* LGZ splat write only*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0445, 1, 0x0001, 0x0006) /* LGZ keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0445, 2, 0x0001, 0x0004) /* LGZ joystick*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0445, 3, 0x0001, 0x0002) /* LGZ mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0446, 0, 0x000c, 0x0001) /* LGZ splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0446, 1, 0x0001, 0x0006) /* LGZ keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0446, 2, 0x0001, 0x0004) /* LGZ joystick*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0447, 0, 0x000c, 0x0001) /* PushPull splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0447, 1, 0x0001, 0x0006) /* PushPull keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0447, 2, 0x0001, 0x0002) /* PushPull mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0448, 0, 0x000c, 0x0001) /* PushPull splat write only*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0448, 1, 0x0001, 0x0006) /* PushPull keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0448, 2, 0x0001, 0x0004) /* PushPull joystick*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0448, 3, 0x0001, 0x0002) /* PushPull mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0449, 0, 0x000c, 0x0001) /* PushPull splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0449, 1, 0x0001, 0x0006) /* PushPull keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0449, 2, 0x0001, 0x0004) /* PushPull joystick*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x044A, 0, 0x000c, 0x0001) /* Bluetooth Encoder splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x044A, 1, 0x0001, 0x0006) /* Bluetooth Encoder keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x044A, 2, 0x0001, 0x0002) /* Bluetooth Encoder mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x044B, 0, 0x000c, 0x0001) /* Bluetooth Encoder splat write only*/
	DEVICE_MAP_ENTRY(PI_VID, 0x044B, 1, 0x0001, 0x0006) /* Bluetooth Encoder keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x044B, 2, 0x0001, 0x0004) /* Bluetooth Encoder joystick*/
	DEVICE_MAP_ENTRY(PI_VID, 0x044B, 3, 0x0001, 0x0002) /* Bluetooth Encoder mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x044C, 0, 0x000c, 0x0001) /* Bluetooth Encoder splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x044C, 1, 0x0001, 0x0006) /* Bluetooth Encoder keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x044C, 2, 0x0001, 0x0004) /* Bluetooth Encoder joystick*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x00F6, 0, 0x000c, 0x0001) /* VEC splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x00F7, 0, 0x000c, 0x0001) /* VEC Audiotranskription.de footpedal splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x00F8, 0, 0x000c, 0x0001) /* VEC sbs footpedal splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x00F9, 0, 0x000c, 0x0001) /* VEC dwx footpedal splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x00FA, 0, 0x000c, 0x0001) /* VEC spx footpedal splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x00FB, 0, 0x000c, 0x0001) /* VEC dac footpedal splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x00FC, 0, 0x000c, 0x0001) /* VEC srw footpedal splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x00FD, 0, 0x000c, 0x0001) /* VEC dictation (VIS) splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x00FE, 0, 0x000c, 0x0001) /* VEC dvi footpedal splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x00FF, 0, 0x000c, 0x0001) /* VEC footpedal splat read and write*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x0268, 0, 0x000c, 0x0001) /* Footpedal SE splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0261, 0, 0x000c, 0x0001) /* Matrix/Footpedal/SI SE splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0271, 0, 0x000c, 0x0001) /* Stick SE splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0281, 0, 0x000c, 0x0001) /* Desktop SE splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0291, 0, 0x000c, 0x0001) /* Professional SE splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0241, 0, 0x000c, 0x0001) /* Jog & Shuttle SE splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0251, 0, 0x000c, 0x0001) /* Joystick Pro SE splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0261, 0, 0x000c, 0x0001) /* Pendant SE splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0269, 0, 0x000c, 0x0001) /* Switch Interface SE splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0304, 0, 0x000c, 0x0001) /* Button Panel SE splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x026A, 0, 0x000c, 0x0001) /* Matrix Board SE splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0305, 0, 0x000c, 0x0001) /* 128 w Mag Strip splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0306, 0, 0x000c, 0x0001) /* 128 no reader splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0307, 0, 0x000c, 0x0001) /* 128 w Bar Code splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0308, 0, 0x000c, 0x0001) /* 84 w Mag Strip splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0309, 0, 0x000c, 0x0001) /* 84 no reader splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x030A, 0, 0x000c, 0x0001) /* 84 w Bar Code splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0301, 0, 0x000c, 0x0001) /* LCD w Mag Strip splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0302, 0, 0x000c, 0x0001) /* LCD no reader splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x0303, 0, 0x000c, 0x0001) /* LCD w Bar Code splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x00D9, 0, 0x000c, 0x0001) /* ReDAC IO Module splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x00D2, 0, 0x000c, 0x0001) /* Raildriver splat read and write*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x02B5, 0, 0x000c, 0x0001) /* Stick MWII splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x02B6, 1, 0x0001, 0x0006) /* Stick MWII keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x02B6, 2, 0x0001, 0x0002) /* Stick MWII mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x02A5, 0, 0x000c, 0x0001) /* Desktop MWII splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x02A6, 1, 0x0001, 0x0006) /* Desktop MWII keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x02A6, 2, 0x0001, 0x0002) /* Desktop MWII mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x02A7, 0, 0x000c, 0x0001) /* Professional MWII splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x02A8, 1, 0x0001, 0x0006) /* Professional MWII keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x02A8, 2, 0x0001, 0x0002) /* Professional MWII mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x02B1, 0, 0x000c, 0x0001) /* Jog & Shuttle MWII splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x02B2, 1, 0x0001, 0x0006) /* Jog & Shuttle MWII keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x02B2, 2, 0x0001, 0x0002) /* Jog & Shuttle MWII mouse*/
	 
	DEVICE_MAP_ENTRY(PI_VID, 0x02B7, 0, 0x000c, 0x0001) /* Switch Interface MWII splat read and write*/
	DEVICE_MAP_ENTRY(PI_VID, 0x02B8, 1, 0x0001, 0x0006) /* Switch Interface MWII keyboard*/
	DEVICE_MAP_ENTRY(PI_VID, 0x02B8, 2, 0x0001, 0x0002) /* Switch Interface MWII mouse*/
};

static bool get_usage(unsigned short vid, unsigned short pid,
                      int interface_number,
                      unsigned short *usage_page,
                      unsigned short *usage)
{
	size_t num = sizeof(device_map) / sizeof(*device_map);
	size_t i;

	for (i = 0; i < num; i++) {
		const struct device_map_entry *dev = &device_map[i];
		
		if (dev->vid == vid &&
		    dev->pid == pid &&
		    dev->interface_number == interface_number)
		{
			*usage_page = dev->usage_page;
			*usage = dev->usage;
			return true;
		}
	}
	
	return false;
}

void print_buf(char *data, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		printf("%02hhx ", data[i]);
		if ((i+1) % 8 == 0)
			printf("  ");
		if ((i+1) % 16 == 0)
			printf("\n");
	}
	printf("\n\n");

}

int main(void)
{
	TEnumHIDInfo info[128];
	long count;
	int i;
	long handle = -1;
	
	unsigned res = EnumeratePIE(PI_VID, info, &count);
	
	for (i = 0; i < count; i++) {
		TEnumHIDInfo *dev = &info[i];
		printf("Found XKeys Device:\n");
		printf("\tPID: %04x\n", dev->PID);
		printf("\tUsage Page: %04x\n", dev->UP);
		printf("\tUsage:      %04x\n", dev->Usage);
		printf("\tVersion: %d\n\n", dev->Version);


		handle = dev->Handle;
		unsigned int res = SetupInterfaceEx(handle);
		if (res != 0) {
			printf("Unabe to open device. err: %d\n", res);
		}
		break;
	}
	
	if (handle < 0) {
		printf("Unable to open device\n");
		exit(1);
	}
	
	char data[80];
	while (1) {
		
		unsigned int res = 0;

		res  = ReadLast(handle, data);
		if (res == 0) {
			printf("LAST: \n");
			print_buf(data, 33);
			printf("ENDLAST\n\n");
		}

		res = 0;
		
		while (res == 0) {
			res = BlockingReadData(handle, data, 20);
			if (res == 0) {
				print_buf(data, 33);
			}
			else if (res == PIE_HID_READ_INSUFFICIENT_DATA) {
				printf(".");
				fflush(stdout);
			}	
			else {
				printf("Error Reading\n");
			}
		}
		
		printf("Sleeping\n");
		#if 1
		if (res != 0) {
			//usleep(10*1000); // Sleep 10 milliseconds.
			sleep(2); // 2 seconds
		}
		#endif
		
		//ClearBuffer(handle);
		
	}


	return 0;
}
