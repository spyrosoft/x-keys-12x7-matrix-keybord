/** @file
 * @defgroup API hidapi API
 */

#ifndef HIDAPI_H__
#define HIDAPI_H__

#include <wchar.h>

#ifdef _WIN32
      #define HID_API_EXPORT __declspec(dllexport)
      #define HID_API_CALL
#else
      #define HID_API_EXPORT /**< API export macro */
      #define HID_API_CALL /**< API call macro */
#endif

#define HID_API_EXPORT_CALL HID_API_EXPORT HID_API_CALL /**< API export and call macro*/

#ifdef __cplusplus
extern "C" {
#endif
		struct hid_device_;
		typedef struct hid_device_ hid_device; /**< opaque hidapi structure */

		/** hidapi info structure */
		struct hid_device_info {
			/** Platform-specific device path */
			char *path;
			/** Device Vendor ID */
			unsigned short vendor_id;
			/** Device Product ID */
			unsigned short product_id;
			/** Serial Number */
			wchar_t *serial_number;
			/** Device Release Number in binary-coded decimal,
			    also known as Device Version Number */
			unsigned short release_number;
			/** Manufacturer String */
			wchar_t *manufacturer_string;
			/** Product string */
			wchar_t *product_string;
			/** Usage Page for this Device/Interface
			    (Windows/Mac only). */
			unsigned short usage_page;
			/** Usage for this Device/Interface
			    (Windows/Mac only).*/
			unsigned short usage;
			/** The USB interface which this logical device
			    represents. Valid on the Linux/libusb implementation
			    in all cases, and valid on the Windows implementation
			    only if the device contains more than one interface. */
			int interface_number;

			/** Pointer to the next device */
			struct hid_device_info *next;
		};


		/** @brief Enumerate the HID Devices.

			This function returns a linked list of all the HID devices
			attached to the system which match vendor_id and product_id.
			If @p vendor_id and @p product_id are both set to 0, then
			all HID devices will be returned.

			@ingroup API
			@param vendor_id The Vendor ID (VID) of the types of device
				to open.
			@param product_id The Product ID (PID) of the types of
				device to open.

		    @returns
		    	This function returns a pointer to a linked list of type
		    	struct #hid_device, containing information about the HID devices
		    	attached to the system, or NULL in the case of failure. Free
		    	this linked list by calling hid_free_enumeration().
		*/
		struct hid_device_info HID_API_EXPORT * HID_API_CALL hid_enumerate(unsigned short vendor_id, unsigned short product_id);

		/** @brief Free an enumeration Linked List

		    This function frees a linked list created by hid_enumerate().

			@ingroup API
		    @param devs Pointer to a list of struct_device returned from
		    	      hid_enumerate().
		*/
		void  HID_API_EXPORT HID_API_CALL hid_free_enumeration(struct hid_device_info *devs);

		/** @brief Open a HID device using a Vendor ID (VID), Product ID
			(PID) and optionally a serial number.

			If @p serial_number is NULL, the first device with the
			specified VID and PID is opened.

			@ingroup API
			@param vendor_id The Vendor ID (VID) of the device to open.
			@param product_id The Product ID (PID) of the device to open.
			@param serial_number The Serial Number of the device to open
				               (Optionally NULL).

			@returns
				This function returns a pointer to a #hid_device object on
				success or NULL on failure.
		*/
		HID_API_EXPORT hid_device * HID_API_CALL hid_open(unsigned short vendor_id, unsigned short product_id, wchar_t *serial_number);

		/** @brief Open a HID device by its path name.

			The path name be determined by calling hid_enumerate(), or a
			platform-specific path name can be used (eg: /dev/hidraw0 on
			Linux).

			@ingroup API
		    @param path The path name of the device to open

			@returns
				This function returns a pointer to a #hid_device object on
				success or NULL on failure.
		*/
		HID_API_EXPORT hid_device * HID_API_CALL hid_open_path(const char *path);

		/** @brief Write an Output report to a HID device.

			The first byte of @p data[] must contain the Report ID. For
			devices which only support a single report, this must be set
			to 0x0. The remaining bytes contain the report data. Since
			the Report ID is mandatory, calls to hid_write() will always
			contain one more byte than the report contains. For example,
			if a hid report is 16 bytes long, 17 bytes must be passed to
			hid_write(), the Report ID (or 0x0, for devices with a
			single report), followed by the report data (16 bytes). In
			this example, the length passed in would be 17.

			hid_write() will send the data on the first OUT endpoint, if
			one exists. If it does not, it will send the data through
			the Control Endpoint (Endpoint 0).

			@ingroup API
			@param device A device handle returned from hid_open().
			@param data The data to send, including the report number as
				the first byte.
			@param length The length in bytes of the data to send.

			@returns
				This function returns the actual number of bytes written and
				-1 on error.
		*/
		int  HID_API_EXPORT HID_API_CALL hid_write(hid_device *device, const unsigned char *data, size_t length);

		/** @brief Read an Input report from a HID device with timeout.

			Input reports are returned
			to the host through the INTERRUPT IN endpoint. The first byte will
			contain the Report number if the device uses numbered reports.

			@ingroup API
			@param device A device handle returned from hid_open().
			@param data A buffer to put the read data into.
			@param length The number of bytes to read. For devices with
				multiple reports, make sure to read an extra byte for
				the report number.
			@param milliseconds timeout in milliseconds or -1 for blocking wait.

			@returns
				This function returns the actual number of bytes read and
				-1 on error.
		*/
		int HID_API_EXPORT HID_API_CALL hid_read_timeout(hid_device *dev, unsigned char *data, size_t length, int milliseconds);

		/** @brief Read an Input report from a HID device.

			Input reports are returned
		    to the host through the INTERRUPT IN endpoint. The first byte will
			contain the Report number if the device uses numbered reports.

			@ingroup API
			@param device A device handle returned from hid_open().
			@param data A buffer to put the read data into.
			@param length The number of bytes to read. For devices with
				multiple reports, make sure to read an extra byte for
				the report number.

			@returns
				This function returns the actual number of bytes read and
				-1 on error.
		*/
		int  HID_API_EXPORT HID_API_CALL hid_read(hid_device *device, unsigned char *data, size_t length);

		/** @brief Set the device handle to be non-blocking.

			In non-blocking mode calls to hid_read() will return
			immediately with a value of 0 if there is no data to be
			read. In blocking mode, hid_read() will wait (block) until
			there is data to read before returning.

			Nonblocking can be turned on and off at any time.

			@ingroup API
			@param device A device handle returned from hid_open().
			@param nonblock enable or not the nonblocking reads
			 - 1 to enable nonblocking
			 - 0 to disable nonblocking.

			@returns
				This function returns 0 on success and -1 on error.
		*/
		int  HID_API_EXPORT HID_API_CALL hid_set_nonblocking(hid_device *device, int nonblock);

		/** @brief Send a Feature report to the device.

			Feature reports are sent over the Control endpoint as a
			Set_Report transfer.  The first byte of @p data[] must
			contain the Report ID. For devices which only support a
			single report, this must be set to 0x0. The remaining bytes
			contain the report data. Since the Report ID is mandatory,
			calls to hid_send_feature_report() will always contain one
			more byte than the report contains. For example, if a hid
			report is 16 bytes long, 17 bytes must be passed to
			hid_send_feature_report(): the Report ID (or 0x0, for
			devices which do not use numbered reports), followed by the
			report data (16 bytes). In this example, the length passed
			in would be 17.

			@ingroup API
			@param device A device handle returned from hid_open().
			@param data The data to send, including the report number as
				the first byte.
			@param length The length in bytes of the data to send, including
				the report number.

			@returns
				This function returns the actual number of bytes written and
				-1 on error.
		*/
		int HID_API_EXPORT HID_API_CALL hid_send_feature_report(hid_device *device, const unsigned char *data, size_t length);

		/** @brief Get a feature report from a HID device.

			Make sure to set the first byte of @p data[] to the Report
			ID of the report to be read.  Make sure to allow space for
			this extra byte in @p data[].

			@ingroup API
			@param device A device handle returned from hid_open().
			@param data A buffer to put the read data into, including
				the Report ID. Set the first byte of @p data[] to the
				Report ID of the report to be read.
			@param length The number of bytes to read, including an
				extra byte for the report ID. The buffer can be longer
				than the actual report.

			@returns
				This function returns the number of bytes read and
				-1 on error.
		*/
		int HID_API_EXPORT HID_API_CALL hid_get_feature_report(hid_device *device, unsigned char *data, size_t length);

		/** @brief Close a HID device.

			@ingroup API
			@param device A device handle returned from hid_open().
		*/
		void HID_API_EXPORT HID_API_CALL hid_close(hid_device *device);

		/** @brief Get The Manufacturer String from a HID device.

			@ingroup API
			@param device A device handle returned from hid_open().
			@param string A wide string buffer to put the data into.
			@param maxlen The length of the buffer in multiples of wchar_t.

			@returns
				This function returns 0 on success and -1 on error.
		*/
		int HID_API_EXPORT_CALL hid_get_manufacturer_string(hid_device *device, wchar_t *string, size_t maxlen);

		/** @brief Get The Product String from a HID device.

			@ingroup API
			@param device A device handle returned from hid_open().
			@param string A wide string buffer to put the data into.
			@param maxlen The length of the buffer in multiples of wchar_t.

			@returns
				This function returns 0 on success and -1 on error.
		*/
		int HID_API_EXPORT_CALL hid_get_product_string(hid_device *device, wchar_t *string, size_t maxlen);

		/** @brief Get The Serial Number String from a HID device.

			@ingroup API
			@param device A device handle returned from hid_open().
			@param string A wide string buffer to put the data into.
			@param maxlen The length of the buffer in multiples of wchar_t.

			@returns
				This function returns 0 on success and -1 on error.
		*/
		int HID_API_EXPORT_CALL hid_get_serial_number_string(hid_device *device, wchar_t *string, size_t maxlen);

		/** @brief Get a string from a HID device, based on its string index.

			@ingroup API
			@param device A device handle returned from hid_open().
			@param string_index The index of the string to get.
			@param string A wide string buffer to put the data into.
			@param maxlen The length of the buffer in multiples of wchar_t.

			@returns
				This function returns 0 on success and -1 on error.
		*/
		int HID_API_EXPORT_CALL hid_get_indexed_string(hid_device *device, int string_index, wchar_t *string, size_t maxlen);

		/** @brief Get a string describing the last error which occurred.

			@ingroup API
			@param device A device handle returned from hid_open().

			@returns
				This function returns a string containing the last error
				which occurred or NULL if none has occurred.
		*/
		HID_API_EXPORT const wchar_t* HID_API_CALL hid_error(hid_device *device);

#ifdef __cplusplus
}
#endif

#endif

#ifndef PIE_HID_H__
#define PIE_HID_H__

#ifdef _WIN32
	#define PIE_HID_CALL __stdcall
#else
	#define PIE_HID_CALL
	#include <stdbool.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif


typedef enum {
	piNone = 0,
	piNewData = 1,
	piDataChange = 2
} EEventPI;

#define MAX_XKEY_DEVICES 128
#define PI_VID 0x5F3



// Enumerate() errors
#define PIE_HID_ENUMERATE_BAD_HID_DEVICE 101 /* Bad HID device information set handle */
#define PIE_HID_ENUMERATE_NO_DEVICES_FOUND 102 /* No devices found in device information set */
#define PIE_HID_ENUMERATE_OTHER_ENUM_ERROR 103 /* Other enumeration error */
#define PIE_HID_ENUMERATE_ERROR_GETTING_DEVICE_DETAIL 104 /* Error getting device interface detail (symbolic link name) */ 
#define PIE_HID_ENUMERATE_ERROR_GETTING_DEVICE_DETATIL2 105 /* Error getting device interface detail (symbolic link name) */
#define PIE_HID_ENUMERATE_UNABLE_TO_OPEN_HANDLE 106 /*Unable to open a handle. */
#define PIE_HID_ENUMERATE_GET_ATTRIBUTES_ERROR 107
#define PIE_HID_ENUMERATE_VENDOR_ID_ERROR 108
#define PIE_HID_ENUMERATE_GET_PREPARSED_DATA_ERROR 109
#define PIE_HID_ENUMERATE_GET_CAPS 110
#define PIE_HID_ENUMERATE_GET_MANUFACTURER_STRING 111
#define PIE_HID_ENUMERATE_GET_PRODUCT_STRING 112

// SetupInterface() errors
#define PIE_HID_SETUP_BAD_HANDLE 201 /* Bad interface handle */
#define PIE_HID_SETUP_CANNOT_ALLOCATE_MEM_FOR_RING 202 /* Cannot allocate memory for ring buffer */
#define PIE_HID_SETUP_CANNOT_CREATE_MUTEX 203 /* Cannot create mutex */
#define PIE_HID_SETUP_CANNOT_CREATE_READ_THREAD 204 /* Cannot create read thread */
#define PIE_HID_SETUP_CANNOT_OPEN_READ_HANDLE 205 /* Cannot open read handle */
#define PIE_HID_SETUP_CANNOT_OPEN_READ_HANDLE_ACCESS_DENIED 206 /* Cannot open read handle - Access Denied */
#define PIE_HID_SETUP_CANNOT_OPEN_READ_HANDLE_BAD_PATH 207 /* Cannot open read handle - bad DevicePath */
#define PIE_HID_SETUP_CANNOT_OPEN_WRITE_HANDLE 208 /* Cannot open write handle */
#define PIE_HID_SETUP_CANNOT_OPEN_WRITE_HANDLE_ACCESS_DENIED 209 /* Cannot open write handle - Access Denied */
#define PIE_HID_SETUP_CANNOT_OPEN_WRITE_HANDLE_BAD_PATH 210 /* Cannot open write handle - bad DevicePath */

// ReadData() errors
#define PIE_HID_READ_BAD_INTERFACE_HANDLE 301 /* Bad interface handle */
#define PIE_HID_READ_LENGTH_ZERO 302 /* Read length is zero */
#define PIE_HID_READ_CANNOT_ACQUIRE_MUTEX 303 /* Could not acquire data mutex */
#define PIE_HID_READ_INSUFFICIENT_DATA 304 /* Insufficient data (< readSize bytes) */
#define PIE_HID_READ_CANNOT_RELEASE_MUTEX 305 /* Could not release data mutex */
#define PIE_HID_READ_CANNOT_RELEASE_MUTEX2 306 /* Could not release data mutex */
#define PIE_HID_READ_INVALID_HANDLE 307 /* Handle Invalid or Device_Not_Found (probably device unplugged) */
#define PIE_HID_READ_DEVICE_DISCONNECTED 308
#define PIE_HID_READ_READ_ERROR 309
#define PIE_HID_READ_BYTES_NOT_EQUAL_READSIZE 310
#define PIE_HID_READ_BLOCKING_READ_DATA_TIMED_OUT 311

// Write() errors
#define PIE_HID_WRITE_BAD_HANDLE 401 /* Bad interface handle */
#define PIE_HID_WRITE_LENGTH_ZERO 402 /* Write length is zero */
#define PIE_HID_WRITE_FAILED 403 /* Write failed */
#define PIE_HID_WRITE_INCOMPLETE 404 /* Write incomplete */
#define PIE_HID_WRITE_UNABLE_TO_ACQUIRE_MUTEX 405 /* unable to acquire write mutex */
#define PIE_HID_WRITE_UNABLE_TO_RELEASE_MUTEX 406 /* unable to release write mutex */
#define PIE_HID_WRITE_HANDLE_INVALID 407 /* Handle Invalid or Device_Not_Found (probably device unplugged) (previous buffered write) */
#define PIE_HID_WRITE_BUFFER_FULL 408 /* Buffer full */
#define PIE_HID_WRITE_PREV_WRITE_FAILED 409 /* Previous buffered write failed. */
#define PIE_HID_WRITE_PREV_WRITE_WRONG_NUMBER 410 /* Previous buffered write sent wrong number of bytes */
#define PIE_HID_WRITE_TIMER_FAILED 411 /* timer failed */
#define PIE_HID_WRITE_PREV_WRITE_UNABLE_TO_RELEASE_MUTEX 412 /* previous buffered write count not release mutex */
#define PIE_HID_WRITE_BUFFER_FULL2 413 /* write buffer is full */
#define PIE_HID_WRITE_FAST_WRITE_ERROR 414 /* cannot write queue a fast write while slow writes are still pending */

// ReadLast errors
#define PIE_HID_READLAST_BAD_HANDLE 501 /* Bad interface handle */
#define PIE_HID_READLAST_LENGTH_ZERO 502 /* Read length is zero */
#define PIE_HID_READLAST_UNABLE_TO_ACQUIRE_MUTEX 503 /* Could not acquire data mutex */
#define PIE_HID_READLAST_INSUFFICIENT_DATA 504 /* Insufficient data (< readSize bytes) */
#define PIE_HID_READLAST_UNABLE_TO_RELEASE_MUTEX 505 /* Could not release data mutex */
#define PIE_HID_READLAST_UNABLE_TO_RELEASE_MUTEX2 506 /* Could not release data mutex */
#define PIE_HID_READLAST_INVALID_HANDLE 507 /* Handle Invalid or Device_Not_Found (probably device unplugged) */

// ClearBuffer() errors
#define PIE_HID_CLEARBUFFER_BAD_HANDLE 601 /* Bad interface handle */
#define PIE_HID_CLEARBUFFER_UNABLE_TO_RELEASE_MUTEX 602 /* Could not release data mutex */
#define PIE_HID_CLEARBUFFER_UNABLE_TO_ACQUIRE_MUTEX 603 /* Could not acquire data mutex */

// SetDataCallback() errors
#define PIE_HID_DATACALLBACK_BAD_HANDLE 701 /* Bad interface handle */
#define PIE_HID_DATACALLBACK_INVALID_INTERFACE 702
#define PIE_HID_DATACALLBACK_CANNOT_CREATE_CALLBACK_THREAD 703
#define PIE_HID_DATACALLBACK_CALLBACK_ALREADY_SET 704

// SetErrorCallback() errors
#define PIE_HID_ERRORCALLBACK_BAD_HANDLE 801 /* Bad interface handle */
#define PIE_HID_ERRORCALLBACK_INVALID_INTERFACE 802
#define PIE_HID_ERRORCALLBACK_CANNOT_CREATE_ERROR_THREAD 803
#define PIE_HID_ERRORCALLBACK_ERROR_THREAD_ALREADY_CREATED 1804



typedef struct  _HID_ENUM_INFO  {
    unsigned int   PID;
    unsigned int   Usage;
    unsigned int   UP;
    long    readSize;
    long    writeSize;
    char    DevicePath[256];
    unsigned int   Handle;
    unsigned int   Version;
    char   ManufacturerString[128];
    char   ProductString[128];
} TEnumHIDInfo;

#define MAX_XKEY_DEVICES		128
#define PI_VID					0x5F3

typedef unsigned int (PIE_HID_CALL *PHIDDataEvent)(unsigned char *pData, unsigned int deviceID, unsigned int error);
typedef unsigned int (PIE_HID_CALL *PHIDErrorEvent)( unsigned int deviceID,unsigned int status);

void PIE_HID_CALL GetErrorString(int errNumb,char* EString,int size);
unsigned int PIE_HID_CALL EnumeratePIE(long VID, TEnumHIDInfo *info, long *count);
unsigned int PIE_HID_CALL GetXKeyVersion(long hnd);
unsigned int PIE_HID_CALL SetupInterfaceEx(long hnd);
void  PIE_HID_CALL CloseInterface(long hnd);
void  PIE_HID_CALL CleanupInterface(long hnd);
unsigned int PIE_HID_CALL ReadData(long hnd, unsigned char *data);
unsigned int PIE_HID_CALL BlockingReadData(long hnd, unsigned char *data, int maxMillis);
unsigned int PIE_HID_CALL WriteData(long hnd, unsigned char *data);
unsigned int PIE_HID_CALL FastWrite(long hnd, unsigned char *data);
unsigned int PIE_HID_CALL ReadLast(long hnd, unsigned char *data);
unsigned int PIE_HID_CALL ClearBuffer(long hnd);
unsigned int PIE_HID_CALL GetReadLength(long hnd);
unsigned int PIE_HID_CALL GetWriteLength(long hnd);
unsigned int PIE_HID_CALL SetDataCallback(long hnd, PHIDDataEvent pDataEvent);
unsigned int PIE_HID_CALL SetErrorCallback(long hnd, PHIDErrorEvent pErrorCall);
#ifdef _WIN32
void PIE_HID_CALL DongleCheck2(int k0, int k1, int k2, int k3, int n0, int n1, int n2, int n3, int &r0, int &r1, int &r2, int &r3);
#endif
void PIE_HID_CALL SuppressDuplicateReports(long hnd,bool supp);
void PIE_HID_CALL DisableDataCallback(long hnd,bool disable);
bool PIE_HID_CALL IsDataCallbackDisabled(long hnd);
bool PIE_HID_CALL GetSuppressDuplicateReports(long hnd);


#ifdef __cplusplus
}
#endif


#endif /* PIE_HID_H__ */