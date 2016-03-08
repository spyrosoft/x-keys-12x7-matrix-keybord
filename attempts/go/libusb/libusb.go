package libusb

/*
	#cgo LDFLAGS: -lusb-1.0
	#include <libusb.h>
*/
import "C"
import "unsafe"

import "fmt"

func Init() (int, int) {
	C.libusb_init()

	bn := C.libusb_find_busses()
	dn := C.libusb_find_devices()

	return int(bn), int(dn)
}

type Info struct {
	Bus    string
	Device string
	Vid    int
	Pid    int
}

func Enum() []Info {
	fmt.Printf("")

	bus := C.libusb_get_busses()
	n := 0
	for ; bus != nil; bus = bus.next {
		for dev := bus.devices; dev != nil; dev = dev.next {
			n += 1
		}
	}
	infos := make([]Info, n)

	bus = C.libusb_get_busses()
	n = 0

	for ; bus != nil; bus = bus.next {
		busname := C.GoString(&bus.dirname[0])

		for dev := bus.devices; dev != nil; dev = dev.next {
			devname := C.GoString(&dev.filename[0])

			var info Info
			info.Bus = busname
			info.Device = devname
			info.Vid = int(dev.descriptor.idVendor)
			info.Pid = int(dev.descriptor.idProduct)

			infos[n] = info
			n += 1
		}
	}
	return infos
}

type Device struct {
	*Info
	handle     *C.libusb_dev_handle
	descriptor C.struct_usb_device_descriptor
	Timeout    int
}

type UsbError struct {
	ErrorDesc string	
}

func (u UsbError) Error() string {
	return u.ErrorDesc
}

func OpenAllCallback(vid, pid int, callback func (*Device, error)) {
	for bus := C.libusb_get_busses(); bus != nil; bus = bus.next {
		for dev := bus.devices; dev != nil; dev = dev.next {
			if int(dev.descriptor.idVendor) == vid &&
				int(dev.descriptor.idProduct) == pid {
				h := C.libusb_open(dev)
				if h == nil {
					callback(nil, UsbError{LastError()})
				} else {
					rdev := &Device{
						&Info{
							C.GoString(&bus.dirname[0]),
							C.GoString(&dev.filename[0]), vid, pid},
						h, dev.descriptor, 10000}
					callback(rdev, nil)
				}
			}
		}
	}
}

/// open usb device with info
//func Open(info Info) (*Device)
//{
//    var rdev *Device = nil;
//
//    for bus := C.libusb_get_busses() ; bus != nil ; bus=bus.next
//    {
//        for dev := bus.devices ; dev!=nil ; dev = dev.next
//        {
//            if int(dev.descriptor.idVendor)  == info.Vid &&
//               int(dev.descriptor.idProduct) == info.Pid
//            {
//                h := C.libusb_open(dev);
//                rdev = &Device{&info,h,dev.descriptor,10000};
//                return rdev;
//            }
//        }
//    }
//    return rdev;
//}
/// open usb device with info
func Open(vid, pid int) *Device {
	for bus := C.libusb_get_busses(); bus != nil; bus = bus.next {
		for dev := bus.devices; dev != nil; dev = dev.next {
			if int(dev.descriptor.idVendor) == vid &&
				int(dev.descriptor.idProduct) == pid {
				h := C.libusb_open(dev)
				rdev := &Device{
					&Info{
						C.GoString(&bus.dirname[0]),
						C.GoString(&dev.filename[0]), vid, pid},
					h, dev.descriptor, 10000}
				return rdev
			}
		}
	}
	return nil
}

func (dev *Device) Close() int {
	r := int(C.libusb_close(dev.handle))
	dev.handle = nil
	return r
}

func (dev *Device) String(key int) string {
	buf := make([]C.char, 256)

	C.libusb_get_string_simple(
		dev.handle,
		C.int(key),
		&buf[0],
		C.size_t(len(buf)))

	return C.GoString(&buf[0])

}

func (self *Device) Vendor() string {
	return self.String(int(self.descriptor.iManufacturer))
}
func (self *Device) Product() string {
	return self.String(int(self.descriptor.iProduct))
}
func LastError() string {
	return C.GoString(C.libusb_strerror())
}
func (*Device) LastError() string {
	return LastError()
}

func (self *Device) BulkWrite(ep int, dat []byte) int {
	return int(C.libusb_bulk_write(self.handle,
		C.int(ep),
		(*C.char)(unsafe.Pointer(&dat[0])),
		C.int(len(dat)),
		C.int(self.Timeout)))
}
func (self *Device) BulkRead(ep int, dat []byte) int {
	return int(C.libusb_bulk_read(self.handle,
		C.int(ep),
		(*C.char)(unsafe.Pointer(&dat[0])),
		C.int(len(dat)),
		C.int(self.Timeout)))
}

func (self *Device) InterruptWrite(ep int, dat []byte) int {
	return int(C.libusb_interrupt_write(self.handle,
		C.int(ep),
		(*C.char)(unsafe.Pointer(&dat[0])),
		C.int(len(dat)),
		C.int(self.Timeout)))
}

func (self *Device) InterruptRead(ep int, dat []byte) int {
	return int(C.libusb_interrupt_read(self.handle,
		C.int(ep),
		(*C.char)(unsafe.Pointer(&dat[0])),
		C.int(len(dat)),
		C.int(self.Timeout)))
}

func (self *Device) Configuration(conf int) int {
	return int(C.libusb_set_configuration(self.handle, C.int(conf)))
	//return int( C.libusb_set_configuration( (*C.uint)(123), C.int(conf)) );
}
func (self *Device) Interface(ifc int) int {
	return int(C.libusb_claim_interface(self.handle, C.int(ifc)))
}

const (
	USB_TYPE_STANDARD = (0x00 << 5)
	USB_TYPE_CLASS    = (0x01 << 5)
	USB_TYPE_VENDOR   = (0x02 << 5)
	USB_TYPE_RESERVED = (0x03 << 5)
)

func (self *Device) ControlMsg(reqtype int, req int, value int, index int, dat []byte) int {
	return int(C.libusb_control_msg(self.handle,
		C.int(reqtype),
		C.int(req),
		C.int(value),
		C.int(index),
		(*C.char)(unsafe.Pointer(&dat[0])),
		C.int(len(dat)),
		C.int(self.Timeout)))
}
