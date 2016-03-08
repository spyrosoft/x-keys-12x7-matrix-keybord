# Troubleshooting

### If there are permissions issues accessing the device

```shell
git clone https://github.com/piengineering/xkeys.git
cd xkeys
cp udev/90-xkeys.rules /usr/lib/udev/rules.d/
```

# Research Notes

### USB Advice

http://stackoverflow.com/questions/17679480/details-on-usb-no-luck-so-far/17679571


### Possible Solutions

* https://github.com/GeertJohan/go.hid
    * https://gowalker.org/github.com/GeertJohan/go.hid
    * https://godoc.org/github.com/GeertJohan/go.hid
* https://github.com/qmsk/onewire/blob/master/hidraw/device.go
* https://github.com/jessta/udev
* https://github.com/boombuler/hid
* https://github.com/popons/go-libusb.git
* http://lxr.free-electrons.com/source/samples/hidraw/hid-example.c
* https://www.kernel.org/doc/Documentation/hid/hidraw.txt

### Sending Key Events to X11

http://www.doctort.org/adam/nerd-notes/x11-fake-keypress-event.html


### File Locations In The Filesystem

To find the device file itself use lsusb then locate the Bus and Device numbers. They map to the file in:
```shell
/dev/bus/usb/BUS/DEVICE
e.g.
/dev/bus/usb/001/007
```

The libusb.h file:
```shell
/usr/include/libusb-1.0/
```

### Low Level USB

http://libusb.sourceforge.net/api-1.0/api.html
https://github.com/libusb/libusb/wiki
https://www.kernel.org/doc/Documentation/hid/hidraw.txt

### Official xkeys code

* https://github.com/signal11/hidapi
* https://github.com/piengineering/xkeys.git


### Goals

* Open the device using the Vendor ID and Product ID
* Read a report from the device
* Compare the new state to the previous state
* For state differences, trigger keydown and keyup events in X