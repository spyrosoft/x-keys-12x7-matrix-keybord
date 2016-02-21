# Research Notes

### If there are permissions issues accessing the device

```shell
git clone https://github.com/piengineering/xkeys.git
cd xkeys
cp udev/90-xkeys.rules /usr/lib/udev/rules.d/
```

### USB Advice

http://stackoverflow.com/questions/17679480/details-on-usb-no-luck-so-far/17679571


### Possible Go USB solutions

* https://github.com/GeertJohan/go.hid
    * https://gowalker.org/github.com/GeertJohan/go.hid
    * https://godoc.org/github.com/GeertJohan/go.hid
* https://github.com/boombuler/hid
* https://github.com/popons/go-libusb.git


### Sending Key Events to X11

http://www.doctort.org/adam/nerd-notes/x11-fake-keypress-event.html


### File Locations In The Filesystem

The device file itself:
```shell
/dev/bus/usb/004/004
```

The libusb.h file:
```shell
/usr/include/libusb-1.0/
```

### Low Level USB

https://github.com/libusb/libusb/wiki


### Official xkeys code

* https://github.com/signal11/hidapi
* https://github.com/piengineering/xkeys.git