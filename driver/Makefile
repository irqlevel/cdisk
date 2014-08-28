obj-m = cdisk.o cdisk_srv.o

ccflags-y := -I$(src)/include -I$(src)/inc -g3 -Wall -Werror

cdisk-y := cdisk/cdisk.o lib/klog.o lib/ksocket.o
cdisk_srv-y := cdisk_srv/cdisk_srv.o lib/klog.o lib/ksocket.o

KVERSION = $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
	cp cdisk.ko ../bin/cdisk.ko
	cp cdisk_srv.ko ../bin/cdisk_srv.ko

clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
	rm -r -f ../bin/cdisk.ko
	rm -r -f ../bin/cdisk_srv.ko

