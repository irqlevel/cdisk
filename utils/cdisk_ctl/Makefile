CC=gcc
CFLAGS=-c -Wall -Werror -I../../driver/include

all: cdisk_ctl
	cp cdisk_ctl ../../bin/cdisk_ctl

cdisk_ctl: cdisk_ctl.o
	$(CC) cdisk_ctl.o -o cdisk_ctl

cdisk_ctl.o: cdisk_ctl.c
	$(CC) $(CFLAGS) cdisk_ctl.c

clean:
	rm -rf *.o cdisk_ctl
	rm -r -f ../../bin/cdisk_ctl

