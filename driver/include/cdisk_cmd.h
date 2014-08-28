#pragma once
#include <linux/ioctl.h>
#include <cdisk_gen.h>

#define IOC_MAGIC 0xED000000

#define IOCTL_DISK_CREATE	_IO(IOC_MAGIC, 1)
#define IOCTL_DISK_SETUP	_IO(IOC_MAGIC, 2)
#define IOCTL_DISK_DELETE	_IO(IOC_MAGIC, 3)


#define CDISK_FNAME_MAX_SZ 256

#pragma pack(push, 1)

struct cdisk_cmd {
	int error;
	union {
		struct {
			int disk_num;
			char fname[CDISK_FNAME_MAX_SZ];
		} create;
		struct {
			int disk_num;
		} setup;
		struct {
			int disk_num;
		} delete;
	} u;
};

#pragma pack(pop)
