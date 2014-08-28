#pragma once

#include <linux/ioctl.h>
#include <cdisk_gen.h>

#define IOC_MAGIC 0xED000000

#define IOCTL_DISK_CREATE	_IO(IOC_MAGIC, 1)
#define IOCTL_DISK_SETUP	_IO(IOC_MAGIC, 2)
#define IOCTL_DISK_DELETE	_IO(IOC_MAGIC, 3)


#pragma pack(push, 1)

struct cdisk_srv_cmd {
	int error;
	union {
		struct {
			struct cd_id disk_id;
		} create;
		struct {
			struct cd_id disk_id;
		} setup;
		struct {
			struct cd_id disk_id;
		} delete;
	} u;
};

#pragma pack(pop)
