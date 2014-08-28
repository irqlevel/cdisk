#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <memory.h>
#include <errno.h>
#include <malloc.h>

#include <cdisk_cmd.h>

static void usage(void)
{
    	printf("Usage:\ncdisk_ctl --create\ncdisk_ctl --delete DISK_NUM\n");
}

static int cdisk_ctl_open(int *fd)
{
	int dev_fd = -1;
	int error = -EINVAL;

	dev_fd = open("/dev/cdiskctl", 0);
	if (dev_fd == -1) {
		error = errno;
		printf("cant open ctl disk device, error=%d\n", error);
		return error;
	}
	*fd = dev_fd;
	return 0;
}

static int cdisk_create(int disk_num, char *fname)
{
	int error = -EINVAL;
	struct cdisk_cmd params;
	int fd;

	error = cdisk_ctl_open(&fd);
	if (error)
		return error;
	
	memset(&params, 0, sizeof(struct cdisk_cmd));

	params.u.create.disk_num = disk_num;
	snprintf(params.u.create.fname, sizeof(params.u.create.fname), "%s", fname);

	error = ioctl(fd, IOCTL_DISK_CREATE, &params);
	if (error)
		goto out;
	
	error = params.error;
	if (error)
		goto out;

out:
	close(fd);
	return error;
}

static int cdisk_delete(int disk_num)
{
	int error = -EINVAL;
	int fd = -1;
	struct cdisk_cmd params;

	error = cdisk_ctl_open(&fd);
	if (error)
		return error;
	
	memset(&params, 0, sizeof(struct cdisk_cmd));
	params.u.delete.disk_num = disk_num;

	error = ioctl(fd, IOCTL_DISK_DELETE, &params);
	if (error)
		goto out;

	error = params.error;
	if (error)
		goto out;

out:
	close(fd);
	return error;
}


#define CREATE_OPT "--create"
#define DELETE_OPT "--delete"

int main(int argc, char *argv[])
{
    	int error = -EINVAL;
    
    	if (argc < 2) {
    		usage();
    	    	error = -EINVAL;
		goto out;
    	}
    
    	if (strncmp(argv[1], CREATE_OPT, strlen(CREATE_OPT) + 1) == 0) {
		int disk_num = -1;
		char *fname = NULL;
		if (argc != 4) {
			usage();
			error = -EINVAL;
			goto out;
		}
		disk_num = strtol(argv[2], NULL, 10);
		fname = argv[3];
		printf("disk num for creation is %d, fname=%s\n", disk_num, fname);
		error = cdisk_create(disk_num, fname);
		if (!error)
			printf("created disk with num=%d\n", disk_num);
		goto out;
    	} else if (strncmp(argv[1], DELETE_OPT, strlen(DELETE_OPT) + 1) == 0) {
		int disk_num = -1;
		if (argc != 3) {
			usage();
			error = -EINVAL;
			goto out;
		}
		disk_num = strtol(argv[2], NULL, 10);
		printf("disk num for deletion is %d\n", disk_num);
		error = cdisk_delete(disk_num);
		if (!error)
			printf("deleted disk with num=%d\n", disk_num);
		goto out;	
	} else {
		usage();
		error = -EINVAL;
		goto out;
	}

out:
	if (error)
		printf("error - %d\n", error);
	else
		printf("success\n");

	return error;
}

