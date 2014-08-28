# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
import os
import logging.config
import logging
import sys
import inspect
import cmd
import uuid

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))

import settings

logging.config.dictConfig(settings.LOGGING)

log = logging.getLogger('main')
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
log.addHandler(ch)


BS = 65536
CDISK_MNT_DIR = '/mnt/cdisk'
FS_TYPE = 'ext4'
CDISK_DEV = '/dev/cdisk'

def test():
    loaded = False
    created = False
    try:
	image_size = 10*1024*1024*1024
	image_file = os.path.abspath("test.img")
        disk_num = 1
        cmd.exec_cmd2('insmod ' + settings.CDISK_MOD_KO_P, throw = True)
        loaded = True
	cmd.exec_cmd2("rm -r -f " + image_file)
	cmd.exec_cmd2("qemu-img create -f qcow2 " + image_file + " " + str(image_size), throw = True)
	cmd.exec_cmd2(settings.CDISK_CTL_P + ' --create ' + str(disk_num) + " " + image_file, throw = True)
        created = True
	#cmd.exec_cmd2("dd if=/dev/zero of=" + CDISK_DEV + str(disk_num) + " bs=" + str(BS) + " count=" + str(image_size//BS), throw = True)
	cmd.exec_cmd2("fio " + os.path.join(currentdir, "write.ini"), throw = True)
        cmd.exec_cmd2("fio " + os.path.join(currentdir, "read.ini"), throw = True)
        cmd.exec_cmd2("fio " + os.path.join(currentdir, "rw.ini"), throw = True)
        cmd.exec_cmd2("fio " + os.path.join(currentdir, "write.ini"), throw = True)
        cmd.exec_cmd2('qemu-img check ' + image_file, throw = True)
    except Exception as e:
        log.exception(str(e))
    finally:
        try:
	    if created:
		cmd.exec_cmd2(settings.CDISK_CTL_P + ' --delete ' + str(disk_num))
            if loaded:
	    	cmd.exec_cmd2('rmmod ' + settings.CDISK_MOD, throw = True)
        except Exception as e:
            log.exception(str(e))

if __name__=="__main__":
    test()
