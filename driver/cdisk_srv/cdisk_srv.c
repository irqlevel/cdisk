#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/highmem.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/cdrom.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/cdev.h>
#include <linux/kthread.h>
#include <linux/time.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/miscdevice.h>
#include <asm/uaccess.h>


#include <cdisk_srv.h>
#include <cdisk_srv_cmd.h>
#include <klog.h>
#include <ksocket.h>

MODULE_LICENSE("GPL");

#define __SUBCOMPONENT__ "cdisk_srv"
#define __LOGNAME__ "cdisk_srv.log"

#define LISTEN_RESTART_TIMEOUT_MS 5000

#define CDISK_SRV_NAME "cdisk_srv"

#define CDISK_SRV_PORT 9111


static struct task_struct *csrv_thread;

static struct socket *csrv_sock = NULL;

static DEFINE_MUTEX(csrv_lock);

static int csrv_stopping = 0;

static LIST_HEAD(con_list);
static DEFINE_MUTEX(con_list_lock);

struct csrv_con {
	struct task_struct 	*thread;
	struct socket 		*sock;
	struct list_head	con_list;
};

static void csrv_con_wait(struct csrv_con *con)
{
	kthread_stop(con->thread);
}

static void csrv_con_free(struct csrv_con *con)
{
	klog(KL_DBG, "releasing sock %p", con->sock);
	ksock_release(con->sock);
	put_task_struct(con->thread);
	kfree(con);
}

static int csrv_con_thread_routine(void *data)
{
	struct csrv_con *con = (struct csrv_con *)data;
	BUG_ON(con->thread != current);

	klog(KL_DBG, "inside con thread %p, sock %p", con->thread, con->sock);


	klog(KL_DBG, "closing sock %p", con->sock);
	if (!csrv_stopping) {
		mutex_lock(&con_list_lock);
		if (!list_empty(&con->con_list))
			list_del_init(&con->con_list);	
		else
			con = NULL;
		mutex_unlock(&con_list_lock);

		if (con)
			csrv_con_free(con);
	}

	return 0;
}

static struct csrv_con *csrv_con_start(struct socket *sock)
{
	struct csrv_con *con = kmalloc(sizeof(struct csrv_con), GFP_KERNEL);
	int error = -EINVAL;
	if (!con) {
		klog(KL_ERR, "cant alloc csrv_con");
		return NULL;
	}

	con->thread = NULL;
	con->sock = sock;
	con->thread = kthread_create(csrv_con_thread_routine, con, "cdisk_srv_con");
	if (IS_ERR(con->thread)) {
		error = PTR_ERR(con->thread);
		klog(KL_ERR, "kthread_create err=%d", error);
		goto out;
	}

	get_task_struct(con->thread);	
	mutex_lock(&con_list_lock);
	list_add_tail(&con->con_list, &con_list);
	mutex_unlock(&con_list_lock);

	wake_up_process(con->thread);

	return con;	
out:
	kfree(con);
	return NULL;
}

static int csrv_thread_routine(void *data)
{
	struct socket *lsock = NULL;
	struct socket *con_sock = NULL;
	struct csrv_con *con = NULL;
	int error = 0;

	while (!kthread_should_stop()) {
		if (!csrv_sock) {
			error = ksock_listen(&lsock, INADDR_ANY, CDISK_SRV_PORT, 5);
			if (error) {
				klog(KL_ERR, "csock_listen err=%d", error);
				msleep_interruptible(LISTEN_RESTART_TIMEOUT_MS);
				continue;
			} else {
				mutex_lock(&csrv_lock);
				csrv_sock = lsock;
				mutex_unlock(&csrv_lock);
			}
		}

		if (csrv_sock && !csrv_stopping) {
			klog(KL_DBG, "accepting");
			error = ksock_accept(&con_sock, csrv_sock);
			if (error) {
				if (error == -EAGAIN)
					klog(KL_WRN, "csock_accept err=%d", error);
				else
					klog(KL_ERR, "csock_accept err=%d", error);
				continue;
			}
			klog(KL_DBG, "accepted con_sock=%p", con_sock);

			if (!csrv_con_start(con_sock)) {
				klog(KL_ERR, "csrv_con_start failed");
				ksock_release(con_sock);
				continue;
			}
		}
	}

	error = 0;
	klog(KL_DBG, "releasing listen socket");
	
	mutex_lock(&csrv_lock);
	lsock = csrv_sock;
	csrv_sock = NULL;
	mutex_unlock(&csrv_lock);

	if (lsock)
		ksock_release(lsock);
	
	klog(KL_DBG, "releasing cons");

	for (;;) {
		con = NULL;
		mutex_lock(&con_list_lock);
		if (!list_empty(&con_list)) {
			con = list_first_entry(&con_list, struct csrv_con, con_list);
			list_del_init(&con->con_list);		
		}
		mutex_unlock(&con_list_lock);
		if (!con)
			break;

		csrv_con_wait(con);
		csrv_con_free(con);
	}

	klog(KL_DBG, "released cons");	
	return 0;
}

static int csrv_open(struct inode *inode, struct file *file)
{
	klog(KL_DBG, "in open");
	if (!try_module_get(THIS_MODULE)) {
		klog(KL_ERR, "cant ref module");
		return -EINVAL;
	}
	klog(KL_DBG, "opened");
	return 0;
}

static int csrv_release(struct inode *inode, struct file *file)
{
	klog(KL_DBG, "in release");
	module_put(THIS_MODULE);
	klog(KL_DBG, "released");
	return 0;
}

static long csrv_ioctl(struct file *file, unsigned int code, unsigned long arg)
{
	int error = -EINVAL;
	struct cdisk_srv_cmd *cmd = NULL;	

	cmd = kmalloc(sizeof(struct cdisk_srv_cmd), GFP_KERNEL);
	if (!cmd) {
		error = -ENOMEM;
		goto out;
	}

	if (copy_from_user(cmd, (const void *)arg, sizeof(struct cdisk_srv_cmd))) {
		error = -EFAULT;
		goto out_free_cmd;
	}
	
	error = 0;
	switch (code) {
		case IOCTL_DISK_CREATE:
			cmd->error = -EINVAL;	
			break;
		case IOCTL_DISK_DELETE:
			cmd->error = -EINVAL;
			break;
		case IOCTL_DISK_SETUP:
			cmd->error = -EINVAL;
			break;
		default:
			klog(KL_ERR, "unknown ioctl=%d", cmd);
			error = -EINVAL;
			break;
	}
	
	if (copy_to_user((void *)arg, cmd, sizeof(struct cdisk_srv_cmd))) {
		error = -EFAULT;
		goto out_free_cmd;
	}
	
	return 0;
out_free_cmd:
	kfree(cmd);
out:
	return error;	
}

static const struct file_operations csrv_fops = {
	.owner = THIS_MODULE,
	.open = csrv_open,
	.release = csrv_release,
	.unlocked_ioctl = csrv_ioctl,
};

static struct miscdevice csrv_misc = {
	.fops = &csrv_fops,
	.minor = MISC_DYNAMIC_MINOR,
	.name = CDISK_SRV_NAME,	
};


static int __init csrv_init(void)
{	
	int error = -EINVAL;
	
	error = klog_init(KL_ERR_L);
	if (error) {
		printk(KERN_ERR "klog_init failed with err=%d", error);
		goto out;
	}

	klog(KL_DBG, "initing");

	error = misc_register(&csrv_misc);
	if (error) {
		klog(KL_ERR, "misc_register err=%d", error);
		goto out_klog_release; 
	}
	csrv_thread = kthread_create(csrv_thread_routine, NULL, "cdisk_srv");
	if (IS_ERR(csrv_thread)) {
		error = PTR_ERR(csrv_thread);
		klog(KL_ERR, "kthread_create err=%d", error);
		goto out_misc_release;
	}
	get_task_struct(csrv_thread);
	wake_up_process(csrv_thread);

	klog(KL_DBG, "inited");
	return 0;

out_misc_release:
	misc_deregister(&csrv_misc);
out_klog_release:
	klog_release();
out:
	return error;
}

static void __exit csrv_exit(void)
{
	klog(KL_DBG, "exiting");
	
	csrv_stopping = 1;

	mutex_lock(&csrv_lock);
	if (csrv_sock)
		ksock_abort_accept(csrv_sock);
	mutex_unlock(&csrv_lock);

	kthread_stop(csrv_thread);
	put_task_struct(csrv_thread);

	misc_deregister(&csrv_misc);

	klog(KL_DBG, "exited");
	klog_release();
}

module_init(csrv_init);
module_exit(csrv_exit);

