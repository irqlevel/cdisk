/*
*/

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
#include <linux/file.h>
#include <linux/rbtree.h>
#include <linux/sort.h>
#include <asm/uaccess.h>
#include <linux/version.h>


#include <cdisk_cmd.h>
#include <qcow_image.h>
#include <cdisk.h>
#include <klog.h>

MODULE_LICENSE("GPL");

#define __SUBCOMPONENT__ "cdisk"
#define __LOGNAME__ "cdisk.log"

#define SECTOR_SHIFT		9
#define PAGE_SECTORS_SHIFT	(PAGE_SHIFT - SECTOR_SHIFT)
#define PAGE_SECTORS		(1 << PAGE_SECTORS_SHIFT)
#define SECTOR_SIZE  (PAGE_SIZE/PAGE_SECTORS)

#define CDISK_FLAGS_SHUTDOWN	(1 << 1)

#define CDISK_NUMS 256

#define CDISK_BLOCK_DEV_NAME	"cdisk"
#define CDISKCTL_CHAR_DEV_NAME 	"cdiskctl"

#define CDISK_TIMER_TIMEOUT_MSECS	1000
#define CDISK_NAME_MAX_SZ	20

#define CDISK_MAPS_MAX		64


struct cdisk_request {
	struct list_head req_list;
	struct bio *bio;
};

#define CDISK_EVENT_AGE 1

struct cdisk_event {
	struct list_head event_list;
	int type;
	void *context;
};

struct cdisk_map {
	spinlock_t		nodes_lock;
	struct radix_tree_root	nodes;
	spinlock_t		lru_list_lock;
	struct list_head	lru_list;
	struct rb_node		tree_link;
	int			nr_nodes;
};

#define CDISK_MN_DIRTY 	(1 << 1)
#define CDISK_MN_PINNED	(1 << 2)

struct cdisk_map_node {
	struct list_head 	lru_list;
	unsigned long		index;
	struct page 		**pages;
	int			*pg_flags;
	int			nr_pages;
	int 			flags;
	atomic_t		refs;
	unsigned long		age;
};

#define CDISK_MN_PAGE_READ	(1 << 1)
#define CDISK_MN_PAGE_DIRTY	(1 << 2)

struct cdisk_device {
	int			number;
	int			flags;
	int			num_blocks;
	struct request_queue	*queue;
	struct gendisk		*disk;
	struct list_head	devices_list;
	spinlock_t		lock;
	atomic_t		writes;
	atomic_t		reads;
	atomic_t		write_bytes;
	atomic_t		read_bytes;
	struct task_struct	*thread;
	wait_queue_head_t	waitq;
	spinlock_t		req_list_lock;
	struct list_head	req_list;
	spinlock_t		event_list_lock;
	struct list_head	event_list;
	char			name[CDISK_NAME_MAX_SZ];
	struct	file 		*file;
	struct cdisk_map	map;
	int			nr_maps_max;
	__u32			version;
	__u64			l1_table_offset;
	__u32			l1_size;
	__u64			refcount_table_offset;
	__u32			refcount_table_clusters;
	__u32			cluster_bits;
	__u32			cluster_size;
	__u64			size;	
};

static struct kmem_cache *cdisk_req_cachep;
static struct kmem_cache *cdisk_mn_cachep;
static struct kmem_cache *cdisk_event_cachep;

static struct workqueue_struct *cdisk_wq;

static struct timer_list cdisk_timer;

static int cdisk_num_alloc(void);
static void cdisk_num_free(int num);
static void cdisk_del_one(struct cdisk_device *device);
static struct cdisk_device *cdisk_alloc(int num);
static void cdisk_free(struct cdisk_device *device);

static void cdisk_stats_dump(struct cdisk_device *device);
static int cdisk_discard(struct cdisk_device *device, sector_t sector, u32 len);
static int cdisk_do_bvec(struct cdisk_device *device, struct page *page, u32 len, u32 off, int rw, sector_t sector);

static int file_read(struct file *file, const void *buf, u32 len, loff_t *off);
static int file_write(struct file *file, const void *buf, u32 len, loff_t *off);
static int file_sync(struct file *file);

static int cdisk_event_create_queue(struct cdisk_device *device, int type, void *context);
static void cdisk_device_age(struct cdisk_device *device);

static char cdisk_nums[CDISK_NUMS];
static DEFINE_MUTEX(cdisk_nums_lock);

static DEFINE_MUTEX(cdisk_devices_lock);
static LIST_HEAD(cdisk_devices);

static int cdisk_block_major = -1;

static atomic_t cdisk_mn_count = ATOMIC_INIT(0);

static void cdisk_map_node_free(struct cdisk_map_node *node)
{
	int i;

	if (node->pg_flags)
		kfree(node->pg_flags);

	if (node->pages) {
		for (i = 0; i < node->nr_pages; i++) {
			if (node->pages[i])
				__free_page(node->pages[i]);
		}
		kfree(node->pages);
	}
	kmem_cache_free(cdisk_mn_cachep, node);
	atomic_dec(&cdisk_mn_count);
}

static void cdisk_map_node_deref(struct cdisk_map_node *node)
{
	if (atomic_read(&node->refs) < 1) {
		klog(KL_ERR, "node=%p, index=%lld", node, node->index);
	}

	BUG_ON(atomic_read(&node->refs) < 1);
	if (atomic_dec_and_test(&node->refs)) {
		cdisk_map_node_free(node);
	}
}

static struct cdisk_map_node *cdisk_map_node_alloc(int nr_pages)
{
	struct cdisk_map_node *node;
	int i;

	node = kmem_cache_alloc(cdisk_mn_cachep, GFP_NOIO);
	if (!node) {
		klog(KL_ERR, "cant alloc node");
		return NULL;
	}
	atomic_inc(&cdisk_mn_count);
	memset(node, 0, sizeof(*node));
	atomic_set(&node->refs, 1);
	//node->age |= (1UL << 63);
	
	node->pg_flags = kzalloc(nr_pages*sizeof(int *), GFP_NOIO);
	if (!node->pg_flags) {
		klog(KL_ERR, "cant alloc flags arr");
		goto fail;
	}

	node->pages = kzalloc(nr_pages*sizeof(struct page *), GFP_NOIO);
	if (!node->pages) {
		klog(KL_ERR, "cant alloc pages arr");
		goto fail;
	}
	
	node->nr_pages = nr_pages;
	for (i = 0; i < node->nr_pages; i++) {
		node->pages[i] = alloc_page(GFP_NOIO);
		if (!node->pages[i]) {
			klog(KL_ERR, "cant alloc page");
			goto fail;
		}
	}

	return node;
fail:
	cdisk_map_node_deref(node);
	return NULL;	
}

static void cdisk_map_node_age(struct cdisk_map_node *node)
{
	node->age = node->age >> 1;
}

static void cdisk_map_init(struct cdisk_map *map)
{
	spin_lock_init(&map->nodes_lock);
	spin_lock_init(&map->lru_list_lock);
	INIT_RADIX_TREE(&map->nodes, GFP_ATOMIC);
	INIT_LIST_HEAD(&map->lru_list);
	map->nr_nodes = 0;
}

static int cdisk_map_insert(struct cdisk_map *map, struct cdisk_map_node *node)
{
	int err;

	if (radix_tree_preload(GFP_NOIO))
		return -ENOMEM;

	spin_lock(&map->nodes_lock);
	if (radix_tree_insert(&map->nodes, node->index, node)) {
		err = -EINVAL;
	} else {
		map->nr_nodes++;
		atomic_inc(&node->refs);
		err = 0;
	}
	spin_unlock(&map->nodes_lock);
	radix_tree_preload_end();

	if (!err) {
		spin_lock(&map->lru_list_lock);		
		list_add_tail(&node->lru_list, &map->lru_list);
		atomic_inc(&node->refs);
		spin_unlock(&map->lru_list_lock);
	}

	return 0;
}

static struct cdisk_map_node *cdisk_map_lookup(struct cdisk_map *map, unsigned long index)
{
	struct cdisk_map_node *node;

	spin_lock(&map->nodes_lock);
	node = radix_tree_lookup(&map->nodes, index);
	if (node)
		atomic_inc(&node->refs);
	spin_unlock(&map->nodes_lock);

	if (node) {
		node->age |= (1UL << 63);
		spin_lock(&map->lru_list_lock);
		list_del(&node->lru_list);
		list_add_tail(&node->lru_list, &map->lru_list);
		spin_unlock(&map->lru_list_lock);
	}

	return node;
}

static struct cdisk_map_node *cdisk_map_remove(struct cdisk_map *map, unsigned long index)
{
	struct cdisk_map_node *node;

	spin_lock(&map->nodes_lock);
	node = radix_tree_delete(&map->nodes, index);
	if (node) {
		BUG_ON(node->index != index);
		map->nr_nodes--;
		cdisk_map_node_deref(node);
	}
	spin_unlock(&map->nodes_lock);
	if (node) {
		spin_lock(&map->lru_list_lock);
		list_del(&node->lru_list);
		cdisk_map_node_deref(node);
		spin_unlock(&map->lru_list_lock);
	}

	return node;
}

/*
static void cdisk_map_lru_free(struct cdisk_map *map)
{
	struct cdisk_map_node *node = NULL, *removed;

	spin_lock(&map->lru_list_lock);
	if (!list_empty(&map->lru_list)) {
		node = list_first_entry(&map->lru_list, struct cdisk_map_node, lru_list);
		if (!(node->flags & CDISK_MN_DIRTY) && !(node->flags & CDISK_MN_PINNED)) {
			list_del(&node->lru_list);
			cdisk_map_node_deref(node);
		} else {
			list_del(&node->lru_list);
			list_add_tail(&node->lru_list, &map->lru_list);
			node = NULL;
		}
	}
	spin_unlock(&map->lru_list_lock);

	if (node) {
		spin_lock(&map->nodes_lock);
		removed = radix_tree_delete(&map->nodes, node->index);
		BUG_ON(removed != node);
		map->nr_nodes--;
		cdisk_map_node_deref(node);
		spin_unlock(&map->nodes_lock);
		cdisk_map_node_deref(node);
	}
}
*/
static int cdisk_map_node_age_cmp(const void *a, const void *b)
{
	struct cdisk_map_node *node_a = *((struct cdisk_map_node **)a);
	struct cdisk_map_node *node_b = *((struct cdisk_map_node **)b);

	if (node_a->age > node_b->age)
		return 1;
	else if (node_a->age < node_b->age)
		return -1;
	else
		return 0;
}

static void cdisk_map_node_ptr_swap(void *a, void *b, int size)
{
	struct cdisk_map_node **node_a = a;
	struct cdisk_map_node **node_b = b;
	struct cdisk_map_node *tmp;

	tmp = *node_a;
	*node_a = *node_b;
	*node_b = tmp;
}

static void cdisk_device_map_lru_frees(struct cdisk_device *device)
{
	struct cdisk_map_node *batch[4];
	int nr_found;
	unsigned long index, first_index = 0;
	struct cdisk_map_node *node, *removed, *prev;
	struct cdisk_map_node **nodes;
	struct page *page;
	int nr_nodes = 0, nodes_limit = PAGE_SIZE/sizeof(struct cdisk_map_node *);

	if (device->map.nr_nodes <= device->nr_maps_max)
		return;

	page = alloc_page(GFP_NOIO);
	if (!page) {
		klog(KL_ERR, "no memory");
		return;
	}
	nodes = kmap(page);
	for (;;) {
		spin_lock(&device->map.nodes_lock);
		nr_found = radix_tree_gang_lookup(&device->map.nodes, (void **)batch, first_index, ARRAY_SIZE(batch));
		for (index = 0; index < nr_found; index++) {
			node = batch[index];
			atomic_inc(&node->refs);
			if (node->index >= first_index)
				first_index = node->index + 1;
		}
		spin_unlock(&device->map.nodes_lock);
		if (nr_found == 0)
			break;

		for (index = 0; index < nr_found; index++) {
			node = batch[index];
			if (!(node->flags & CDISK_MN_DIRTY) && !(node->flags & CDISK_MN_PINNED)) {
				if (nr_nodes < nodes_limit) {
					nodes[nr_nodes++] = node; 
				} else {
					klog(KL_ERR, "nr_nodes=%d vs. nodes_limit=%d", nr_nodes, nodes_limit);
					goto release;
				}
			} else {	
				cdisk_map_node_deref(node);
			}
		}		
	}

	sort(nodes, nr_nodes, sizeof(struct cdisk_map_node *), cdisk_map_node_age_cmp, cdisk_map_node_ptr_swap);
	prev = NULL;
	for (index = 0; index < nr_nodes; index++) {
		node = nodes[index];
		if (prev && (prev->age > node->age)) {
			int i;
			struct cdisk_map_node *n;
			for (i = 0; i < nr_nodes; i++) {
				n = nodes[i];
				klog(KL_ERR, "node=%p, age=%llx, index=%lld", n, n->age, n->index);
			}
			BUG_ON(1);
		}
		prev = node;
		if (device->map.nr_nodes > device->nr_maps_max) {
			//klog(KL_INF, "going to remove node=%p, age=%lld", node, node->age);
			removed = cdisk_map_remove(&device->map, node->index);
			BUG_ON(removed != node);
			cdisk_map_node_deref(node);
		}
	}

release:
	for (index = 0; index < nr_nodes; index++) {
		node = nodes[index];
		cdisk_map_node_deref(node);
	}

	kunmap(page);
	__free_page(page);
}

static int cdisk_device_write_map(struct cdisk_device *device, struct cdisk_map_node *node)
{
	void *va;
	loff_t off;
	int i;
	int err;

	klog(KL_DBG, "write node=%p, index=%lld, age=%llx, flags=%d", node, node->index, node->age, node->flags);

	for (i = 0; i < node->nr_pages; i++) {
		if (node->pg_flags[i] & CDISK_MN_PAGE_DIRTY) {
			BUG_ON(!(node->pg_flags[i] & CDISK_MN_PAGE_READ));
			va = kmap(node->pages[i]);
			off = node->index*device->cluster_size + i*PAGE_SIZE;
			err = file_write(device->file, va, PAGE_SIZE, &off);
			kunmap(node->pages[i]);
			if (err) {
				klog(KL_ERR, "cant write page at %lld, err=%d", off, err);
				goto out;
			}
			node->pg_flags[i] &= ~CDISK_MN_PAGE_DIRTY;
		}
	}
	err = 0;
out:
	return err;
}

static void cdisk_device_map_dump(struct cdisk_device *device)
{
	struct cdisk_map_node *batch[4];
	int nr_found;
	unsigned long index, first_index = 0;
	struct cdisk_map_node *node;

	for (;;) {
		spin_lock(&device->map.nodes_lock);
		nr_found = radix_tree_gang_lookup(&device->map.nodes, (void **)batch, first_index, ARRAY_SIZE(batch));
		for (index = 0; index < nr_found; index++) {
			node = batch[index];
			atomic_inc(&node->refs);
			if (node->index >= first_index)
				first_index = node->index + 1;
		}
		spin_unlock(&device->map.nodes_lock);
		if (nr_found == 0) {
			break;
		}

		for (index = 0; index < nr_found; index++) {
			node = batch[index];
			klog(KL_INF, "node=%p index=%lld flags=%d age=%p refs=%d", node, node->index, 
				node->flags, node->age, atomic_read(&node->refs));
			cdisk_map_node_deref(node);
		}
	}
	//file_sync(device->file);	
}

static void cdisk_device_write_dirties(struct cdisk_device *device)
{
	struct cdisk_map_node *batch[4];
	int nr_found;
	unsigned long index, first_index = 0;
	struct cdisk_map_node *node;
	int err;

	for (;;) {
		spin_lock(&device->map.nodes_lock);
		nr_found = radix_tree_gang_lookup(&device->map.nodes, (void **)batch, first_index, ARRAY_SIZE(batch));
		for (index = 0; index < nr_found; index++) {
			node = batch[index];
			atomic_inc(&node->refs);
			if (node->index >= first_index)
				first_index = node->index + 1;
		}
		spin_unlock(&device->map.nodes_lock);
		if (nr_found == 0)
			break;

		for (index = 0; index < nr_found; index++) {
			node = batch[index];
			if (node->flags & CDISK_MN_DIRTY) {
				err = cdisk_device_write_map(device, node);
				if (!err)
					node->flags &= ~CDISK_MN_DIRTY;
				else
					klog(KL_ERR, "cant write map of dev=%p, node=%p, index=%lld", device, node, node->index);
			}
			cdisk_map_node_deref(node);
		}
	}
	//file_sync(device->file);	
}

static void cdisk_device_map_compact(struct cdisk_device *device)
{
	for (;;) {
		if (device->map.nr_nodes > device->nr_maps_max) {
			cdisk_device_map_lru_frees(device);
			if (device->map.nr_nodes > device->nr_maps_max)
				cdisk_device_write_dirties(device);
		} else {
			break;
		}
	}
}

static void cdisk_map_nodes_free(struct cdisk_map *map)
{
	struct cdisk_map_node *batch[4];
	int nr_found, index;
	struct cdisk_map_node *node, *removed;

	klog(KL_DBG, "map->nr_nodes=%d", map->nr_nodes);
	klog(KL_DBG, "cdisk_mn_count=%d", atomic_read(&cdisk_mn_count));

	for (;;) {
		spin_lock(&map->nodes_lock);
		nr_found = radix_tree_gang_lookup(&map->nodes, (void **)batch, 0, ARRAY_SIZE(batch));
		for (index = 0; index < nr_found; index++) {
			node = batch[index];
			atomic_inc(&node->refs);
		}
		spin_unlock(&map->nodes_lock);
		if (nr_found == 0)
			break;

		for (index = 0; index < nr_found; index++) {
			node = batch[index];
			removed = cdisk_map_remove(map, node->index);
			BUG_ON(removed != node);
			cdisk_map_node_deref(node);
			cdisk_map_node_deref(node);
		}
	}

	klog(KL_DBG, "cdisk_mn_count=%d", atomic_read(&cdisk_mn_count));
	klog(KL_DBG, "map->nr_nodes=%d", map->nr_nodes);
	BUG_ON(map->nr_nodes != 0);
	BUG_ON(!list_empty(&map->lru_list));
}


static int cdisk_device_get_map(struct cdisk_device *device, unsigned long index, struct cdisk_map_node **pnode)
{
	struct cdisk_map_node *node;
	int err;

	*pnode = NULL;
	node = cdisk_map_lookup(&device->map, index);
	if (node) {
		*pnode = node;
		return 0;
	}

	cdisk_device_map_compact(device);
	node = cdisk_map_node_alloc(device->cluster_size/PAGE_SIZE);
	if (!node) {
		klog(KL_ERR, "cant alloc map node");
		return -ENOMEM;
	}

	node->index = index;
	err = cdisk_map_insert(&device->map, node);
	if (err) {
		cdisk_map_node_deref(node);
		klog(KL_ERR, "cant insert map node, err=%lld", err);
		return err;
	}
	atomic_inc(&node->refs);
	*pnode = node;
	return 0;
}


static int cdisk_num_use(int num)
{
	int error = -EINVAL;
	
	if (num < 0 || num >= CDISK_NUMS)
		return -EINVAL;

	mutex_lock(&cdisk_nums_lock);
	if (cdisk_nums[num] == 0) {
		cdisk_nums[num] = 1;
		error = 0;
	} else {
		error = -EBUSY;
	}
	mutex_unlock(&cdisk_nums_lock);
	return error;
}

static int cdisk_num_alloc(void)
{
	int i = 0;
	int num = -1;

	mutex_lock(&cdisk_nums_lock);
	for (i = 0; i < CDISK_NUMS; i++) {
		if (cdisk_nums[i] == 0) {
			cdisk_nums[i] = 1;
			num = i;
			break;
		}
	}
	mutex_unlock(&cdisk_nums_lock);
	return num;
}

static void cdisk_num_free(int num) 
{
	if (num < 0 || num >= CDISK_NUMS)
		return;

	mutex_lock(&cdisk_nums_lock);
	cdisk_nums[num] = 0;
	mutex_unlock(&cdisk_nums_lock);	
}

static void cdisk_thread_wakeup(struct cdisk_device *device)
{
	wake_up_interruptible(&device->waitq);
}

static void cdisk_thread_wait(struct cdisk_device *device)
{
	wait_event_interruptible(device->waitq, (kthread_should_stop() 
		|| !list_empty(&device->req_list) || !list_empty(&device->event_list)));
}

static void cdisk_request_free(struct cdisk_request *request)
{
	bio_put(request->bio);
	kmem_cache_free(cdisk_req_cachep, request);	
}

static void cdisk_request_cancel(struct cdisk_device *device, struct cdisk_request *request)
{
	struct bio *bio = request->bio;
	bio_endio(bio, -EIO);
	cdisk_request_free(request);	
}

static void cdisk_request_handle(struct cdisk_device *device, struct cdisk_request *request)
{
	struct bio *bio = request->bio;
	int rw, idx;
	struct bio_vec *bvec;
	sector_t sector;
	int err = -EIO;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,14,0)
	sector = bio->bi_sector;
#else
	sector = bio->bi_iter.bi_sector;
#endif
	if (bio_end_sector(bio) > get_capacity(device->disk))
		goto out;

	if (unlikely(bio->bi_rw & REQ_DISCARD)) {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,14,0)
		err = cdisk_discard(device, sector, bio->bi_size);
#else
		err = cdisk_discard(device, sector, bio->bi_iter.bi_size);
#endif
		if (err) {
			klog(KL_ERR, "disk discard failed with err=%d", err);
		}
		goto out;
	}	
	rw = bio_rw(bio);
	if (rw == READA)
		rw = READ;

	for (idx = 0; idx < bio->bi_vcnt; idx++) {
		bvec = bio->bi_io_vec + idx;
		err = cdisk_do_bvec(device, bvec->bv_page, bvec->bv_len, bvec->bv_offset, rw, sector);
		if (err) {
			klog(KL_ERR, "disk bio bvec failed with err=%d", err);
			break;
		}
		sector+= bvec->bv_len >> SECTOR_SHIFT;
	}
out:	
	bio_endio(bio, err);
	cdisk_request_free(request);	
}
static void cdisk_event_free(struct cdisk_event *event)
{
	kmem_cache_free(cdisk_event_cachep, event);
}

static void cdisk_event_handle(struct cdisk_device *device, struct cdisk_event *event)
{
	switch (event->type) {
		case CDISK_EVENT_AGE:
			cdisk_device_age(device);
			break;
		default:
			klog(KL_ERR, "unknown event=%p - %d", event, event->type);
			break;
	}
	cdisk_event_free(event);	
}

static void cdisk_event_cancel(struct cdisk_device *device, struct cdisk_event *event)
{
	cdisk_event_free(event);
}

static int cdisk_event_create_queue(struct cdisk_device *device, int type, void *context)
{
	struct cdisk_event *event;
	int queued = 0;
	int err;
	unsigned long irqf;

	if (device->flags & CDISK_FLAGS_SHUTDOWN) {
		err = -EINVAL;
		goto out;
	}

	event = kmem_cache_alloc(cdisk_event_cachep, GFP_NOFS);
	if (!event) {
		klog(KL_ERR, "request alloc failed");
		err = -ENOMEM;
		goto out;
	}

	if (device->flags & CDISK_FLAGS_SHUTDOWN) {
		err = -EINVAL;
		cdisk_event_free(event);
		goto out;
	}	

	event->type = type;
	event->context = context;
	spin_lock_irqsave(&device->event_list_lock, irqf);
	if (!(device->flags & CDISK_FLAGS_SHUTDOWN)) {
		list_add_tail(&event->event_list, &device->event_list);
		queued = 1;
	}
	spin_unlock_irqrestore(&device->event_list_lock, irqf);
	
	if (queued) {
		cdisk_thread_wakeup(device);
		err = 0;
	} else {
		cdisk_event_free(event);
		err = -EINVAL;
	}

out:
	return err;
}


static int cdisk_request_create_queue(struct cdisk_device *device, struct bio *bio)
{
	struct cdisk_request *request;
	int queued = 0;
	int err;
	unsigned long irqf;

	if (device->flags & CDISK_FLAGS_SHUTDOWN) {
		err = -EINVAL;
		goto out;
	}

	request = kmem_cache_alloc(cdisk_req_cachep, GFP_NOFS);
	if (!request) {
		klog(KL_ERR, "request alloc failed");
		err = -ENOMEM;
		goto out;
	}

	if (device->flags & CDISK_FLAGS_SHUTDOWN) {
		err = -EINVAL;
		cdisk_request_free(request);
		goto out;
	}	

	bio_get(bio);
	request->bio = bio;
	spin_lock_irqsave(&device->req_list_lock, irqf);
	if (!(device->flags & CDISK_FLAGS_SHUTDOWN)) {
		list_add_tail(&request->req_list, &device->req_list);
		queued = 1;
	}
	spin_unlock_irqrestore(&device->req_list_lock, irqf);
	
	if (queued) {
		cdisk_thread_wakeup(device);
		err = 0;
	} else {
		cdisk_request_free(request);
		err = -EINVAL;
	}

out:
	return err;
}

static void cdisk_make_request(struct request_queue *q, struct bio *bio)
{
	struct block_device *bdev = bio->bi_bdev;
	struct cdisk_device *device = bdev->bd_disk->private_data;
	int err = -EIO;

	err = cdisk_request_create_queue(device, bio);
	if (!err)
		return;

	bio_endio(bio, err);
}

static int cdisk_thread_routine(void *data)
{
	struct cdisk_device *device = data;
	struct cdisk_event *event;
	struct cdisk_request *request;

	while (!kthread_should_stop()) {
		/* Process requests */
		if (!list_empty(&device->req_list)) {
			spin_lock(&device->req_list_lock);
			if (!list_empty(&device->req_list)) {
				request = list_first_entry(&device->req_list, struct cdisk_request, req_list);
				list_del(&request->req_list);
			} else {
				request = NULL;	
			}
			spin_unlock(&device->req_list_lock);
			if (request)
				cdisk_request_handle(device, request);
		}
		/* Process events */
		if (!list_empty(&device->event_list)) {
			spin_lock(&device->event_list_lock);
			if (!list_empty(&device->event_list)) {
				event = list_first_entry(&device->event_list, struct cdisk_event, event_list);
				list_del(&event->event_list);
			} else {
				event = NULL;	
			}
			spin_unlock(&device->event_list_lock);
			if (event)
				cdisk_event_handle(device, event);
		}

		cdisk_device_write_dirties(device);
		cdisk_device_map_lru_frees(device);
		cdisk_thread_wait(device);
	}
	/* Cancel requests */
	while (!list_empty(&device->req_list)) {
		spin_lock(&device->req_list_lock);
		if (!list_empty(&device->req_list)) {
			request = list_first_entry(&device->req_list, struct cdisk_request, req_list);
			list_del(&request->req_list);
		} else {
			request = NULL;	
		}
		spin_unlock(&device->req_list_lock);
		if (request)
			cdisk_request_cancel(device, request);
	}
	/* Cancel events */
	while (!list_empty(&device->event_list)) {
		spin_lock(&device->event_list_lock);
		if (!list_empty(&device->event_list)) {
			event = list_first_entry(&device->event_list, struct cdisk_event, event_list);
			list_del(&event->event_list);
		} else {
			event = NULL;	
		}
		spin_unlock(&device->event_list_lock);
		if (event)
			cdisk_event_cancel(device, event);
	}
	cdisk_device_write_dirties(device);
	file_sync(device->file);
	return 0;
}

static int cdisk_device_start(struct cdisk_device *device)
{
	int error = -EINVAL;

	device->thread = kthread_create(cdisk_thread_routine, device, device->name);
	if (IS_ERR(device->thread)) {
		error = PTR_ERR(device->thread);
		klog(KL_ERR, "kthread_create err=%d", error);
		goto out;
	}
	get_task_struct(device->thread);	
	wake_up_process(device->thread);
	error = 0;
out:
	return error;
}

static void cdisk_device_stop(struct cdisk_device *device)
{
	int err;
	
	device->flags|= CDISK_FLAGS_SHUTDOWN;
	spin_lock(&device->req_list_lock);
	spin_unlock(&device->req_list_lock);

	err = kthread_stop(device->thread);
	klog(KL_DBG, "kthread stop err=%d", err);
	put_task_struct(device->thread);
}


static int cdisk_map_create(struct cdisk_device *device)
{
	return 0;
}

static void cdisk_map_delete(struct cdisk_device *device)
{
	cdisk_map_nodes_free(&device->map);	
}

static int file_write(struct file *file, const void *buf, u32 len, loff_t *off)
{	
	int ret;
	mm_segment_t old_fs;
	u32 pos = 0;
	old_fs = get_fs();
	set_fs(get_ds());
	while (pos < len) {
		ret = vfs_write(file, (char *)buf + pos, len - pos, off);
		if (ret < 0)
			goto out;
		if (ret == 0) {
			ret = -EIO;
			goto out;
		} 
		pos += ret;
	}
	ret = 0;
out:
	set_fs(old_fs);
	return ret;
}


static int file_sync(struct file *file)
{
	int err = vfs_fsync(file, 0);
	if (err) {
		klog(KL_ERR, "vfs_fsync err=%d", err);
	}
	return err;
}

static int file_read(struct file *file, const void *buf, u32 len, loff_t *off)
{	
	int ret;
	mm_segment_t old_fs;
	u32 pos = 0;
	old_fs = get_fs();
	set_fs(get_ds());
	while (pos < len) {
		ret = vfs_read(file, (char *)buf + pos, len - pos, off);
		if (ret < 0) {
			klog(KL_ERR, "ret=%d, pos=%d, len=%d, off=%lld", ret, pos, len, *off);
			goto out;
		}

		if (ret == 0) {
			klog(KL_ERR, "ret=%d, pos=%d, len=%d, off=%lld", ret, pos, len, *off);	
			ret = -EIO;
			goto out;
		} 
		pos += ret;
	}
	ret = 0;
out:
	set_fs(old_fs);
	return ret;
}

static unsigned long cdisk_device_file_size(struct cdisk_device *device)
{
	return i_size_read(device->file->f_mapping->host);
}

static int cdisk_device_file_grow(struct cdisk_device *device, u32 delta)
{
	void *va;
	struct page *page;
	u32 wrote, len;
	loff_t off;
	size_t size;
	int err;

	page = alloc_page(GFP_NOIO);
	if (!page) {
		klog(KL_ERR, "cant alloc mem");
		err = -ENOMEM;
		goto out;
	}

	size = cdisk_device_file_size(device);
	va = kmap(page);
	memset(va, 0, PAGE_SIZE);
	wrote = 0;
	while (wrote < delta) {
		off = size + wrote;
		len = ((delta - wrote) > PAGE_SIZE) ? PAGE_SIZE : (delta - wrote);
		err = file_write(device->file, va, len, &off);
		if (err) {
			klog(KL_ERR, "cant write at off=%lld, len=%d, err=%d", off, len, err);
			break;
		}
		wrote+= len;
	}
	err = 0;	
	kunmap(page);
	__free_page(page);
out:
	return err;

}

static int cdisk_device_fix_file_size(struct cdisk_device *device)
{
	unsigned long size = cdisk_device_file_size(device);
	int err;
	unsigned long new_size = (size/device->cluster_size + 1)*device->cluster_size;
	unsigned long delta = new_size - size;

	if (!(size%device->cluster_size)) {
		klog(KL_DBG, "size is ok %lld", size);
		return 0;
	}

	err = cdisk_device_file_grow(device, delta);
	return err;
}

static void cdisk_cluster_by_off(struct cdisk_device *device, loff_t off, unsigned long *cluster, unsigned long *coff)
{
	*coff = off & ((1UL << device->cluster_bits) - 1);
	*cluster = off/device->cluster_size;
}

static void cdisk_index_by_off(struct cdisk_device *device, loff_t off, unsigned long *l1_index, unsigned long *l2_index, unsigned long *cluster_off)
{
	*cluster_off = off & ((1UL << device->cluster_bits) - 1);
	off = off >> device->cluster_bits;
	*l2_index = off & ((1UL << (device->cluster_bits - QCOW_INDEX_BITS)) - 1);
	off = off >> (device->cluster_bits - QCOW_INDEX_BITS);
	*l1_index = off;
}

static void cdisk_index_test(struct cdisk_device *device)
{
	loff_t off[] = {0, PAGE_SIZE, 15*PAGE_SIZE, 16*PAGE_SIZE, 17*PAGE_SIZE, 8192*16*PAGE_SIZE + 17*PAGE_SIZE + 32};
	unsigned long l1_index, l2_index, cluster_off;
	int i;
	for (i = 0; i < sizeof(off)/sizeof(off[0]); i++) {
		cdisk_index_by_off(device, off[i], &l1_index, &l2_index, &cluster_off);
		klog(KL_DBG, "off=%lld, l1=%lld, l2=%lld, coff=%lld",
			off[i], l1_index, l2_index, cluster_off);
	}
}

static int cdisk_map_node_read_page(struct cdisk_device *device, struct cdisk_map_node *node, int pg_index)
{
	loff_t off;
	int err;
	void *pg_va;

	BUG_ON(pg_index >= node->nr_pages);

	pg_va = kmap(node->pages[pg_index]);
	off = node->index*device->cluster_size + pg_index*PAGE_SIZE;
	err = file_read(device->file, pg_va, PAGE_SIZE, &off);
	kunmap(node->pages[pg_index]);
	if (!err) {
		node->pg_flags[pg_index] |= CDISK_MN_PAGE_READ;
	}

	return err;
}

static int cdisk_map_node_read_buf(struct cdisk_device *device, struct cdisk_map_node *node, unsigned long coff, u32 len, void *buf)
{
	unsigned long pg_index = coff/PAGE_SIZE;
	unsigned long pg_off = coff & ((1UL << PAGE_SHIFT) - 1);
	u32 read = 0, read_len;
	void *pg_va;
	int err;

	while (read < len) {
		read_len = ((len - read) > (PAGE_SIZE - pg_off)) ? (PAGE_SIZE - pg_off) : (len - read);
		if (!(node->pg_flags[pg_index] & CDISK_MN_PAGE_READ)) {
			err = cdisk_map_node_read_page(device, node, pg_index);
			if (err) {
				klog(KL_ERR, "cant read page %d for node %lld, err=%d", pg_index, node->index, err);
				goto out;
			}
		}
		BUG_ON(!(node->pg_flags[pg_index] & CDISK_MN_PAGE_READ));
		pg_va = kmap(node->pages[pg_index]);
		memcpy((char *)buf + read, pg_va + pg_off, read_len);
		kunmap(node->pages[pg_index]);
		pg_off = 0;
		pg_index++;
		read+= read_len;
	}
	err = 0;
out:
	return err;
}

static int cdisk_device_read_buf(struct cdisk_device *device, loff_t off, u32 len, void *buf)
{
	unsigned long cluster = off/device->cluster_size;
	unsigned long coff = off & ((1UL << device->cluster_bits) - 1);
	struct cdisk_map_node *node;
	int err;
	u32 read = 0, read_len;

	while (read < len) {
		err = cdisk_device_get_map(device, cluster, &node);
		if (err) {
			goto out;
		}
		read_len = ((len - read) > (device->cluster_size - coff)) ? (device->cluster_size - coff) : (len - read);
		err =  cdisk_map_node_read_buf(device, node, coff, read_len, (char *)buf + read);
		if (err) {
			cdisk_map_node_deref(node);
			goto out;
		}
		cdisk_map_node_deref(node);
		coff = 0;
		cluster++;
		read+= read_len;
	}
	err = 0;

out:
	return err;
}

static int cdisk_map_node_write_buf(struct cdisk_device *device, struct cdisk_map_node *node, unsigned long coff, u32 len, void *buf)
{
	unsigned long pg_index = coff/PAGE_SIZE;
	unsigned long pg_off = coff & ((1UL << PAGE_SHIFT) - 1);
	u32 read = 0, read_len;
	void *pg_va;
	int err;

	while (read < len) {
		read_len = ((len - read) > (PAGE_SIZE - pg_off)) ? (PAGE_SIZE - pg_off) : (len - read);
		if (!(node->pg_flags[pg_index] & CDISK_MN_PAGE_READ) && (read_len != PAGE_SIZE)) {
			err = cdisk_map_node_read_page(device, node, pg_index);
			if (err) {
				klog(KL_ERR, "cant read page=%d for node %lld, err=%d", pg_index, node->index, err);
				goto out;
			}
			BUG_ON(!(node->pg_flags[pg_index] & CDISK_MN_PAGE_READ));
		}
		pg_va = kmap(node->pages[pg_index]);
		memcpy((char *)pg_va + pg_off, (char *)buf + read, read_len);
		node->pg_flags[pg_index] |= CDISK_MN_PAGE_DIRTY;
		if (read_len == PAGE_SIZE) {
			node->pg_flags[pg_index]|= CDISK_MN_PAGE_READ;
		}
		BUG_ON(!(node->pg_flags[pg_index] & CDISK_MN_PAGE_READ));
		kunmap(node->pages[pg_index]);
		pg_off = 0;
		pg_index++;
		read+= read_len;
	}
	node->flags |= CDISK_MN_DIRTY;
	err = 0;
out:
	return err;
}

static int cdisk_device_write_buf(struct cdisk_device *device, loff_t off, u32 len, void *buf)
{
	unsigned long cluster = off/device->cluster_size;
	unsigned long coff = off & ((1UL << device->cluster_bits) - 1);
	struct cdisk_map_node *node;
	int err;
	u32 read = 0, read_len;

	while (read < len) {
		err = cdisk_device_get_map(device, cluster, &node);
		if (err) {
			goto out;
		}
		read_len = ((len - read) > (device->cluster_size - coff)) ? (device->cluster_size - coff) : (len - read);
		err =  cdisk_map_node_write_buf(device, node, coff, read_len, (char *)buf + read);
		if (err) {
			cdisk_map_node_deref(node);
			goto out;
		}
		cdisk_map_node_deref(node);
		coff = 0;
		cluster++;
		read+= read_len;
	}
	err = 0;

out:
	return err;
}


static int cdisk_lookup_cluster(struct cdisk_device *device, unsigned long vcluster, unsigned long *pcluster, unsigned long *pl2_start)
{
	loff_t off = vcluster*device->cluster_size;
	unsigned long l1_index, l2_index, coff;
	struct qcow_index i_read;
	int err;
	unsigned long l2_start, found_cluster;

	*pcluster = 0;
	*pl2_start = 0;

	BUG_ON(device->size % device->cluster_size);

	if (vcluster*device->cluster_size >= device->size) {
		klog(KL_ERR, "vcluster=%lld, out of size=%lld", vcluster, device->size);
		return -EIO;
	}

	cdisk_index_by_off(device, off, &l1_index, &l2_index, &coff);
	BUG_ON(coff);
	err = cdisk_device_read_buf(device, device->l1_table_offset + l1_index*sizeof(struct qcow_index), 
			sizeof(struct qcow_index), &i_read);
	if (err) {
		klog(KL_ERR, "cant read buf, err=%d", err);
		goto out;
	} 	

	l2_start = qcow_index_offset(&i_read)/(device->cluster_size);
	if (l2_start == 0) {
		err = 0;
		goto out;
	}

	*pl2_start = l2_start;
	err = cdisk_device_read_buf(device, l2_start*device->cluster_size + l2_index*sizeof(struct qcow_index), 
			sizeof(struct qcow_index), &i_read);
	if (err) {
		klog(KL_ERR, "cant read buf, err=%d", err);
		goto out;
	} 

	found_cluster = qcow_index_offset(&i_read)/(device->cluster_size);
	if (found_cluster == 0) {
		err = 0;
		goto out;
	}

	*pcluster = found_cluster;
	err = 0;
out:
	return err;		
}

static void cdisk_cluster_refcount_offset(struct cdisk_device *device, unsigned long pcluster,
	unsigned long *rt_index, unsigned long *coff)
{	
	*coff = pcluster & ((1UL << (device->cluster_bits - 1)) -1);
	*rt_index = pcluster >> (device->cluster_bits -1);			
}

static int cdisk_write_cluster_refcount(struct cdisk_device *device, unsigned long pcluster, u16 refcount, bool *nallocated)
{
	int err;
	unsigned long rt_index;
	unsigned long coff;
	__be16 w_refcount;
	struct qcow_index index;
	loff_t off, ref_block_pos;
	
	*nallocated = false;
	cdisk_cluster_refcount_offset(device, pcluster, &rt_index, &coff);
	klog(KL_DBG, "refcnts:pcluster=%lld, rt_index=%lld, coff=%lld", pcluster, rt_index, coff);

	err = cdisk_device_read_buf(device, device->refcount_table_offset + rt_index*sizeof(struct qcow_index), sizeof(struct qcow_index), &index);
	if (err) {
		klog(KL_ERR, "read buf failed, err=%d, off=%lld, rt_index=%lld", err, device->refcount_table_offset + rt_index*sizeof(struct qcow_index), rt_index);
		return err;
	}

	ref_block_pos = qcow_index_offset(&index);
	if (ref_block_pos == 0) {
		klog(KL_INF, "refcount block not allocated, index=%lld", rt_index);
		*nallocated = true;
		return -EINVAL;
	}

	off = ref_block_pos + coff*sizeof(refcount);
	w_refcount = cpu_to_be16(refcount);
	err = cdisk_device_write_buf(device, off, sizeof(w_refcount), &w_refcount);
	return err;
}

static int __cdisk_add_cluster_refcount_table(struct cdisk_device *device, unsigned long cluster)
{
	loff_t ref_block_pos;
	int err;
	struct qcow_index index;
	bool nallocated = false;
	unsigned long rt_index, coff;

	ref_block_pos = cluster*device->cluster_size;
	qcow_index_set(&index,  ref_block_pos, false, false);

	cdisk_cluster_refcount_offset(device, cluster, &rt_index, &coff);
	klog(KL_DBG, "refcnts:cluster=%lld, rt_index=%lld, coff=%lld", cluster, rt_index, coff);

	err = cdisk_device_write_buf(device, device->refcount_table_offset + rt_index*sizeof(struct qcow_index), sizeof(struct qcow_index), &index);
	if (err) {
		klog(KL_ERR, "write buf failed, err=%d, off=%lld, rt_index=%lld", err, device->refcount_table_offset + rt_index*sizeof(struct qcow_index), rt_index);
		goto out;
	}
	
	err = cdisk_write_cluster_refcount(device, cluster, 1, &nallocated);
	if (err) {
		klog(KL_ERR, "cant write cluster=%lld refcount, err=%d", cluster, err);
		goto out;
	}
out:
	return err;
}


static int __cdisk_alloc_cluster(struct cdisk_device *device, unsigned long *pcluster)
{
	int err;
	unsigned long size;
	unsigned long cluster;

	*pcluster = 0;
	err = cdisk_device_fix_file_size(device);
	if (err)
		return err;

	size = cdisk_device_file_size(device);
	err = cdisk_device_file_grow(device, device->cluster_size);
	if (err)
		return err;
	
	cluster = size/device->cluster_size;
	*pcluster = cluster;
	klog(KL_DBG, "allocate cluster at=%lld", *pcluster);
	return 0;				
}

static int cdisk_alloc_cluster(struct cdisk_device *device, unsigned long *pcluster)
{
	int err;
	unsigned long cluster;
	bool nallocated = false;

	*pcluster = 0;
	err = __cdisk_alloc_cluster(device, &cluster);
	if (err) {
		klog(KL_ERR, "cant alloc cluster, err=%d", err);
		return err;
	}

	err = cdisk_write_cluster_refcount(device, cluster, 1, &nallocated);
	if (err) {
		if (!nallocated)
			goto out;
		err = __cdisk_add_cluster_refcount_table(device, cluster);	
		if (err) {
			klog(KL_ERR, "cant add cluster=%lld to refcount table, err=%d", cluster, err);
			goto out;
		}
		err = __cdisk_alloc_cluster(device, &cluster);
		if (err) {
			klog(KL_ERR, "cant alloc cluster, err=%d", err);
			goto out;
		}
		err = cdisk_write_cluster_refcount(device, cluster, 1, &nallocated);
		if (err) {
			klog(KL_ERR, "cant write cluster=%lld refcount, err=%d", cluster, err);
			goto out;
		}	
	}

	err = 0;
	*pcluster = cluster;
	klog(KL_DBG, "allocated data cluster at=%lld", *pcluster);
out:
	return err;				
}


/*
static int cdisk_read_cluster_refcount(struct cdisk_device *device, unsigned long pcluster, u16 *prefcount)
{
	int err;
	loff_t off;
	__be16 refcount;

	*prefcount = 0;
	off = cdisk_cluster_refcount_offset(device, pcluster);
	if (off == -1)
		return -EINVAL;

	err = cdisk_device_read_buf(device, off, sizeof(refcount), &refcount);
	if (err)
		return err;
	*prefcount = be16_to_cpu(refcount);
	return 0;
}


static int cdisk_inc_cluster_refcount(struct cdisk_device *device, unsigned long pcluster)
{
	int err;
	u16 refcount;

	err = cdisk_read_cluster_refcount(device, pcluster, &refcount);
	if (err)
		return err;
	refcount+= 1;
	err = cdisk_write_cluster_refcount(device, pcluster, refcount);
	return err;
}
*/
static int cdisk_add_cluster(struct cdisk_device *device, unsigned long vcluster, unsigned long *pcluster)
{
	int err;
	unsigned long l2_start, data_cluster;
	unsigned long off = vcluster*device->cluster_size, l1_index, l2_index, coff;	
	struct qcow_index i_wrote;
	bool l2_allocated = false;

	*pcluster = 0;
	BUG_ON(device->size % device->cluster_size);
	if (vcluster*device->cluster_size >= device->size) {
		klog(KL_ERR, "vcluster=%lld, out of size=%lld", vcluster, device->size);
		err = -EIO;
		goto out;
	}

	cdisk_index_by_off(device, off, &l1_index, &l2_index, &coff);
	BUG_ON(coff);

	err =  cdisk_lookup_cluster(device, vcluster, pcluster, &l2_start);
	if (err) {
		klog(KL_ERR, "cant find cluster for vc=%lld", vcluster);
		goto out;
	}

	klog(KL_DBG, "found pc=%lld for vc=%lld, l2_start=%lld", *pcluster, vcluster, l2_start);
	if (*pcluster != 0) {
		err = 0;
		goto out;
	}

	if (l2_start == 0) {
		/* allocate l2 table cluster */	
		err = cdisk_alloc_cluster(device, &l2_start);
		if (err) {
			klog(KL_ERR, "cant alloc l2 cluster, err=%d", err);
			goto out;
		}	
		l2_allocated = true;	
	}

	err = cdisk_alloc_cluster(device, &data_cluster);
	if (err) {
		klog(KL_ERR, "cant alloc data cluster, err=%d", data_cluster, err);
		goto out;
	}

	/* make link from l2 to data */
	qcow_index_set(&i_wrote, data_cluster*device->cluster_size, true, false);
	err = cdisk_device_write_buf(device, l2_start*device->cluster_size + l2_index*sizeof(struct qcow_index), 
		sizeof(struct qcow_index), &i_wrote);
 	if (err) {
		klog(KL_ERR, "cant link l2 -> data");
		goto out;
	}

	
	if (l2_allocated) {
		/* make link from l1 to l2 */	
		qcow_index_set(&i_wrote, l2_start*device->cluster_size, true, false);
		err = cdisk_device_write_buf(device, device->l1_table_offset + l1_index*sizeof(struct qcow_index), 
			sizeof(struct qcow_index), &i_wrote);
		if (err) {
			klog(KL_ERR, "cant link l1 -> l2");
			goto out;
		}
	}
	err = 0;
	*pcluster = data_cluster;

out:
	return err;
}

static int cdisk_discard(struct cdisk_device *device, sector_t sector, u32 len)
{
	int err;
	unsigned long vcluster, pcluster, coff;
	u32 wrote = 0;
	struct page *page;	
	void *va;
	loff_t off;
	u32 write_len;

	klog(KL_DBG, "sector=%lld, n=%lld", sector, len);

	page = alloc_page(GFP_NOIO);
	if (!page) {
		klog(KL_ERR, "cant alloc mem");
		err = -ENOMEM;
		goto out;
	}

	va = kmap(page);
	memset(va, 0, PAGE_SIZE);
	cdisk_cluster_by_off(device, sector*SECTOR_SIZE, &vcluster, &coff); 	
	while (wrote < len) {
		err = cdisk_add_cluster(device, vcluster, &pcluster);
		if (err) {
			goto free_page;
		}
		write_len = ((len - wrote) > (device->cluster_size - coff)) ? (device->cluster_size - coff) :
			(len - wrote);
		if (write_len > PAGE_SIZE)
			write_len = PAGE_SIZE;

		off = pcluster*device->cluster_size + coff;
		err = cdisk_device_write_buf(device, off, write_len, va);
		if (err) {
			goto free_page;
		}
		wrote+= write_len;
		coff+= write_len;
		if (coff >= device->cluster_size) {
			vcluster+= 1;
			coff = 0;
		}
	}
	err = 0;

free_page:
	kunmap(page);
	__free_page(page);
out:
	return err;
}

static int cdisk_do_bvec(struct cdisk_device *device, struct page *page,
	u32 len, u32 off, int rw, sector_t sector)
{
	int err;
	unsigned long vcluster, pcluster, coff;
	u32 wrote = 0;	
	void *va;
	loff_t loff;
	u32 write_len;

	klog(KL_DBG, "off=%d, len=%d, sector=%lld, rw=%d", off, len, sector, rw);
	va = (char *)kmap(page) + off;
	cdisk_cluster_by_off(device, sector*SECTOR_SIZE, &vcluster, &coff); 	
	klog(KL_DBG, "vcluster=%lld, sector=%lld, coff=%lld", vcluster, sector, coff);

	while (wrote < len) {
		err = cdisk_add_cluster(device, vcluster, &pcluster);
		if (err) {
			klog(KL_ERR, "cant add cluster vc=%lld", vcluster);
			goto free_page;
		}
		klog(KL_DBG, "pcluster=%lld", pcluster);
		write_len = ((len - wrote) > (device->cluster_size - coff)) ? (device->cluster_size - coff) :
			(len - wrote);
		if (write_len > PAGE_SIZE)
			write_len = PAGE_SIZE;

		loff = pcluster*device->cluster_size + coff;
		if (rw == READ) 	
			err = cdisk_device_read_buf(device, loff, write_len, (char *)va + wrote);
		else
			err = cdisk_device_write_buf(device, loff, write_len, (char *)va + wrote);
		if (err) {
			klog(KL_ERR, "io failed, rw=%d, err=%d", rw, err);
			goto free_page;
		}
		wrote+= write_len;
		coff+= write_len;
		if (coff >= device->cluster_size) {
			vcluster+= 1;
			coff = 0;
		}
	}
	err = 0;

free_page:
	kunmap(page);
	return err;
}

static int cdisk_parse_header(struct cdisk_device *device, struct qcow_header *header)
{
	int err;

	if (qcow_header_magic(header) != QCOW_MAGIC) {
		klog(KL_ERR, "disk magic incorrect, has %x", header->magic);
		err = -EINVAL;
		goto out;
	}

	if ((qcow_header_version(header) != QCOW_VERSION_2) &&
		(qcow_header_version(header) != QCOW_VERSION_3)) {
		klog(KL_ERR, "disk format version not supported, has %x", header->version);
		err = -EINVAL;
		goto out;
	}

	device->version = qcow_header_version(header);
	device->cluster_bits = qcow_header_cluster_bits(header);
	device->size = qcow_header_size(header);
	device->l1_table_offset = qcow_header_l1_table_offset(header);
	device->l1_size = qcow_header_l1_size(header);
	device->refcount_table_offset = qcow_header_refcount_table_offset(header);
	device->refcount_table_clusters = qcow_header_refcount_table_clusters(header);

	device->cluster_size = (1 << device->cluster_bits);
	
	klog(KL_INF, "version=%d, cluster_bits=%d, size=%lld, l1_table_offset=%lld, l1_size=%d", 
		device->version, device->cluster_bits, device->size, device->l1_table_offset, device->l1_size); 
	klog(KL_INF, "cluster_size=%d, refcount_table_offset=%lld, refcount_table_clusters=%d", 
		device->cluster_size, device->refcount_table_offset, device->refcount_table_clusters);

	err = 0;

out:
	return err;
}

static int cdisk_pin_cluster(struct cdisk_device *device, unsigned long cluster)
{
	int err;
	struct cdisk_map_node *node;

	err = cdisk_device_get_map(device, cluster, &node);
	if (err)
		return err;

	klog(KL_DBG, "Successfuly pinned cluster=%lld", cluster);
	node->flags |= CDISK_MN_PINNED;
	klog(KL_INF, "pinned node=%p, index=%lld, ref=%d", node, node->index, atomic_read(&node->refs));

	cdisk_map_node_deref(node);

	return 0;
}

static int cdisk_pin_l1(struct cdisk_device *device)
{
	unsigned long cluster = device->l1_table_offset/device->cluster_size;
	int num_clusters = ((device->l1_size*sizeof(struct qcow_index))%device->cluster_size) ? 
		((device->l1_size*sizeof(struct qcow_index))/device->cluster_size + 1) : (device->l1_size*sizeof(struct qcow_index))/device->cluster_size;
	int i;
	int err;

	for (i = 0; i < num_clusters; i++) {
		err = cdisk_pin_cluster(device, cluster);
		if (err) {
			klog(KL_ERR, "cant pin cluster=%d", cluster);
			goto out;
		}
		cluster++;
	}
	err = 0;
out:
	return err;
}

static int cdisk_read_check_header(struct cdisk_device *device)
{
	struct page *page;
	int err;
	struct qcow_header *header;
	loff_t off;

	page = alloc_page(GFP_NOIO);
	if (!page) {
		err = -ENOMEM;
		goto out;
	}

	header = kmap(page);
	off = 0;
	err = file_read(device->file, header, PAGE_SIZE, &off);
	if (err) {
		klog(KL_ERR, "cant read header 0 page");
		goto unmap_page;
	}
	klog(KL_DBG, "header was read");
	err = cdisk_parse_header(device, header);

unmap_page:
	kunmap(page);
	__free_page(page);
out:
	return err;
}



static int cdisk_create(int num, char *fname)
{
	struct cdisk_device *device = NULL;
	int error = -EINVAL;
	struct file *file;

	file = filp_open(fname, O_RDWR|O_LARGEFILE, 0);
	if (!file) {
		klog(KL_ERR, "cant open file by name=%s", fname);
		error = -EINVAL;
		goto out;
	}	

	klog(KL_DBG, "file fmode=%x", file->f_mode);

	if (!file->f_op) {
		klog(KL_ERR, "file no ops");
		error = -EINVAL;
		goto release_file;	
	}	

	if ((!file->f_op->write && !file->f_op->aio_write)) {
		klog(KL_ERR, "file no write ops");
		error = -EINVAL;
		goto release_file;	
	}

	if ((!file->f_op->read && !file->f_op->aio_read)) {
		klog(KL_ERR, "file no read ops");
		error = -EINVAL;
		goto release_file;	
	}

	device = cdisk_alloc(num);
	if (!device) {
		klog(KL_ERR, "cant alloc disk device");
		error = -ENOMEM;
		goto release_file;
	}
	
	device->file = file;
	error = cdisk_map_create(device);
	if (error) {
		klog(KL_ERR, "device map create failed");
		goto free_device;
	}

	error =  cdisk_read_check_header(device);
	if (error) {
		klog(KL_ERR, "cant read header, err=%d", error);
		goto map_delete;
	}

	error = cdisk_pin_cluster(device, 0);
	if (error) {
		klog(KL_ERR, "cant pin 0 cluster, err=%d", error);
		goto map_delete;
	}
	cdisk_index_test(device);
	error = cdisk_device_fix_file_size(device);
	if (error) {
		klog(KL_ERR, "cant fix file size, err=%d", error);
		goto map_delete;
	}

	error = cdisk_pin_l1(device);
	if (error) {
		klog(KL_ERR, "cant pin l1 table, err=%d", error);
		goto map_delete;
	}

	set_capacity((device->disk), device->size/SECTOR_SIZE);

	error = cdisk_device_start(device);
	if (error) {
		klog(KL_ERR, "device start failed");
		goto map_delete;
	}

	klog(KL_INF, "created device=%p, num=%d, capacity=%lld, cluster_size=%lld", 
		device, device->number, get_capacity(device->disk), device->cluster_size);

	mutex_lock(&cdisk_devices_lock);
	list_add_tail(&device->devices_list, &cdisk_devices);
	mutex_unlock(&cdisk_devices_lock);
	add_disk(device->disk);
	return 0;
map_delete:
	cdisk_map_delete(device);
free_device:
	cdisk_free(device);
release_file:
	fput(file);
out:
	return error;
}

static int cdisk_delete(int disk_num)
{
	int error = -EINVAL;
	struct cdisk_device *device = NULL;

	klog(KL_DBG, "disk_num=%d", disk_num);
	
	mutex_lock(&cdisk_devices_lock);
	list_for_each_entry(device, &cdisk_devices, devices_list) {
		if (device->number == disk_num) {
			cdisk_del_one(device);
			error = 0;			
			break;
		}	
	}
	mutex_unlock(&cdisk_devices_lock);

	return error;
}

static int cdisk_setup(int disk_num)
{
	int error = -EINVAL;

	klog(KL_ERR, "not implemented yet");
	return error;
}

static int cdisk_disk_ioctl(struct block_device *bdev, fmode_t mode, unsigned int cmd, unsigned long arg)
{
	int error = -EINVAL;
	struct cdisk_device *device = bdev->bd_disk->private_data;

	switch (cmd) {
		case BLKFLSBUF:
			klog(KL_DBG, "device=%p,  BLKFLSBUF", device);
			error = 0;
			break;
		case CDROM_GET_CAPABILITY:
			error = -ENOIOCTLCMD;
			break;
		default:
			error = -EINVAL;
			klog(KL_ERR, "%d not implemented yet, device=%p", cmd, device);
	}

	return error;
}

static const struct block_device_operations cdisk_fops = {
	.owner = THIS_MODULE,
	.ioctl = cdisk_disk_ioctl,
};

static void cdisk_del_one(struct cdisk_device *device)
{
	klog(KL_INF, "deleting disk %p, num %d", device, device->number);

	cdisk_stats_dump(device);
	cdisk_device_stop(device);
	list_del(&device->devices_list);
	del_gendisk(device->disk);
	cdisk_map_delete(device);
	fput(device->file);
	cdisk_free(device);
	klog(KL_INF, "deleted disk %p", device);
}

static struct cdisk_device *cdisk_alloc(int num)
{
	struct cdisk_device *device = NULL;
	struct gendisk *disk = NULL;
	
	if (num == -1) {
		num = cdisk_num_alloc();
		if (num == -1) 
			goto out;
	} else {
		if (cdisk_num_use(num))
			goto out;
	}

	device = kzalloc(sizeof(*device), GFP_KERNEL);
	if (!device)
		goto out_free_num;

	device->nr_maps_max = CDISK_MAPS_MAX;
	cdisk_map_init(&device->map);
	atomic_set(&device->reads, 0);
	atomic_set(&device->writes, 0);
	atomic_set(&device->read_bytes, 0);
	atomic_set(&device->write_bytes, 0);
	
	init_waitqueue_head(&device->waitq);
	INIT_LIST_HEAD(&device->req_list);
	INIT_LIST_HEAD(&device->event_list);

	snprintf(device->name, sizeof(device->name), "cdisk%d", num);

	device->number = num;
	spin_lock_init(&device->lock);
	spin_lock_init(&device->req_list_lock);
	spin_lock_init(&device->event_list_lock);	

	device->queue = blk_alloc_queue(GFP_KERNEL);
	if (!device->queue)
		goto out_free_device;

	blk_queue_make_request(device->queue, cdisk_make_request);
	blk_queue_max_hw_sectors(device->queue, 1024);
	blk_queue_bounce_limit(device->queue, BLK_BOUNCE_ANY);

	device->queue->limits.discard_granularity = PAGE_SIZE;
	device->queue->limits.max_discard_sectors = UINT_MAX;
	device->queue->limits.discard_zeroes_data = 1;
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, device->queue);
	
	disk = device->disk = alloc_disk(1);
	if (!disk)
		goto out_free_queue;

	disk->major = cdisk_block_major;
	disk->first_minor = num;
	disk->fops = &cdisk_fops;
	disk->private_data = device;
	disk->queue = device->queue;
	disk->flags|= GENHD_FL_SUPPRESS_PARTITION_INFO;
	snprintf(disk->disk_name, sizeof(disk->disk_name), "cdisk%d", num);
	set_capacity(disk, 0);

	return device;

out_free_queue:
	blk_cleanup_queue(device->queue);
out_free_device:
	kfree(device);
out_free_num:
	cdisk_num_free(num);
out:
	return NULL;
}

static void cdisk_free(struct cdisk_device *device)
{
	BUG_ON(!list_empty(&device->req_list));
	
	blk_cleanup_queue(device->queue);
	put_disk(device->disk);
	cdisk_num_free(device->number);
	kfree(device);
}

static void cdisk_stats_dump(struct cdisk_device *device)
{
	klog(KL_INF, "dev=%p, num=%d, reads=%d, writes=%d, read_bytes=%d, write_bytes=%d", device, device->number,
		device->reads, device->writes, device->read_bytes, device->write_bytes);
	klog(KL_INF, "dev=%p, map_nodes=%d", device, device->map.nr_nodes);

	cdisk_device_map_dump(device);
}

static void cdisk_stats_work(struct work_struct *work)
{
	struct cdisk_device *device, *next;

	mutex_lock(&cdisk_devices_lock);

	list_for_each_entry_safe(device, next, &cdisk_devices, devices_list)
		cdisk_stats_dump(device);

	mutex_unlock(&cdisk_devices_lock);

	kfree(work);
}


static void cdisk_device_age(struct cdisk_device *device)
{
	struct cdisk_map_node *batch[4];
	int nr_found;
	unsigned long index, first_index = 0;
	struct cdisk_map_node *node;

	for (;;) {
		spin_lock(&device->map.nodes_lock);
		nr_found = radix_tree_gang_lookup(&device->map.nodes, (void **)batch, first_index, ARRAY_SIZE(batch));
		for (index = 0; index < nr_found; index++) {
			node = batch[index];
			atomic_inc(&node->refs);
			if (node->index >= first_index)
				first_index = node->index + 1;
		}
		spin_unlock(&device->map.nodes_lock);
		if (nr_found == 0) {
			break;
		}

		for (index = 0; index < nr_found; index++) {
			node = batch[index];
			cdisk_map_node_age(node);
			cdisk_map_node_deref(node);
		}
	}
}

static void cdisk_age_work(struct work_struct *work)
{
	struct cdisk_device *device, *next;
	int err;

	mutex_lock(&cdisk_devices_lock);

	list_for_each_entry_safe(device, next, &cdisk_devices, devices_list) {
		err = cdisk_event_create_queue(device, CDISK_EVENT_AGE, NULL);
		if (err) 
			klog(KL_ERR, "event create queue err=%d", err);
	}

	mutex_unlock(&cdisk_devices_lock);

	kfree(work);
}

static int cdisk_wq_queue_work(work_func_t func)
{
	struct work_struct *work = NULL;

	work = kmalloc(sizeof(struct work_struct), GFP_ATOMIC);
	if (!work) {
		klog(KL_ERR, "cant alloc work");
		return -ENOMEM;
	}

	INIT_WORK(work, func);
	if (!queue_work(cdisk_wq, work)) {
		kfree(work);
		klog(KL_ERR, "cant queue work");
		return -ENOMEM;
	}
	return 0;
}	

static atomic_t ticks = ATOMIC_INIT(1);

static void cdisk_timer_callback(unsigned long data)
{
	klog(KL_DBG, "in timer");

	atomic_inc(&ticks);
	if ((atomic_read(&ticks) % 1200) == 0)
		cdisk_wq_queue_work(cdisk_stats_work);
	cdisk_wq_queue_work(cdisk_age_work);
	mod_timer(&cdisk_timer, jiffies + msecs_to_jiffies(CDISK_TIMER_TIMEOUT_MSECS));
}

static int cdisk_char_open(struct inode *inode, struct file *file)
{
	klog(KL_DBG, "in open");
	if (!try_module_get(THIS_MODULE)) {
		klog(KL_ERR, "cant ref module");
		return -EINVAL;
	}
	klog(KL_DBG, "opened");
	return 0;
}

static int cdisk_char_release(struct inode *inode, struct file *file)
{
	klog(KL_DBG, "in release");
	module_put(THIS_MODULE);
	klog(KL_DBG, "released");
	return 0;
}

static long cdisk_char_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int error = -EINVAL;
	struct cdisk_cmd *params = NULL;	

	params = kmalloc(sizeof(struct cdisk_cmd), GFP_KERNEL);
	if (!params) {
		error = -ENOMEM;
		goto out;
	}

	if (copy_from_user(params, (const void *)arg, sizeof(struct cdisk_cmd))) {
		error = -EFAULT;
		goto out_free_params;
	}
	
	error = 0;
	switch (cmd) {
		case IOCTL_DISK_CREATE:
			params->error = cdisk_create(params->u.create.disk_num, params->u.create.fname);	
			break;
		case IOCTL_DISK_DELETE:
			params->error = cdisk_delete(params->u.delete.disk_num);
			break;
		case IOCTL_DISK_SETUP:
			params->error = cdisk_setup(params->u.delete.disk_num);
			break;
		default:
			klog(KL_ERR, "unknown ioctl=%d", cmd);
			error = -EINVAL;
			break;
	}
	
	if (copy_to_user((void *)arg, params, sizeof(struct cdisk_cmd))) {
		error = -EFAULT;
		goto out_free_params;
	}
	
	return 0;
out_free_params:
	kfree(params);
out:
	return error;	
}

static struct file_operations cdiskctl_fops = {
	.owner = THIS_MODULE,
	.open = cdisk_char_open,
	.release = cdisk_char_release,
	.unlocked_ioctl = cdisk_char_ioctl
};


static struct class *cdiskctl_class;
static dev_t cdiskctl_dev_t;
static struct cdev cdiskctl_cdev;


#define CDISKCTL_MAX_MINOR 1

static int cdiskctl_create(void)
{
	int error = -EINVAL;
	struct device *device = NULL;

	cdiskctl_class = class_create(THIS_MODULE, CDISKCTL_CHAR_DEV_NAME);
	if (IS_ERR(cdiskctl_class)) {
		error = PTR_ERR(cdiskctl_class);
		klog(KL_ERR, "class_create error=%d", error);
		return error;
	}
	
	error = alloc_chrdev_region(&cdiskctl_dev_t, 0, CDISKCTL_MAX_MINOR, CDISKCTL_CHAR_DEV_NAME);
	if (error) {
		klog(KL_ERR, "alloc_chrdev_region failed err=%d", error);
		goto out_class_destroy;
	}
	cdev_init(&cdiskctl_cdev, &cdiskctl_fops);
	cdiskctl_cdev.owner = THIS_MODULE;

	error = cdev_add(&cdiskctl_cdev, cdiskctl_dev_t, CDISKCTL_MAX_MINOR);
	if (error) {
		klog(KL_ERR, "cdev_add failed with err=%d", error);
		goto out_unreg_devreg;
	}
	
	device = device_create(cdiskctl_class, NULL, MKDEV(MAJOR(cdiskctl_dev_t), 0), NULL, CDISKCTL_CHAR_DEV_NAME);
	if (IS_ERR(device)) {
		error = PTR_ERR(device);
		klog(KL_ERR, "device_create err=%d", error);
		goto out_cdev_del;
	}
	return 0;

out_cdev_del:
	cdev_del(&cdiskctl_cdev);
out_unreg_devreg:
	unregister_chrdev_region(cdiskctl_dev_t, CDISKCTL_MAX_MINOR);
out_class_destroy:
	class_destroy(cdiskctl_class);	
	return error;

}

static void cdiskctl_release(void)
{
	device_destroy(cdiskctl_class, MKDEV(MAJOR(cdiskctl_dev_t), 0));
	cdev_del(&cdiskctl_cdev);
	unregister_chrdev_region(cdiskctl_dev_t, CDISKCTL_MAX_MINOR);
	class_destroy(cdiskctl_class);
}


static int cdisk_create_pools(void)
{
	int err;

	cdisk_mn_cachep = kmem_cache_create("cdisk_mn_cache", sizeof(struct cdisk_map_node),
						__alignof__(struct cdisk_map_node), 0, NULL);
	if (!cdisk_mn_cachep) {
		klog(KL_ERR, "kmem_cache_create failed");
		err = -ENOMEM;
		goto out;
	}

	cdisk_req_cachep = kmem_cache_create("cdisk_req_cache", sizeof(struct cdisk_request),
						__alignof__(struct cdisk_request), 0, NULL);
	if (!cdisk_req_cachep) {
		klog(KL_ERR, "kmem_cache_create failed");
		err = -ENOMEM;
		goto out_mn_cache_release;
	}

	cdisk_event_cachep = kmem_cache_create("cdisk_event_cache", sizeof(struct cdisk_event),
						__alignof__(struct cdisk_event), 0, NULL);
	if (!cdisk_event_cachep) {
		klog(KL_ERR, "kmem_cache_create failed");
		err = -ENOMEM;
		goto out_req_cache_release;
	}
	err = 0;
	goto out;

out_req_cache_release:
	kmem_cache_destroy(cdisk_req_cachep);
out_mn_cache_release:
	kmem_cache_destroy(cdisk_mn_cachep);
out:
	return err;

}

static void cdisk_free_pools(void)
{
	kmem_cache_destroy(cdisk_event_cachep);
	kmem_cache_destroy(cdisk_req_cachep);
	kmem_cache_destroy(cdisk_mn_cachep);
}

static int __init cdisk_init(void)
{	
	int error = -EINVAL;
	
	error = klog_init(KL_INF_L);
	if (error) {
		printk(KERN_ERR "klog_init failed with err=%d", error);
		goto out;
	}


	klog(KL_INF, "init");

	error = cdisk_create_pools();
	if (error) {
		klog(KL_ERR, "create pools err=%d", error);
		goto out_log_release;
	}

	error = cdiskctl_create();
	if (error) {
		klog(KL_ERR, "cdiskctl_create err=%d", error);
		goto out_free_pools;
	}

	cdisk_block_major = register_blkdev(0, CDISK_BLOCK_DEV_NAME);
	if (cdisk_block_major < 0) {
		klog(KL_ERR, "register_blkdev failed, result=%d", cdisk_block_major);
		error = -ENOMEM;
		goto out_cdiskctl_release;
	}
	
	cdisk_wq = alloc_workqueue("cdisk-wq", WQ_MEM_RECLAIM|WQ_UNBOUND, 2);
	if (!cdisk_wq) {
		klog(KL_ERR, "cant create wq");
		error = -ENOMEM;
		goto out_unreg_block_dev;
	}

	setup_timer(&cdisk_timer, cdisk_timer_callback, 0);
	error = mod_timer(&cdisk_timer, jiffies + msecs_to_jiffies(CDISK_TIMER_TIMEOUT_MSECS));
	if (error) {
		klog(KL_ERR, "mod_timer failed with err=%d", error);
		goto out_del_wq;
	}	
	klog(KL_INF, "module loaded, block major=%d", cdisk_block_major);
	return 0;

out_del_wq:
	destroy_workqueue(cdisk_wq);
out_unreg_block_dev:
	unregister_blkdev(cdisk_block_major, CDISK_BLOCK_DEV_NAME);
out_cdiskctl_release:
	cdiskctl_release();
out_free_pools:
	cdisk_free_pools();
out_log_release:
	klog_release();
out:
	return error;
}

static void __exit cdisk_exit(void)
{
	struct cdisk_device *device, *next;

	klog(KL_INF, "exiting");

	del_timer_sync(&cdisk_timer);	
	destroy_workqueue(cdisk_wq);
	klog(KL_INF, "going delete disks");

	mutex_lock(&cdisk_devices_lock);
	list_for_each_entry_safe(device, next, &cdisk_devices, devices_list)
		cdisk_del_one(device);
	mutex_unlock(&cdisk_devices_lock);

	unregister_blkdev(cdisk_block_major, CDISK_BLOCK_DEV_NAME);
	cdiskctl_release();

	klog(KL_INF, "cdisk_mn_count=%d", atomic_read(&cdisk_mn_count));
	BUG_ON(atomic_read(&cdisk_mn_count));

	cdisk_free_pools();
	klog(KL_INF, "exited");
	klog_release();
}

module_init(cdisk_init);
module_exit(cdisk_exit);

