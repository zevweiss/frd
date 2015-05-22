/*
 * *Flat* ram backed block device driver.  For when brd.c is just too slow,
 * with all its radix-tree cycle-wasting...here we just use a single giant
 * vmalloc() area instead (space/time tradeoff).
 *
 * Caveat: DAX requires physical pages (pfns), so direct_access() requires
 * what is essentially a software page-table walk in vmalloc_to_pfn().
 * Ironically, given the nature of multi-level page tables, this is basically
 * just another radix-tree lookup (though it's faster than the generic
 * radix-tree code and doesn't involve any locking).
 *
 * Copyright (C) 2007 Nick Piggin
 * Copyright (C) 2007 Novell Inc.
 * Copyright (C) 2015 Zev Weiss
 *
 * Parts derived from drivers/block/rd.c, and drivers/block/loop.c, copyright
 * of their respective owners.
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

#include <asm/uaccess.h>

#define SECTOR_SHIFT		9

static int rd_nr = 1;
module_param(rd_nr, int, S_IRUGO);
MODULE_PARM_DESC(rd_nr, "Maximum number of frd devices");

int rd_size = (32 * 1024);
module_param(rd_size, int, S_IRUGO);
MODULE_PARM_DESC(rd_size, "Size of each RAM disk in kbytes.");

static int max_part = 1;
module_param(max_part, int, S_IRUGO);
MODULE_PARM_DESC(max_part, "Num Minors to reserve between devices");

/*
 * Each flat ramdisk device has a big flat array of memory serving as the
 * backing store.
 */
struct frd_device {
	/* Backing store of memory. This is the raw vmalloc pointer, of unknown alignment. */
	void* __frd_rawmem;

	size_t size_bytes;

	/* This is the contents of the block device, just PAGE_ALIGN(__frd_rawmem). */
	void* frd_mem;

	int		frd_number;

	struct request_queue	*frd_queue;
	struct gendisk		*frd_disk;
	struct list_head	frd_list;
};

static inline void* frd_sector_addr(struct frd_device* frd, sector_t s)
{
	return frd->frd_mem + (s << SECTOR_SHIFT);
}

static DEFINE_MUTEX(frd_mutex);

/*
 * Free all backing store. This must only be called when there are no other
 * users of the device.
 */
static void frd_free_mem(struct frd_device *frd)
{
	vfree(frd->__frd_rawmem);
	frd->frd_mem = frd->__frd_rawmem = NULL;
	frd->size_bytes = 0;
}

static void discard_from_frd(struct frd_device *frd,
			sector_t sector, size_t n)
{
	void* loc = frd_sector_addr(frd, sector);
	memset(loc, 0, n);
}

/*
 * Copy n bytes from src to the frd starting at sector. Does not sleep.
 */
static void copy_to_frd(struct frd_device *frd, const void *src,
			sector_t sector, size_t n)
{
	void *dst = frd_sector_addr(frd, sector);
	memcpy(dst, src, n);
}

/*
 * Copy n bytes to dst from the frd starting at sector. Does not sleep.
 */
static void copy_from_frd(void *dst, struct frd_device *frd,
			sector_t sector, size_t n)
{
	void* src = frd_sector_addr(frd, sector);
	memcpy(dst, src, n);
}

/*
 * Process a single bvec of a bio.
 */
static int frd_do_bvec(struct frd_device *frd, struct page *page,
			unsigned int len, unsigned int off, int rw,
			sector_t sector)
{
	void *mem;
	int err = 0;

	mem = kmap_atomic(page);
	if (rw == READ) {
		copy_from_frd(mem + off, frd, sector, len);
		flush_dcache_page(page);
	} else {
		flush_dcache_page(page);
		copy_to_frd(frd, mem + off, sector, len);
	}
	kunmap_atomic(mem);

	return err;
}

static void frd_make_request(struct request_queue *q, struct bio *bio)
{
	struct block_device *bdev = bio->bi_bdev;
	struct frd_device *frd = bdev->bd_disk->private_data;
	int rw;
	struct bio_vec bvec;
	sector_t sector;
	struct bvec_iter iter;
	int err = -EIO;

	sector = bio->bi_iter.bi_sector;
	if (bio_end_sector(bio) > get_capacity(bdev->bd_disk))
		goto out;

	if (unlikely(bio->bi_rw & REQ_DISCARD)) {
		err = 0;
		discard_from_frd(frd, sector, bio->bi_iter.bi_size);
		goto out;
	}

	rw = bio_rw(bio);
	if (rw == READA)
		rw = READ;

	bio_for_each_segment(bvec, bio, iter) {
		unsigned int len = bvec.bv_len;
		err = frd_do_bvec(frd, bvec.bv_page, len,
					bvec.bv_offset, rw, sector);
		if (err)
			break;
		sector += len >> SECTOR_SHIFT;
	}

out:
	bio_endio(bio, err);
}

static int frd_rw_page(struct block_device *bdev, sector_t sector,
		       struct page *page, int rw)
{
	struct frd_device *frd = bdev->bd_disk->private_data;
	int err = frd_do_bvec(frd, page, PAGE_CACHE_SIZE, 0, rw, sector);
	page_endio(page, rw & WRITE, err);
	return err;
}

static long frd_direct_access(struct block_device *bdev, sector_t sector,
			void **kaddr, unsigned long *pfn, long size)
{
	struct frd_device *frd = bdev->bd_disk->private_data;

	*kaddr = frd_sector_addr(frd, sector);
	*pfn = vmalloc_to_pfn(*kaddr);

	return frd->size_bytes - (sector << SECTOR_SHIFT);
}

static int frd_ioctl(struct block_device *bdev, fmode_t mode,
			unsigned int cmd, unsigned long arg)
{
	return -ENOTTY;
}

static const struct block_device_operations frd_fops = {
	.owner =		THIS_MODULE,
	.rw_page =		frd_rw_page,
	.ioctl =		frd_ioctl,
	.direct_access =	frd_direct_access,
};

/*
 * The device scheme is derived from loop.c. Keep them in synch where possible
 * (should share code eventually).
 */
static LIST_HEAD(frd_devices);
static DEFINE_MUTEX(frd_devices_mutex);

static int frd_major;

static struct frd_device *frd_alloc(int i)
{
	struct frd_device *frd;
	struct gendisk *disk;

	frd = kzalloc(sizeof(*frd), GFP_KERNEL);
	if (!frd)
		goto out;
	frd->frd_number		= i;
	frd->size_bytes = rd_size * 1024UL;

	/*
	 * I think vmalloc() is probably guaranteed to return a page-aligned
	 * address, but just in case it doesn't for some reason, we grab an
	 * extra page here so we can guarantee page-alignment of the base
	 * address of the backing store.
	 */
	frd->__frd_rawmem = vzalloc(frd->size_bytes + PAGE_SIZE);
	if (!frd->__frd_rawmem)
		goto out_free_dev;
	frd->frd_mem = (void*)PAGE_ALIGN((unsigned long)frd->__frd_rawmem);

	frd->frd_queue = blk_alloc_queue(GFP_KERNEL);
	if (!frd->frd_queue)
		goto out_free_mem;

	blk_queue_make_request(frd->frd_queue, frd_make_request);
	blk_queue_max_hw_sectors(frd->frd_queue, 1024);
	blk_queue_bounce_limit(frd->frd_queue, BLK_BOUNCE_ANY);

	/* This is so fdisk will align partitions on 4k, because of
	 * direct_access API needing 4k alignment, returning a PFN
	 * (This is only a problem on very small devices <= 4M,
	 *  otherwise fdisk will align on 1M. Regardless this call
	 *  is harmless)
	 */
	blk_queue_physical_block_size(frd->frd_queue, PAGE_SIZE);

	frd->frd_queue->limits.discard_granularity = PAGE_SIZE;
	frd->frd_queue->limits.max_discard_sectors = UINT_MAX;
	frd->frd_queue->limits.discard_zeroes_data = 1;
	queue_flag_set_unlocked(QUEUE_FLAG_DISCARD, frd->frd_queue);

	disk = frd->frd_disk = alloc_disk(max_part);
	if (!disk)
		goto out_free_queue;
	disk->major		= frd_major;
	disk->first_minor	= i * max_part;
	disk->fops		= &frd_fops;
	disk->private_data	= frd;
	disk->queue		= frd->frd_queue;
	disk->flags		= GENHD_FL_EXT_DEVT;
	sprintf(disk->disk_name, "flatram%d", i);
	set_capacity(disk, rd_size * 2);

	return frd;

out_free_queue:
	blk_cleanup_queue(frd->frd_queue);
out_free_mem:
	vfree(frd->__frd_rawmem);
out_free_dev:
	kfree(frd);
out:
	return NULL;
}

static void frd_free(struct frd_device *frd)
{
	put_disk(frd->frd_disk);
	blk_cleanup_queue(frd->frd_queue);
	frd_free_mem(frd);
	kfree(frd);
}

static struct frd_device *frd_init_one(int i, bool *new)
{
	struct frd_device *frd;

	*new = false;
	list_for_each_entry(frd, &frd_devices, frd_list) {
		if (frd->frd_number == i)
			goto out;
	}

	frd = frd_alloc(i);
	if (frd) {
		add_disk(frd->frd_disk);
		list_add_tail(&frd->frd_list, &frd_devices);
	}
	*new = true;
out:
	return frd;
}

static void frd_del_one(struct frd_device *frd)
{
	list_del(&frd->frd_list);
	del_gendisk(frd->frd_disk);
	frd_free(frd);
}

static struct kobject *frd_probe(dev_t dev, int *part, void *data)
{
	struct frd_device *frd;
	struct kobject *kobj;
	bool new;

	mutex_lock(&frd_devices_mutex);
	frd = frd_init_one(MINOR(dev) / max_part, &new);
	kobj = frd ? get_disk(frd->frd_disk) : NULL;
	mutex_unlock(&frd_devices_mutex);

	if (new)
		*part = 0;

	return kobj;
}

static int __init frd_init(void)
{
	struct frd_device *frd, *next;
	int i;

	/*
	 * frd module now has a feature to instantiate underlying device
	 * structure on-demand, provided that there is an access dev node.
	 *
	 * (1) if rd_nr is specified, create that many upfront. else
	 *     it defaults to CONFIG_BLK_DEV_RAM_COUNT
	 * (2) User can further extend frd devices by create dev node themselves
	 *     and have kernel automatically instantiate actual device
	 *     on-demand. Example:
	 *		mknod /path/devnod_name b 1 X	# 1 is the rd major
	 *		fdisk -l /path/devnod_name
	 *	If (X / max_part) was not already created it will be created
	 *	dynamically.
	 */

	frd_major = register_blkdev(0, "flatramdisk");
	if (frd_major < 0)
		return -EIO;

	if (unlikely(!max_part))
		max_part = 1;

	for (i = 0; i < rd_nr; i++) {
		frd = frd_alloc(i);
		if (!frd)
			goto out_free;
		list_add_tail(&frd->frd_list, &frd_devices);
	}

	/* point of no return */

	list_for_each_entry(frd, &frd_devices, frd_list)
		add_disk(frd->frd_disk);

	blk_register_region(MKDEV(frd_major, 0), 1UL << MINORBITS,
	                    THIS_MODULE, frd_probe, NULL, NULL);

	pr_info("frd: module loaded\n");
	return 0;

out_free:
	list_for_each_entry_safe(frd, next, &frd_devices, frd_list) {
		list_del(&frd->frd_list);
		frd_free(frd);
	}
	unregister_blkdev(frd_major, "flatramdisk");

	pr_info("frd: module NOT loaded !!!\n");
	return -ENOMEM;
}

static void __exit frd_exit(void)
{
	struct frd_device *frd, *next;

	list_for_each_entry_safe(frd, next, &frd_devices, frd_list)
		frd_del_one(frd);

	blk_unregister_region(MKDEV(frd_major, 0), 1UL << MINORBITS);
	unregister_blkdev(frd_major, "flatramdisk");

	pr_info("frd: module unloaded\n");
}

module_init(frd_init);
module_exit(frd_exit);

MODULE_LICENSE("GPL");
