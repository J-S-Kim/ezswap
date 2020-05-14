/*
 * zswap.c - zswap driver file
 *
 * zswap is a backend for frontswap that takes pages that are in the process
 * of being swapped out and attempts to compress and store them in a
 * RAM-based memory pool.  This can result in a significant I/O reduction on
 * the swap device and, in the case where decompressing from RAM is faster
 * than reading from the swap device, can also improve workload performance.
 *
 * Copyright (C) 2012  Seth Jennings <sjenning@linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
*/

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/cpu.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/frontswap.h>
#include <linux/rbtree.h>
#include <linux/swap.h>
#include <linux/crypto.h>
#include <linux/mempool.h>
#include <linux/zpool.h>

#include <linux/mm_types.h>
#include <linux/page-flags.h>
#include <linux/swapops.h>
#include <linux/writeback.h>
#include <linux/pagemap.h>

#include "logTable.h"
#include <linux/string.h>

#if defined(CONFIG_SOC_EXYNOS5422) || defined(CONFIG_SOC_EXYNOS5430)
extern void show_exynos_pmu(void);
#endif

#define ADMISSION
/*#define DEBUG_ZSWAP*/

#if defined(DEBUG_ZSWAP)
static u32 compress_ratio[11];
static u64 compress_cpu_cycle;
static u64 entropy_cpu_cycle;
#endif
/*********************************
* statistics
**********************************/
static u32 load_times;
static u32 hit_times;
/* Total bytes used by the compressed storage */
static u64 zswap_pool_total_size;
static u64 zswap_pool_largest_size;
/* The number of compressed pages currently stored in zswap */
static atomic_t zswap_stored_pages = ATOMIC_INIT(0);

/*
 * The statistics below are not protected from concurrent access for
 * performance reasons so they may not be a 100% accurate.  However,
 * they do provide useful information on roughly how many times a
 * certain event is occurring.
*/

/* Pool limit was hit (see zswap_max_pool_percent) */
static u64 zswap_pool_limit_hit;
/* Pages written back when pool limit was reached */
static u64 zswap_written_back_pages;
/* Store failed due to a reclaim failure after pool limit was reached */
/* Compressed page was too big for the allocator to (optimally) store */
static u64 zswap_reject_compress_fail;
/* Store failed because underlying allocator could not get memory */
static u64 zswap_reject_alloc_fail;
/* Store failed because the entry metadata could not be allocated (rare) */
static u64 zswap_reject_kmemcache_fail;
/* Duplicate store was encountered (rare) */
static u64 zswap_duplicate_entry;

unsigned int avg_cost = 0;
unsigned int avg_comprate = 1;
/*********************************
* tunables
**********************************/

/* Enable/disable zswap (disabled by default) */
static bool zswap_enabled;
module_param_named(enabled, zswap_enabled, bool, 0644);

/* Crypto compressor to use */
#define ZSWAP_COMPRESSOR_DEFAULT "lzo"
static char *zswap_compressor = ZSWAP_COMPRESSOR_DEFAULT;
static int zswap_compressor_param_set(const char *,
				      const struct kernel_param *);
static struct kernel_param_ops zswap_compressor_param_ops = {
	.set =		zswap_compressor_param_set,
	.get =		param_get_charp,
	.free =		param_free_charp,
};
module_param_cb(compressor, &zswap_compressor_param_ops,
		&zswap_compressor, 0644);

/* Compressed storage zpool to use */
#define ZSWAP_ZPOOL_DEFAULT "zbud"
static char *zswap_zpool_type = ZSWAP_ZPOOL_DEFAULT;
static int zswap_zpool_param_set(const char *, const struct kernel_param *);
static struct kernel_param_ops zswap_zpool_param_ops = {
	.set =		zswap_zpool_param_set,
	.get =		param_get_charp,
	.free =		param_free_charp,
};
module_param_cb(zpool, &zswap_zpool_param_ops, &zswap_zpool_type, 0644);

/* The maximum percentage of memory that the compressed pool can occupy */
unsigned int zswap_max_pool_percent = 20;
module_param_named(max_pool_percent, zswap_max_pool_percent, uint, 0644);
EXPORT_SYMBOL(zswap_max_pool_percent);

static unsigned int zswap_entropy_threshold = 3200;
module_param_named(entropy_threshold, zswap_entropy_threshold, uint, 0644);

static unsigned int zswap_reclaim_pages = 1;
module_param_named(reclaim_pages, zswap_reclaim_pages, uint, 0644);

static bool zswap_same_filled_pages_enabled = true;
module_param_named(same_filled_pages_enabled, zswap_same_filled_pages_enabled, bool, 0644);
/*********************************
* data structures
**********************************/

struct zswap_pool {
	struct zpool *zpool;
	struct crypto_comp * __percpu *tfm;
	struct kref kref;
	struct list_head list;
	struct work_struct work;
	struct notifier_block notifier;
	char tfm_name[CRYPTO_MAX_ALG_NAME];
};

/*
 * struct zswap_entry
 *
 * This structure contains the metadata for tracking a single compressed
 * page within zswap.
 *
 * rbnode - links the entry into red-black tree for the appropriate swap type
 * offset - the swap offset for the entry.  Index into the red-black tree.
 * refcount - the number of outstanding reference to the entry. This is needed
 *            to protect against premature freeing of the entry by code
 *            concurrent calls to load, invalidate, and writeback.  The lock
 *            for the zswap_tree structure that contains the entry must
 *            be held while changing the refcount.  Since the lock must
 *            be held, there is no reason to also make refcount atomic.
 * length - the length in bytes of the compressed page data.  Needed during
 *          decompression
 * pool - the zswap_pool the entry's data is in
 * handle - zpool allocation handle that stores the compressed page data
 */
struct zswap_entry {
	struct rb_node rbnode;
	pgoff_t offset;
	int refcount;
	unsigned int length;
	struct zswap_pool *pool;
	unsigned long handle;
	bool file_mapped;
	struct list_head list;
	unsigned long mapping;
	unsigned long bdev;
};

struct zswap_header {
	swp_entry_t swpentry;
};
struct zswap_file_header {
	swp_entry_t swpentry;
	unsigned long mapping;
	unsigned long bdev;
};

/*
 * The tree lock in the zswap_tree struct protects a few things:
 * - the rbtree
 * - the refcount field of each entry in the tree
 */
struct zswap_tree {
	struct rb_root rbroot;
	spinlock_t lock;
};

static struct zswap_tree *zswap_trees[MAX_SWAPFILES+1];

/* RCU-protected iteration */
static LIST_HEAD(zswap_pools);
/* protects zswap_pools list modification */
static DEFINE_SPINLOCK(zswap_pools_lock);
/* pool counter to provide unique names to zpool */
static atomic_t zswap_pools_count = ATOMIC_INIT(0);

/* used by param callback function */
static bool zswap_init_started;

/*********************************
* helpers and fwd declarations
**********************************/

#define zswap_pool_debug(msg, p)				\
	pr_debug("%s pool %s/%s\n", msg, (p)->tfm_name,		\
		 zpool_get_type((p)->zpool))

static int zswap_writeback_entry(struct zpool *pool, unsigned long handle);
static int zswap_pool_get(struct zswap_pool *pool);
static void zswap_pool_put(struct zswap_pool *pool);

static const struct zpool_ops zswap_zpool_ops = {
	.evict = zswap_writeback_entry
};

static bool zswap_is_full(void)
{
	return totalram_pages * zswap_max_pool_percent / 100 <
		DIV_ROUND_UP(zswap_pool_total_size, PAGE_SIZE);
}

#ifdef ADMISSION
DECLARE_BITMAP(hitmap, 256);
static u32 load_sliding_times;
static u32 hit_sliding_times;
static unsigned int current_pool_percent(void) {
	unsigned int percent = (DIV_ROUND_UP(zswap_pool_total_size, PAGE_SIZE) * 100) ;
	unsigned int tmp = (totalram_pages * zswap_max_pool_percent / 100);

	percent = percent / tmp;

	return percent > 100 ? 100 : percent;
}

static unsigned int get_hit_weight(void) {
	unsigned int hit_weight;

	if(likely(load_times > 255)) 
		hit_weight = hit_sliding_times * 100 / 256;
	
	else 
		hit_weight = load_times == 0 ? 0 : hit_times * 100 / load_times;
	
	return hit_weight;
}
#endif

static inline int get_byte_entropy(const unsigned char* pData, size_t total_size) {
	unsigned short int nCountTable[256] = {0, };
	unsigned int entropy = 0;
	unsigned short int i;
	size_t total_size2;

	total_size2 = 1024;

	for (i = 0; i < total_size; i+=4)
		nCountTable[pData[i]]++;

	for (i = 0; i < 256; i++)
		if (nCountTable[i]) {
			entropy += nCountTable[i] * 
				(ilog2_1000(total_size2) - ilog2_1000(nCountTable[i]));
		}

	return entropy;
}

static void zswap_update_total_size(void)
{
	struct zswap_pool *pool;
	u64 total = 0;

	rcu_read_lock();

	list_for_each_entry_rcu(pool, &zswap_pools, list)
		total += zpool_get_total_size(pool->zpool);

	rcu_read_unlock();

	zswap_pool_total_size = total;
	zswap_pool_largest_size = zswap_pool_largest_size < zswap_pool_total_size
					? zswap_pool_total_size : zswap_pool_largest_size;
}

/*********************************
* zswap entry functions
**********************************/
static struct kmem_cache *zswap_entry_cache;

static int __init zswap_entry_cache_create(void)
{
	zswap_entry_cache = KMEM_CACHE(zswap_entry, 0);
	return zswap_entry_cache == NULL;
}

static void __init zswap_entry_cache_destroy(void)
{
	kmem_cache_destroy(zswap_entry_cache);
}

static struct zswap_entry *zswap_entry_cache_alloc(gfp_t gfp)
{
	struct zswap_entry *entry;
	entry = kmem_cache_alloc(zswap_entry_cache, gfp);
	if (!entry)
		return NULL;
	entry->refcount = 1;
	entry->file_mapped = 0;
	INIT_LIST_HEAD(&entry->list);
	RB_CLEAR_NODE(&entry->rbnode);
	return entry;
}

static void zswap_entry_cache_free(struct zswap_entry *entry)
{
	kmem_cache_free(zswap_entry_cache, entry);
}

/*********************************
* rbtree functions
**********************************/
static struct zswap_entry *zswap_rb_search(struct rb_root *root, pgoff_t offset)
{
	struct rb_node *node = root->rb_node;
	struct zswap_entry *entry;

	while (node) {
		entry = rb_entry(node, struct zswap_entry, rbnode);
		if (entry->offset > offset)
			node = node->rb_left;
		else if (entry->offset < offset)
			node = node->rb_right;
		else
			return entry;
	}
	return NULL;
}

/*
 * In the case that a entry with the same offset is found, a pointer to
 * the existing entry is stored in dupentry and the function returns -EEXIST
 */
static int zswap_rb_insert(struct rb_root *root, struct zswap_entry *entry,
			struct zswap_entry **dupentry)
{
	struct rb_node **link = &root->rb_node, *parent = NULL;
	struct zswap_entry *myentry, *mentry;

	while (*link) {
		parent = *link;
		myentry = rb_entry(parent, struct zswap_entry, rbnode);
		if (myentry->offset > entry->offset)
			link = &(*link)->rb_left;
		else if (myentry->offset < entry->offset)
			link = &(*link)->rb_right;
		else {
			if(entry->file_mapped){
				if(myentry->mapping == entry->mapping && myentry->bdev == entry->bdev){
					*dupentry = myentry;
						return -EEXIST;
				}
				list_for_each_entry_rcu(mentry, &myentry->list, list){
					if(mentry->mapping == entry->mapping && mentry->bdev == entry->bdev){
						*dupentry = mentry;
						return -EEXIST;
					}
				}
				list_add_tail(&entry->list, &myentry->list);
				return 0;
			}
			*dupentry = myentry;
			return -EEXIST;
		}
	}
	rb_link_node(&entry->rbnode, parent, link);
	rb_insert_color(&entry->rbnode, root);
	return 0;
}

static void zswap_rb_erase(struct rb_root *root, struct zswap_entry *entry)
{
	if(entry->file_mapped && !list_empty(&entry->list)){
		struct zswap_entry *next;
		if (!RB_EMPTY_NODE(&entry->rbnode)){
			next = list_entry(entry->list.next, struct zswap_entry, list);
			rb_replace_node(&entry->rbnode, &next->rbnode, root);
			RB_CLEAR_NODE(&entry->rbnode);
		}
		list_del_init(&entry->list);

		return;
	}

	if (!RB_EMPTY_NODE(&entry->rbnode)) {
		rb_erase(&entry->rbnode, root);
		RB_CLEAR_NODE(&entry->rbnode);
	}
}

/*
 * Carries out the common pattern of freeing and entry's zpool allocation,
 * freeing the entry itself, and decrementing the number of stored pages.
 */
static void zswap_free_entry(struct zswap_entry *entry)
{
		zpool_free(entry->pool->zpool, entry->handle);
		zswap_pool_put(entry->pool);
	zswap_entry_cache_free(entry);
	atomic_dec(&zswap_stored_pages);
	zswap_update_total_size();
}

/* caller must hold the tree lock */
static void zswap_entry_get(struct zswap_entry *entry)
{
	entry->refcount++;
}

/* caller must hold the tree lock
* remove from the tree and free it, if nobody reference the entry
*/
static void zswap_entry_put(struct zswap_tree *tree,
			struct zswap_entry *entry)
{
	int refcount = --entry->refcount;

	if(refcount < 0){
		if(entry->file_mapped)
			printk(KERN_INFO "FILE\n");
		BUG_ON(refcount < 0);
	}
	if (refcount == 0) {
		zswap_rb_erase(&tree->rbroot, entry);
		zswap_free_entry(entry);
		
		/*zswap_rb_search(&tree->rbroot, offset...)*/
	}
}

/* caller must hold the tree lock */
static struct zswap_entry *zswap_entry_find_get(struct rb_root *root,
				pgoff_t offset)
{
	struct zswap_entry *entry;

	entry = zswap_rb_search(root, offset);
	if (entry)
		zswap_entry_get(entry);

	return entry;
}
static struct zswap_entry *zswap_entry_file_find_get(struct zswap_entry *root,
				struct zswap_file_header *zfdr)
{
	struct zswap_entry *entry;

	if(root->mapping == zfdr->mapping && root->bdev == zfdr->bdev){
		/*zswap_entry_get(root);*/
		return root;
	}

	list_for_each_entry_rcu(entry, &root->list, list){
		if(entry->mapping == zfdr->mapping && entry->bdev == zfdr->bdev){
			/*zswap_entry_get(entry);*/
			return entry;
		}
	}

	return NULL;
}


/*********************************
 * per-cpu code
 **********************************/
static DEFINE_PER_CPU(u8 *, zswap_dstmem);

static int __zswap_cpu_dstmem_notifier(unsigned long action, unsigned long cpu)
{
	u8 *dst;

	switch (action) {
	case CPU_UP_PREPARE:
		dst = kmalloc_node(PAGE_SIZE * 2, GFP_KERNEL, cpu_to_node(cpu));
		if (!dst) {
			pr_err("can't allocate compressor buffer\n");
			return NOTIFY_BAD;
		}
		per_cpu(zswap_dstmem, cpu) = dst;
		break;
	case CPU_DEAD:
	case CPU_UP_CANCELED:
		dst = per_cpu(zswap_dstmem, cpu);
		kfree(dst);
		per_cpu(zswap_dstmem, cpu) = NULL;
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}

static int zswap_cpu_dstmem_notifier(struct notifier_block *nb,
				     unsigned long action, void *pcpu)
{
	return __zswap_cpu_dstmem_notifier(action, (unsigned long)pcpu);
}

static struct notifier_block zswap_dstmem_notifier = {
	.notifier_call =	zswap_cpu_dstmem_notifier,
};

static int __init zswap_cpu_dstmem_init(void)
{
	unsigned long cpu;

	cpu_notifier_register_begin();
	for_each_online_cpu(cpu)
		if (__zswap_cpu_dstmem_notifier(CPU_UP_PREPARE, cpu) ==
		    NOTIFY_BAD)
			goto cleanup;
	__register_cpu_notifier(&zswap_dstmem_notifier);
	cpu_notifier_register_done();
	return 0;

cleanup:
	for_each_online_cpu(cpu)
		__zswap_cpu_dstmem_notifier(CPU_UP_CANCELED, cpu);
	cpu_notifier_register_done();
	return -ENOMEM;
}

static void zswap_cpu_dstmem_destroy(void)
{
	unsigned long cpu;

	cpu_notifier_register_begin();
	for_each_online_cpu(cpu)
		__zswap_cpu_dstmem_notifier(CPU_UP_CANCELED, cpu);
	__unregister_cpu_notifier(&zswap_dstmem_notifier);
	cpu_notifier_register_done();
}

static int __zswap_cpu_comp_notifier(struct zswap_pool *pool,
				     unsigned long action, unsigned long cpu)
{
	struct crypto_comp *tfm;

	switch (action) {
	case CPU_UP_PREPARE:
		if (WARN_ON(*per_cpu_ptr(pool->tfm, cpu)))
			break;
		tfm = crypto_alloc_comp(pool->tfm_name, 0, 0);
		if (IS_ERR_OR_NULL(tfm)) {
			pr_err("could not alloc crypto comp %s : %ld\n",
			       pool->tfm_name, PTR_ERR(tfm));
			return NOTIFY_BAD;
		}
		*per_cpu_ptr(pool->tfm, cpu) = tfm;
		break;
	case CPU_DEAD:
	case CPU_UP_CANCELED:
		tfm = *per_cpu_ptr(pool->tfm, cpu);
		if (!IS_ERR_OR_NULL(tfm))
			crypto_free_comp(tfm);
		*per_cpu_ptr(pool->tfm, cpu) = NULL;
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}

static int zswap_cpu_comp_notifier(struct notifier_block *nb,
				   unsigned long action, void *pcpu)
{
	unsigned long cpu = (unsigned long)pcpu;
	struct zswap_pool *pool = container_of(nb, typeof(*pool), notifier);

	return __zswap_cpu_comp_notifier(pool, action, cpu);
}

static int zswap_cpu_comp_init(struct zswap_pool *pool)
{
	unsigned long cpu;

	memset(&pool->notifier, 0, sizeof(pool->notifier));
	pool->notifier.notifier_call = zswap_cpu_comp_notifier;

	cpu_notifier_register_begin();
	for_each_online_cpu(cpu)
		if (__zswap_cpu_comp_notifier(pool, CPU_UP_PREPARE, cpu) ==
		    NOTIFY_BAD)
			goto cleanup;
	__register_cpu_notifier(&pool->notifier);
	cpu_notifier_register_done();
	return 0;

cleanup:
	for_each_online_cpu(cpu)
		__zswap_cpu_comp_notifier(pool, CPU_UP_CANCELED, cpu);
	cpu_notifier_register_done();
	return -ENOMEM;
}

static void zswap_cpu_comp_destroy(struct zswap_pool *pool)
{
	unsigned long cpu;

	cpu_notifier_register_begin();
	for_each_online_cpu(cpu)
		__zswap_cpu_comp_notifier(pool, CPU_UP_CANCELED, cpu);
	__unregister_cpu_notifier(&pool->notifier);
	cpu_notifier_register_done();
}

/*********************************
* pool functions
**********************************/

static struct zswap_pool *__zswap_pool_current(void)
{
	struct zswap_pool *pool;

	pool = list_first_or_null_rcu(&zswap_pools, typeof(*pool), list);
	WARN_ON(!pool);

	return pool;
}

static struct zswap_pool *zswap_pool_current(void)
{
	assert_spin_locked(&zswap_pools_lock);

	return __zswap_pool_current();
}

static struct zswap_pool *zswap_pool_current_get(void)
{
	struct zswap_pool *pool;

	rcu_read_lock();

	pool = __zswap_pool_current();
	if (!pool || !zswap_pool_get(pool))
		pool = NULL;

	rcu_read_unlock();

	return pool;
}

static struct zswap_pool *zswap_pool_last_get(void)
{
	struct zswap_pool *pool, *last = NULL;

	rcu_read_lock();

	list_for_each_entry_rcu(pool, &zswap_pools, list)
		last = pool;
	if (!WARN_ON(!last) && !zswap_pool_get(last))
		last = NULL;

	rcu_read_unlock();

	return last;
}

/* type and compressor must be null-terminated */
static struct zswap_pool *zswap_pool_find_get(char *type, char *compressor)
{
	struct zswap_pool *pool;

	assert_spin_locked(&zswap_pools_lock);

	list_for_each_entry_rcu(pool, &zswap_pools, list) {
		if (strcmp(pool->tfm_name, compressor))
			continue;
		if (strcmp(zpool_get_type(pool->zpool), type))
			continue;
		/* if we can't get it, it's about to be destroyed */
		if (!zswap_pool_get(pool))
			continue;
		return pool;
	}

	return NULL;
}

static struct zswap_pool *zswap_pool_create(char *type, char *compressor)
{
	struct zswap_pool *pool;
	char name[38]; /* 'zswap' + 32 char (max) num + \0 */
	gfp_t gfp = __GFP_NORETRY | __GFP_NOWARN;

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool) {
		pr_err("pool alloc failed\n");
		return NULL;
	}

	/* unique name for each pool specifically required by zsmalloc */
	snprintf(name, 38, "zswap%x", atomic_inc_return(&zswap_pools_count));

	pool->zpool = zpool_create_pool(type, name, gfp, &zswap_zpool_ops);
	if (!pool->zpool) {
		pr_err("%s zpool not available\n", type);
		goto error;
	}
	pr_debug("using %s zpool\n", zpool_get_type(pool->zpool));

	strlcpy(pool->tfm_name, compressor, sizeof(pool->tfm_name));
	pool->tfm = alloc_percpu(struct crypto_comp *);
	if (!pool->tfm) {
		pr_err("percpu alloc failed\n");
		goto error;
	}

	if (zswap_cpu_comp_init(pool))
		goto error;
	pr_debug("using %s compressor\n", pool->tfm_name);

	/* being the current pool takes 1 ref; this func expects the
	 * caller to always add the new pool as the current pool
	 */
	kref_init(&pool->kref);
	INIT_LIST_HEAD(&pool->list);

	zswap_pool_debug("created", pool);

	return pool;

error:
	free_percpu(pool->tfm);
	if (pool->zpool)
		zpool_destroy_pool(pool->zpool);
	kfree(pool);
	return NULL;
}

static __init struct zswap_pool *__zswap_pool_create_fallback(void)
{
	if (!crypto_has_comp(zswap_compressor, 0, 0)) {
		if (!strcmp(zswap_compressor, ZSWAP_COMPRESSOR_DEFAULT)) {
			pr_err("default compressor %s not available\n",
			       zswap_compressor);
			return NULL;
		}
		pr_err("compressor %s not available, using default %s\n",
		       zswap_compressor, ZSWAP_COMPRESSOR_DEFAULT);
		param_free_charp(&zswap_compressor);
		zswap_compressor = ZSWAP_COMPRESSOR_DEFAULT;
	}
	if (!zpool_has_pool(zswap_zpool_type)) {
		if (!strcmp(zswap_zpool_type, ZSWAP_ZPOOL_DEFAULT)) {
			pr_err("default zpool %s not available\n",
			       zswap_zpool_type);
			return NULL;
		}
		pr_err("zpool %s not available, using default %s\n",
		       zswap_zpool_type, ZSWAP_ZPOOL_DEFAULT);
		param_free_charp(&zswap_zpool_type);
		zswap_zpool_type = ZSWAP_ZPOOL_DEFAULT;
	}

	return zswap_pool_create(zswap_zpool_type, zswap_compressor);
}

static void zswap_pool_destroy(struct zswap_pool *pool)
{
	zswap_pool_debug("destroying", pool);

	zswap_cpu_comp_destroy(pool);
	free_percpu(pool->tfm);
	zpool_destroy_pool(pool->zpool);
	kfree(pool);
}

static int __must_check zswap_pool_get(struct zswap_pool *pool)
{
	return kref_get_unless_zero(&pool->kref);
}

static void __zswap_pool_release(struct work_struct *work)
{
	struct zswap_pool *pool = container_of(work, typeof(*pool), work);

	synchronize_rcu();

	/* nobody should have been able to get a kref... */
	WARN_ON(kref_get_unless_zero(&pool->kref));

	/* pool is now off zswap_pools list and has no references. */
	zswap_pool_destroy(pool);
}

static void __zswap_pool_empty(struct kref *kref)
{
	struct zswap_pool *pool;

	pool = container_of(kref, typeof(*pool), kref);

	spin_lock(&zswap_pools_lock);

	WARN_ON(pool == zswap_pool_current());

	list_del_rcu(&pool->list);

	INIT_WORK(&pool->work, __zswap_pool_release);
	schedule_work(&pool->work);

	spin_unlock(&zswap_pools_lock);
}

static void zswap_pool_put(struct zswap_pool *pool)
{
	kref_put(&pool->kref, __zswap_pool_empty);
}

/*********************************
* param callbacks
**********************************/

/* val must be a null-terminated string */
static int __zswap_param_set(const char *val, const struct kernel_param *kp,
			     char *type, char *compressor)
{
	struct zswap_pool *pool, *put_pool = NULL;
	char *s = strstrip((char *)val);
	int ret;

	/* no change required */
	if (!strcmp(s, *(char **)kp->arg))
		return 0;

	/* if this is load-time (pre-init) param setting,
	 * don't create a pool; that's done during init.
	 */
	if (!zswap_init_started)
		return param_set_charp(s, kp);

	if (!type) {
		if (!zpool_has_pool(s)) {
			pr_err("zpool %s not available\n", s);
			return -ENOENT;
		}
		type = s;
	} else if (!compressor) {
		if (!crypto_has_comp(s, 0, 0)) {
			pr_err("compressor %s not available\n", s);
			return -ENOENT;
		}
		compressor = s;
	} else {
		WARN_ON(1);
		return -EINVAL;
	}

	spin_lock(&zswap_pools_lock);

	pool = zswap_pool_find_get(type, compressor);
	if (pool) {
		zswap_pool_debug("using existing", pool);
		list_del_rcu(&pool->list);
	} else {
		spin_unlock(&zswap_pools_lock);
		pool = zswap_pool_create(type, compressor);
		spin_lock(&zswap_pools_lock);
	}

	if (pool)
		ret = param_set_charp(s, kp);
	else
		ret = -EINVAL;

	if (!ret) {
		put_pool = zswap_pool_current();
		list_add_rcu(&pool->list, &zswap_pools);
	} else if (pool) {
		/* add the possibly pre-existing pool to the end of the pools
		 * list; if it's new (and empty) then it'll be removed and
		 * destroyed by the put after we drop the lock
		 */
		list_add_tail_rcu(&pool->list, &zswap_pools);
		put_pool = pool;
	}

	spin_unlock(&zswap_pools_lock);

	/* drop the ref from either the old current pool,
	 * or the new pool we failed to add
	 */
	if (put_pool)
		zswap_pool_put(put_pool);

	return ret;
}

static int zswap_compressor_param_set(const char *val,
				      const struct kernel_param *kp)
{
	return __zswap_param_set(val, kp, zswap_zpool_type, NULL);
}

static int zswap_zpool_param_set(const char *val,
				 const struct kernel_param *kp)
{
	return __zswap_param_set(val, kp, NULL, zswap_compressor);
}

/*********************************
* writeback code
**********************************/
/* return enum for zswap_get_swap_cache_page */
enum zswap_get_swap_ret {
	ZSWAP_SWAPCACHE_NEW,
	ZSWAP_SWAPCACHE_EXIST,
	ZSWAP_SWAPCACHE_FAIL,
};

/*
 * zswap_get_swap_cache_page
 *
 * This is an adaption of read_swap_cache_async()
 *
 * This function tries to find a page with the given swap entry
 * in the swapper_space address space (the swap cache).  If the page
 * is found, it is returned in retpage.  Otherwise, a page is allocated,
 * added to the swap cache, and returned in retpage.
 *
 * If success, the swap cache page is returned in retpage
 * Returns ZSWAP_SWAPCACHE_EXIST if page was already in the swap cache
 * Returns ZSWAP_SWAPCACHE_NEW if the new page needs to be populated,
 *     the new page is added to swapcache and locked
 * Returns ZSWAP_SWAPCACHE_FAIL on error
 */
static int zswap_get_swap_cache_page(swp_entry_t entry,
				struct page **retpage)
{
	bool page_was_allocated;

	*retpage = __read_swap_cache_async(entry, GFP_KERNEL,
			NULL, 0, &page_was_allocated);
	if (page_was_allocated)
		return ZSWAP_SWAPCACHE_NEW;
	if (!*retpage)
		return ZSWAP_SWAPCACHE_FAIL;
	return ZSWAP_SWAPCACHE_EXIST;
}

/*
 * Attempts to free an entry by adding a page to the swap cache,
 * decompressing the entry data into the page, and issuing a
 * bio write to write the page back to the swap device.
 *
 * This can be thought of as a "resumed writeback" of the page
 * to the swap device.  We are basically resuming the same swap
 * writeback path that was intercepted with the frontswap_store()
 * in the first place.  After the page has been decompressed into
 * the swap cache, the compressed version stored by zswap can be
 * freed.
 */
static int zswap_writeback_entry(struct zpool *pool, unsigned long handle)
{
	struct zswap_header *zhdr;
	struct zswap_file_header *zfdr;
	swp_entry_t swpentry;
	struct zswap_tree *tree;
	pgoff_t offset;
	struct zswap_entry *entry, *entry_inval;
	struct page *page;
	struct crypto_comp *tfm;
	u8 *src, *dst;
	unsigned int dlen;
	int ret;
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_NONE,
	};
#ifdef ADMISSION
	unsigned int cost, real_comprate, counter, counter10;
#endif

	/* extract swpentry from data */
	zhdr = zpool_map_handle(pool, handle, ZPOOL_MM_RO);
	swpentry = zhdr->swpentry; /* here */
	zpool_unmap_handle(pool, handle);
	tree = zswap_trees[swp_type(swpentry)];
	offset = swp_offset(swpentry);

	if(!tree) {
		printk(KERN_INFO "No tree in writeback\n");
		return 0;
	}

	/* find and ref zswap entry */
	spin_lock(&tree->lock);
	entry = zswap_entry_find_get(&tree->rbroot, offset);
	if(entry && entry->file_mapped) {
		zfdr = (struct zswap_file_header*)zhdr;
		zswap_entry_put(tree, entry);
		entry = zswap_entry_file_find_get(entry, zfdr);
		if(entry)
			zswap_entry_get(entry);
	}

	if (!entry) {
		/* entry was invalidated */
		spin_unlock(&tree->lock);
		return 0;
	}
	spin_unlock(&tree->lock);
	BUG_ON(offset != entry->offset);

#ifdef ADMISSION
	counter = zswap_stored_pages.counter;
	cost = entry->file_mapped == true ? 10000 : 40000 ;
	real_comprate = entry->length * 10000 / PAGE_SIZE;
	counter10 = counter <= 1000 ? 1 : counter / 1000;
	avg_cost = ((avg_cost * counter) - (cost*counter10)) / (counter - counter10);
	avg_comprate = ((avg_comprate * counter) - (real_comprate*counter10)) / (counter - counter10);
	if(!avg_comprate)
		avg_comprate = 1;
#endif


	if(entry->file_mapped){
		zz_file_page_out++;
		ret = 0;
		goto leave;
	}

	/* try to allocate swap cache page */
	switch (zswap_get_swap_cache_page(swpentry, &page)) {
	case ZSWAP_SWAPCACHE_FAIL: /* no memory or invalidate happened */
		ret = -ENOMEM;
		goto fail;

	case ZSWAP_SWAPCACHE_EXIST:
		/* page is already in the swap cache, ignore for now */
		put_page(page);
		ret = -EEXIST;
		goto fail;

	case ZSWAP_SWAPCACHE_NEW: /* page is locked */
		/* decompress */
		dlen = PAGE_SIZE;
		src = (u8 *)zpool_map_handle(entry->pool->zpool, entry->handle,
				ZPOOL_MM_RO) + sizeof(struct zswap_header);
		dst = kmap_atomic(page);
		tfm = *get_cpu_ptr(entry->pool->tfm);
		ret = crypto_comp_decompress(tfm, src, entry->length,
					     dst, &dlen);
		put_cpu_ptr(entry->pool->tfm);
		kunmap_atomic(dst);
		zpool_unmap_handle(entry->pool->zpool, entry->handle);
		BUG_ON(ret);
		BUG_ON(dlen != PAGE_SIZE);

		/* page is up to date */
		SetPageUptodate(page);
	}

	/* move it to the tail of the inactive list after end_writeback */
	SetPageReclaim(page);

	/* start writeback */
	__swap_writepage(page, &wbc, end_swap_bio_write);
	put_page(page);
	zswap_written_back_pages++;

leave:
	spin_lock(&tree->lock);
	/* drop local reference */
	zswap_entry_put(tree, entry);

	/*
	* There are two possible situations for entry here:
	* (1) refcount is 1(normal case),  entry is valid and on the tree
	* (2) refcount is 0, entry is freed and not on the tree
	*     because invalidate happened during writeback
	*  search the tree and free the entry if find entry
	*/

	//UNIQ
	entry_inval = zswap_rb_search(&tree->rbroot, offset);
	if (entry_inval){ 
		if(!entry_inval->file_mapped && entry_inval == entry)
			zswap_entry_put(tree, entry);
		else if(entry == zswap_entry_file_find_get(entry_inval, zfdr))
			zswap_entry_put(tree, entry);
	}

	spin_unlock(&tree->lock);

	goto end;

	/*
	* if we get here due to ZSWAP_SWAPCACHE_EXIST
	* a load may happening concurrently
	* it is safe and okay to not free the entry
	* if we free the entry in the following put
	* it it either okay to return !0
	*/
fail:
	spin_lock(&tree->lock);
	zswap_entry_put(tree, entry);
	spin_unlock(&tree->lock);

end:
	return ret;
}

static int zswap_shrink(void)
{
	struct zswap_pool *pool;
	int ret;

	pool = zswap_pool_last_get();
	if (!pool)
		return -ENOENT;

	ret = zpool_shrink(pool->zpool, zswap_reclaim_pages, NULL);

	zswap_pool_put(pool);

	return ret;
}

#define PERF_DEF_OPTS (1 | 16)
#define PERF_OPT_RESET_CYCLES (2 | 4)
#define PERF_OPT_DIV64 (8)
static inline uint32_t rdtsc32(void) 
{
	uint32_t r = 0;
	asm volatile("mrc p15, 0, %0, c9, c13, 0" : "=r"(r));
	return r;
}
/*********************************
* frontswap hooks
**********************************/
/* attempts to compress and store an single page */
static int zswap_frontswap_store(unsigned type, pgoff_t offset,
				struct page *page, bool kswapd)
{
	struct zswap_tree *tree = zswap_trees[type];
	struct zswap_entry *entry, *dupentry;
	struct crypto_comp *tfm;
	int ret;
	unsigned int dlen = PAGE_SIZE, hlen;
#ifdef ADMISSION
	unsigned int expected_comprate, expected_benefit, cost, avg_benefit;
	unsigned int capacity_weight, hit_weight, real_comprate, counter, counter10;
#endif
	unsigned long handle = 0;
	char *buf;
	u8 *src, *dst;
	struct zswap_header zhdr = { .swpentry = swp_entry(type, offset) };
	struct zswap_file_header zfdr = { .swpentry = swp_entry(type, offset) };
	bool is_file = !PageSwapBacked(page);
#if defined(DEBUG_ZSWAP)
	uint32_t cycle_before, cycle_after; 
	uint32_t entc_before, entc_after; 
#endif

	if (!zswap_enabled || !tree) {
		ret = -ENODEV;
		goto reject;
	}

#ifdef ADMISSION
	/*Admission Control*/
	cost = is_file == true ? 10000 : 40000 ;
	src = kmap_atomic(page);
#if defined(DEBUG_ZSWAP)
	entc_before = rdtsc32();
#endif
	expected_comprate = ((get_byte_entropy(src, PAGE_SIZE)/1024)*10000)/8000;
#if defined(DEBUG_ZSWAP)
	entc_after = rdtsc32();
	entropy_cpu_cycle += entc_after - entc_before;
#endif

	kunmap_atomic(src);
	if(!expected_comprate)
		expected_comprate = 1;
	expected_benefit = 10000 * cost / expected_comprate;

	counter = zswap_stored_pages.counter;

	capacity_weight = current_pool_percent();
	hit_weight = get_hit_weight();
	avg_benefit = (10000 * avg_cost / avg_comprate) * hit_weight / 100;
	avg_benefit = (avg_benefit * capacity_weight) / 100;

	if(expected_benefit < avg_benefit){

		ret = -EINVAL;
		goto reject;
	}
#endif

	/* reclaim space if needed */
	if (zswap_is_full()) {
		zswap_pool_limit_hit++;
		if(!kswapd){
			ret = -ENOMEM;
			goto reject;
		}
		if (zswap_shrink()) {
			ret = -ENOMEM;
			goto reject;
		}
		if (zswap_is_full()) {
			ret = -ENOMEM;
			goto reject;
		}
	}

	/* allocate entry */
	entry = zswap_entry_cache_alloc(GFP_KERNEL);
	if (!entry) {
		zswap_reject_kmemcache_fail++;
		ret = -ENOMEM;
		goto reject;
	}

	/* if entry is successfully added, it keeps the reference */
	entry->pool = zswap_pool_current_get();
	if (!entry->pool) {
		ret = -EINVAL;
		goto freepage;
	}

	/* compress */
	dst = get_cpu_var(zswap_dstmem);
	tfm = *get_cpu_ptr(entry->pool->tfm);
	src = kmap_atomic(page);
	
#if defined(DEBUG_ZSWAP)
	cycle_before = rdtsc32();
#endif
	ret = crypto_comp_compress(tfm, src, PAGE_SIZE, dst, &dlen);
#if defined(DEBUG_ZSWAP)
	cycle_after = rdtsc32();


	compress_cpu_cycle += cycle_after - cycle_before;
	u32 tmp = (u32)dlen*100/(u32)PAGE_SIZE/10;
	compress_ratio[tmp]++;
#endif

	kunmap_atomic(src);
	put_cpu_ptr(entry->pool->tfm);
	if (ret) {
		ret = -EINVAL;
		zswap_reject_compress_fail++;
		goto put_dstmem;
	}

	/* store */
	//UNIQ
	if(zpool_evictable(entry->pool->zpool)){
		if(is_file){
			if(page->mapping->host == NULL) {
				ret = -EINVAL;
				printk(KERN_INFO "Host NULL\n");
				goto put_dstmem;
			}
			if(page->mapping->host->i_sb == NULL) {
				ret = -EINVAL;
				printk(KERN_INFO "SB NULL\n");
				goto put_dstmem;
			}
			hlen = sizeof(zfdr);
			zfdr.mapping = page->mapping->host->i_ino;
			zfdr.bdev = page->mapping->host->i_sb->s_dev;
			handle = 1;
		}
		else
			hlen = sizeof(zhdr);
	}	
	else
		hlen = 0;

	ret = zpool_malloc(entry->pool->zpool, hlen + dlen,
			   __GFP_NORETRY | __GFP_NOWARN,
			   &handle);
	if (ret == -ENOSPC) {
		goto put_dstmem;
	}
	if (ret) {
		zswap_reject_alloc_fail++;
		goto put_dstmem;
	}

	buf = zpool_map_handle(entry->pool->zpool, handle, ZPOOL_MM_RW);
	if(is_file)
		memcpy(buf, &zfdr, hlen);
	else
		memcpy(buf, &zhdr, hlen);
	memcpy(buf + hlen, dst, dlen);
	zpool_unmap_handle(entry->pool->zpool, handle);
	put_cpu_var(zswap_dstmem);

	/* populate entry */
	entry->offset = offset;
	entry->handle = handle;
	entry->length = dlen;

	if(is_file) {
		entry->file_mapped = 1;
		entry->mapping = zfdr.mapping;
		entry->bdev = zfdr.bdev;
	}

	/* map */
	spin_lock(&tree->lock);
	do {
		ret = zswap_rb_insert(&tree->rbroot, entry, &dupentry);
		if (ret == -EEXIST) {
			zswap_duplicate_entry++;
			/* remove from rbtree */
			zswap_rb_erase(&tree->rbroot, dupentry);
			zswap_entry_put(tree, dupentry);
		}
	} while (ret == -EEXIST);
	spin_unlock(&tree->lock);

#ifdef ADMISSION
	/* average update */
	real_comprate = dlen * 10000 / PAGE_SIZE;
	counter10 = counter <= 1000 ? 1 : counter / 1000;
	avg_cost = ((avg_cost * counter) + (cost*counter10)) / (counter + counter10);
	avg_comprate = ((avg_comprate * counter) + (real_comprate*counter10)) / (counter + counter10);
	if(!avg_comprate)
		avg_comprate = 1;
#endif

	/* update stats */
	atomic_inc(&zswap_stored_pages);
	zswap_update_total_size();

	return 0;

put_dstmem:
	put_cpu_var(zswap_dstmem);
	zswap_pool_put(entry->pool);
freepage:
	zswap_entry_cache_free(entry);
reject:
	return ret;
}

/*
 * returns 0 if the page was successfully decompressed
 * return -1 on entry not found or error
*/
static int zswap_frontswap_load(unsigned type, pgoff_t offset,
				struct page *page)
{
	struct zswap_tree *tree = zswap_trees[type];
	struct zswap_entry *entry, *entry_inval;
	struct crypto_comp *tfm;
	u8 *src, *dst;
	unsigned int dlen;
#ifdef ADMISSION
	unsigned int time, old_hit;

	/*ADDING ADMI*/
	unsigned int cost, real_comprate, counter, counter10;
#endif
	int ret;
	struct zswap_file_header zfdr;

	if (!zswap_enabled || !tree)
		return -1;

#ifdef ADMISSION
	load_times++;
	time = load_sliding_times++;

	if(load_sliding_times >= 256)
		load_sliding_times = 0;
	if(time > 255)
		time -= 255;

	old_hit = test_and_clear_bit(time, hitmap);

	/*ADDING ADMI*/
	counter = zswap_stored_pages.counter;
#endif
	/* find */

	spin_lock(&tree->lock);

	entry = zswap_entry_find_get(&tree->rbroot, offset);
	if(entry && entry->file_mapped) {
		zfdr.mapping = page->mapping->host->i_ino;
		zfdr.bdev = page->mapping->host->i_sb->s_dev;

		zswap_entry_put(tree, entry);
		entry = zswap_entry_file_find_get(entry, &zfdr);
		if(entry){
			zswap_entry_get(entry);
		}
	}

	if (!entry) {
		/* entry was written back */
		spin_unlock(&tree->lock);
#ifdef ADMISSION
		if(hit_sliding_times > 0)
			hit_sliding_times -= old_hit;
#endif
		return -1;
	}
	spin_unlock(&tree->lock);

	/* decompress */
	dlen = PAGE_SIZE;
	src = zpool_map_handle(entry->pool->zpool, entry->handle, ZPOOL_MM_RO);
	if(zpool_evictable(entry->pool->zpool)){
		src += entry->file_mapped ? sizeof(struct zswap_file_header) 
			: sizeof(struct zswap_header);
	}
	dst = kmap_atomic(page);
	tfm = *get_cpu_ptr(entry->pool->tfm);
	ret = crypto_comp_decompress(tfm, src, entry->length, dst, &dlen);
	hit_times++;
	put_cpu_ptr(entry->pool->tfm);
	kunmap_atomic(dst);
	zpool_unmap_handle(entry->pool->zpool, entry->handle);
	BUG_ON(ret);

#ifdef ADMISSION
	set_bit(time, hitmap);
	if(!old_hit)
		hit_sliding_times++;

	cost = entry->file_mapped == true ? 10000 : 40000 ;
	real_comprate = entry->length * 10000 / PAGE_SIZE;
	counter10 = counter <= 1000 ? 1 : counter / 1000;
	avg_cost = ((avg_cost * counter) - (cost*counter10)) / (counter - counter10);
	avg_comprate = ((avg_comprate * counter) - (real_comprate*counter10)) / (counter - counter10);
	if(!avg_comprate)
		avg_comprate = 1;
#endif

	spin_lock(&tree->lock);
	zswap_entry_put(tree, entry);
	if(entry->file_mapped){
		entry_inval = zswap_rb_search(&tree->rbroot, offset);
		if(entry_inval){
			if(entry == zswap_entry_file_find_get(entry_inval, &zfdr))
				zswap_entry_put(tree, entry);
		}
	}
	spin_unlock(&tree->lock);

	return 0;
}

/* frees an entry in zswap */
static void zswap_frontswap_invalidate_page(unsigned type, pgoff_t offset)
{
	struct zswap_tree *tree = zswap_trees[type];
	struct zswap_entry *entry;

	/* find */
	spin_lock(&tree->lock);
	entry = zswap_rb_search(&tree->rbroot, offset);
	if (!entry) {
		/* entry was written back */
		spin_unlock(&tree->lock);
		return;
	}

	/* remove from rbtree */
	zswap_rb_erase(&tree->rbroot, entry);

	/* drop the initial reference from entry creation */
	zswap_entry_put(tree, entry);

	spin_unlock(&tree->lock);
}
static void zswap_frontswap_invalidate_file_page(pgoff_t offset, unsigned long mapping)
{
	struct zswap_tree *tree = zswap_trees[MAX_SWAPFILES];
	struct zswap_entry *entry;

	/* find */
	spin_lock(&tree->lock);
	entry = zswap_rb_search(&tree->rbroot, offset);
	if (!entry) {
		/* entry was written back */
		spin_unlock(&tree->lock);
		return;
	}

	/* remove from rbtree */
	if(!entry) {
		zswap_rb_erase(&tree->rbroot, entry);

		/* drop the initial reference from entry creation */
		zswap_entry_put(tree, entry);
	}

	spin_unlock(&tree->lock);
}

/* frees all zswap entries for the given swap type */
static void zswap_frontswap_invalidate_area(unsigned type)
{
	struct zswap_tree *tree = zswap_trees[type];
	struct zswap_entry *entry, *n;

	if (!tree)
		return;

	/* walk the tree and free everything */
	spin_lock(&tree->lock);
	rbtree_postorder_for_each_entry_safe(entry, n, &tree->rbroot, rbnode)
		zswap_free_entry(entry);
	tree->rbroot = RB_ROOT;
	spin_unlock(&tree->lock);
	kfree(tree);
	zswap_trees[type] = NULL;
}

static void zswap_frontswap_init(unsigned type)
{
	struct zswap_tree *tree;

	tree = kzalloc(sizeof(struct zswap_tree), GFP_KERNEL);
	if (!tree) {
		pr_err("alloc failed, zswap disabled for swap type %d\n", type);
		return;
	}

	tree->rbroot = RB_ROOT;
	spin_lock_init(&tree->lock);
	zswap_trees[type] = tree;
}

static struct frontswap_ops zswap_frontswap_ops = {
	.store = zswap_frontswap_store,
	.load = zswap_frontswap_load,
	.invalidate_page = zswap_frontswap_invalidate_page,
	.invalidate_file_page = zswap_frontswap_invalidate_file_page,
	.invalidate_area = zswap_frontswap_invalidate_area,
	.init = zswap_frontswap_init
};

/*********************************
* debugfs functions
**********************************/
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>

static struct dentry *zswap_debugfs_root;

static int __init zswap_debugfs_init(void)
{
	if (!debugfs_initialized())
		return -ENODEV;

	zswap_debugfs_root = debugfs_create_dir("zswap", NULL);
	if (!zswap_debugfs_root)
		return -ENOMEM;
	debugfs_create_u32("hit_times", S_IRUGO,
			zswap_debugfs_root, &hit_times);
	debugfs_create_u32("load_times", S_IRUGO,
			zswap_debugfs_root, &load_times);

#if defined(DEBUG_ZSWAP)
	debugfs_create_u32_array("compress_ratio", S_IRUGO,
			zswap_debugfs_root, compress_ratio, 11);
	debugfs_create_u64("compress_cpu_cycle", S_IRUGO,
			zswap_debugfs_root, &compress_cpu_cycle);
	debugfs_create_u64("entropy_cpu_cycle", S_IRUGO,
			zswap_debugfs_root, &entropy_cpu_cycle);
#endif

	debugfs_create_u64("pool_largest_size", S_IRUGO,
			zswap_debugfs_root, &zswap_pool_largest_size);

	debugfs_create_u64("pool_limit_hit", S_IRUGO,
			zswap_debugfs_root, &zswap_pool_limit_hit);
	debugfs_create_u64("reject_alloc_fail", S_IRUGO,
			zswap_debugfs_root, &zswap_reject_alloc_fail);
	debugfs_create_u64("reject_kmemcache_fail", S_IRUGO,
			zswap_debugfs_root, &zswap_reject_kmemcache_fail);
	debugfs_create_u64("reject_compress_fail", S_IRUGO,
			zswap_debugfs_root, &zswap_reject_compress_fail);
	debugfs_create_u64("written_back_pages", S_IRUGO,
			zswap_debugfs_root, &zswap_written_back_pages);
	debugfs_create_u64("duplicate_entry", S_IRUGO,
			zswap_debugfs_root, &zswap_duplicate_entry);
	debugfs_create_u64("pool_total_size", S_IRUGO,
			zswap_debugfs_root, &zswap_pool_total_size);
	debugfs_create_u32("stored_pages", S_IRUGO,
			zswap_debugfs_root, (u32 *)&zswap_stored_pages);

	return 0;
}

static void __exit zswap_debugfs_exit(void)
{
	debugfs_remove_recursive(zswap_debugfs_root);
}
#else
static int __init zswap_debugfs_init(void)
{
	return 0;
}

static void __exit zswap_debugfs_exit(void) { }
#endif

/*********************************
* module init and exit
**********************************/
static void enable_cpu_counters(void *data)
{
	uint32_t pmcr;

	printk(KERN_INFO "enabling PMU on CPU#%d\n", smp_processor_id());

	asm volatile("mcr p15, 0, %0, c9, c14, 0" :: "r"(1));
	pmcr = 1;
	pmcr |= 2;
	pmcr |= 4;
	pmcr |= 8;
	pmcr |= 16;
	asm volatile("mcr p15, 0, %0, c9, c12, 0" :: "r"(pmcr));
	asm volatile("mcr p15, 0, %0, c9, c12, 1" :: "r"(0x8000000f));
}

static int __init init_zswap(void)
{
	struct zswap_pool *pool;

	zswap_init_started = true;

	if (zswap_entry_cache_create()) {
		pr_err("entry cache creation failed\n");
		goto cache_fail;
	}

	if (zswap_cpu_dstmem_init()) {
		pr_err("dstmem alloc failed\n");
		goto dstmem_fail;
	}

	pool = __zswap_pool_create_fallback();
	if (!pool) {
		pr_err("pool creation failed\n");
		goto pool_fail;
	}
	on_each_cpu(enable_cpu_counters, NULL, 1);

#if defined(CONFIG_SOC_EXYNOS5422) || defined(CONFIG_SOC_EXYNOS5430)
	show_exynos_pmu();
#endif
	pr_info("loaded using pool %s/%s\n", pool->tfm_name,
		zpool_get_type(pool->zpool));

	list_add(&pool->list, &zswap_pools);

	frontswap_register_ops(&zswap_frontswap_ops);
	if (zswap_debugfs_init())
		pr_warn("debugfs initialization failed\n");
	return 0;

pool_fail:
	zswap_cpu_dstmem_destroy();
dstmem_fail:
	zswap_entry_cache_destroy();
cache_fail:
	return -ENOMEM;
}
/* must be late so crypto has time to come up */
late_initcall(init_zswap);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Seth Jennings <sjennings@variantweb.net>");
MODULE_DESCRIPTION("Compressed cache for swap pages");
