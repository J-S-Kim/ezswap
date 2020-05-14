#ifndef _LINUX_FRONTSWAP_H
#define _LINUX_FRONTSWAP_H

#include <linux/swap.h>
#include <linux/mm.h>
#include <linux/bitops.h>

struct frontswap_ops {
	void (*init)(unsigned);
	int (*store)(unsigned, pgoff_t, struct page *, bool);
	int (*load)(unsigned, pgoff_t, struct page *);
	void (*invalidate_page)(unsigned, pgoff_t);
	void (*invalidate_file_page)(pgoff_t, unsigned long);
	void (*invalidate_area)(unsigned);
    struct frontswap_ops *next;
};

extern bool frontswap_enabled;
extern struct frontswap_ops *
	frontswap_register_ops(struct frontswap_ops *ops);
extern void frontswap_shrink(unsigned long);
extern unsigned long frontswap_curr_pages(void);
extern void frontswap_writethrough(bool);
#define FRONTSWAP_HAS_EXCLUSIVE_GETS
extern void frontswap_tmem_exclusive_gets(bool);

extern bool __frontswap_test(struct swap_info_struct *, pgoff_t);
extern void __frontswap_init(unsigned type, unsigned long *map);
extern int __frontswap_store(struct page *page, bool kswapd);
extern int __frontswap_load(struct page *page);
extern void __frontswap_invalidate_page(unsigned, pgoff_t);
extern void __frontswap_invalidate_file_page(struct page *);
extern void __frontswap_invalidate_area(unsigned);

extern int __frontswap_file_store(struct page *page, bool kswapd);
extern int __frontswap_file_load(struct page *page);

#ifdef CONFIG_FRONTSWAP
#define frontswap_enabled (1)

static inline bool frontswap_test(struct swap_info_struct *sis, pgoff_t offset)
{
	return __frontswap_test(sis, offset);
}

static inline void frontswap_map_set(struct swap_info_struct *p,
				     unsigned long *map)
{
	p->frontswap_map = map;
}

static inline unsigned long *frontswap_map_get(struct swap_info_struct *p)
{
	return p->frontswap_map;
}
#else
/* all inline routines become no-ops and all externs are ignored */

#define frontswap_enabled (0)

static inline bool frontswap_test(struct swap_info_struct *sis, pgoff_t offset)
{
	return false;
}

static inline void frontswap_map_set(struct swap_info_struct *p,
				     unsigned long *map)
{
}

static inline unsigned long *frontswap_map_get(struct swap_info_struct *p)
{
	return NULL;
}
#endif

static inline int frontswap_store(struct page *page, bool kswapd)
{
	int ret = -1;

	if (frontswap_enabled){
        if(!PageSwapCache(page)){
            ret = __frontswap_file_store(page, kswapd);
        } else
            ret = __frontswap_store(page, kswapd);
    }

	return ret;
}
static inline int frontswap_file_store(struct page *page)
{
    int ret = -1;
    return ret;
}

static inline int frontswap_load(struct page *page)
{
	int ret = -1;

	if (frontswap_enabled){
        if(!PageSwapCache(page))
            ret = __frontswap_file_load(page);
        else
            ret = __frontswap_load(page);
    }
	return ret;
}

static inline void frontswap_invalidate_page(unsigned type, pgoff_t offset)
{
	if (frontswap_enabled){
        __frontswap_invalidate_page(type, offset);
    }
}

static inline void frontswap_invalidate_file_page(struct page* page)
{
	if (frontswap_enabled){
        __frontswap_invalidate_file_page(page);
    }
}

static inline void frontswap_invalidate_area(unsigned type)
{
	if (frontswap_enabled)
		__frontswap_invalidate_area(type);
}

static inline void frontswap_init(unsigned type, unsigned long *map)
{
	if (frontswap_enabled)
		__frontswap_init(type, map);
}

#endif /* _LINUX_FRONTSWAP_H */
