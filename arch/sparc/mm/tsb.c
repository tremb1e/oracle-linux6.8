/* arch/sparc64/mm/tsb.c
 *
 * Copyright (C) 2006, 2008 David S. Miller <davem@davemloft.net>
 */

#include <linux/kernel.h>
#include <linux/preempt.h>
#include <linux/slab.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/mmu_context.h>
#include <asm/setup.h>
#include <asm/tsb.h>
#include <asm/tlb.h>
#include <asm/oplib.h>

extern struct tsb swapper_tsb[KERNEL_TSB_NENTRIES];

static inline unsigned long tsb_hash(unsigned long vaddr, unsigned long hash_shift, unsigned long nentries)
{
	vaddr >>= hash_shift;
	return vaddr & (nentries - 1);
}

static inline int tag_compare(unsigned long tag, unsigned long vaddr)
{
	return (tag == (vaddr >> 22));
}

/* TSB flushes need only occur on the processor initiating the address
 * space modification, not on each cpu the address space has run on.
 * Only the TLB flush needs that treatment.
 */

void flush_tsb_kernel_range(unsigned long start, unsigned long end)
{
	unsigned long v;

	for (v = start; v < end; v += PAGE_SIZE) {
		unsigned long hash = tsb_hash(v, PAGE_SHIFT,
					      KERNEL_TSB_NENTRIES);
		struct tsb *ent = &swapper_tsb[hash];

		if (tag_compare(ent->tag, v))
			ent->tag = (1UL << TSB_TAG_INVALID_BIT);
	}
}

static void __flush_tsb_one_entry(unsigned long tsb, unsigned long v,
				  unsigned long hash_shift,
				  unsigned long nentries)
{
	unsigned long tag, ent, hash;

	v &= ~0x1UL;
	hash = tsb_hash(v, hash_shift, nentries);
	ent = tsb + (hash * sizeof(struct tsb));
	tag = (v >> 22UL);

	tsb_flush(ent, tag);
}

static void __flush_tsb_one(struct tlb_batch *tb, unsigned long hash_shift,
			    unsigned long tsb, unsigned long nentries)
{
	unsigned long i;

	for (i = 0; i < tb->tlb_nr; i++)
		__flush_tsb_one_entry(tsb, tb->vaddrs[i], hash_shift, nentries);
}

void flush_tsb_user(struct tlb_batch *tb)
{
	struct mm_struct *mm = tb->mm;
	unsigned long nentries, base, flags;

	spin_lock_irqsave(&mm->context.lock, flags);

	base = (unsigned long) mm->context.tsb_block[MM_TSB_BASE].tsb;
	nentries = mm->context.tsb_block[MM_TSB_BASE].tsb_nentries;
	if (tlb_type == cheetah_plus || tlb_type == hypervisor)
		base = __pa(base);
	__flush_tsb_one(tb, PAGE_SHIFT, base, nentries);

#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
	if (mm->context.tsb_block[MM_TSB_HUGE].tsb) {
		base = (unsigned long) mm->context.tsb_block[MM_TSB_HUGE].tsb;
		nentries = mm->context.tsb_block[MM_TSB_HUGE].tsb_nentries;
		if (tlb_type == cheetah_plus || tlb_type == hypervisor)
			base = __pa(base);
		__flush_tsb_one(tb, REAL_HPAGE_SHIFT, base, nentries);
	}
#endif
#ifdef	CONFIG_HUGETLB_PAGE
	if (mm->context.tsb_block[MM_TSB_XLHUGE].tsb) {
		base = (unsigned long) mm->context.tsb_block[MM_TSB_XLHUGE].tsb;
		nentries = mm->context.tsb_block[MM_TSB_XLHUGE].tsb_nentries;
		base = __pa(base);
		__flush_tsb_one(tb, xl_hugepage_shift, base, nentries);
	}
#endif	/* CONFIG_HUGETLB_PAGE */
	spin_unlock_irqrestore(&mm->context.lock, flags);
}

void flush_tsb_user_page(struct mm_struct *mm, unsigned long vaddr)
{
	unsigned long nentries, base, flags;

	spin_lock_irqsave(&mm->context.lock, flags);

	base = (unsigned long) mm->context.tsb_block[MM_TSB_BASE].tsb;
	nentries = mm->context.tsb_block[MM_TSB_BASE].tsb_nentries;
	if (tlb_type == cheetah_plus || tlb_type == hypervisor)
		base = __pa(base);
	__flush_tsb_one_entry(base, vaddr, PAGE_SHIFT, nentries);

#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
	if (mm->context.tsb_block[MM_TSB_HUGE].tsb) {
		base = (unsigned long) mm->context.tsb_block[MM_TSB_HUGE].tsb;
		nentries = mm->context.tsb_block[MM_TSB_HUGE].tsb_nentries;
		if (tlb_type == cheetah_plus || tlb_type == hypervisor)
			base = __pa(base);
		__flush_tsb_one_entry(base, vaddr, REAL_HPAGE_SHIFT, nentries);
	}
#endif
#ifdef	CONFIG_HUGETLB_PAGE
	if (mm->context.tsb_block[MM_TSB_XLHUGE].tsb) {
		base = (unsigned long) mm->context.tsb_block[MM_TSB_XLHUGE].tsb;
		nentries = mm->context.tsb_block[MM_TSB_XLHUGE].tsb_nentries;
		base = __pa(base);
		__flush_tsb_one_entry(base, vaddr, xl_hugepage_shift, nentries);
	}
#endif	/* CONFIG_HUGETLB_PAGE */
	spin_unlock_irqrestore(&mm->context.lock, flags);
}

#define HV_PGSZ_IDX_BASE	HV_PGSZ_IDX_8K
#define HV_PGSZ_MASK_BASE	HV_PGSZ_MASK_8K

#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
#define HV_PGSZ_IDX_HUGE	HV_PGSZ_IDX_4MB
#define HV_PGSZ_MASK_HUGE	HV_PGSZ_MASK_4MB
static unsigned short hv_pgsz_idx_xlhuge;
static unsigned int hv_pgsz_mask_xlhuge;

void __init hv_establish_xl_hugepage_tsb_descriptor(unsigned short pgsz_idx,
						    unsigned int pgsz_mask)
{
	hv_pgsz_idx_xlhuge = pgsz_idx;
	hv_pgsz_mask_xlhuge = pgsz_mask;
}
#endif

static void sun4v_fill_tsb_descriptor(struct mm_struct *mm)
{
	struct hv_tsb_descr *htd = &mm->context.tsb_descr[0];
	unsigned int tsb_idx;

	for (tsb_idx = 0U; tsb_idx < MM_NUM_TSBS; tsb_idx++) {
		/* Should there not be a tsb then skip it.*/
		if (!mm->context.tsb_block[tsb_idx].tsb)
			continue;

		switch (tsb_idx) {
		case MM_TSB_BASE:
			htd->pgsz_mask = HV_PGSZ_MASK_BASE;
			htd->pgsz_idx = HV_PGSZ_IDX_BASE;
			break;
#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
		case MM_TSB_HUGE:
			htd->pgsz_mask = HV_PGSZ_MASK_HUGE;
			htd->pgsz_idx = HV_PGSZ_IDX_HUGE;
			break;
		case MM_TSB_XLHUGE:
			htd->pgsz_mask = hv_pgsz_mask_xlhuge;
			htd->pgsz_idx = hv_pgsz_idx_xlhuge;
			break;
#endif
		default:
			BUG();
		}
		htd->assoc = 1;
		htd->num_ttes = mm->context.tsb_block[tsb_idx].tsb_nentries;
		htd->ctx_idx = 0;
		htd->tsb_base = __pa(mm->context.tsb_block[tsb_idx].tsb);
		htd->resv = 0;
		htd++;
	}
}

static void setup_tsb_params(struct mm_struct *mm, unsigned long tsb_idx,
			     unsigned long tsb_bytes)
{
	unsigned long tsb_reg, base, tsb_paddr;
	unsigned long page_sz, tte;

	mm->context.tsb_block[tsb_idx].tsb_nentries =
		tsb_bytes / sizeof(struct tsb);

	switch (tsb_idx) {
	case MM_TSB_BASE:
		base = TSBMAP_8K_BASE;
		break;
#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
	case MM_TSB_HUGE:
	case MM_TSB_XLHUGE:
		base = TSBMAP_4M_BASE;
		break;
#endif
	default:
		BUG();
	}

	tte = pgprot_val(PAGE_KERNEL_LOCKED);
	tsb_paddr = __pa(mm->context.tsb_block[tsb_idx].tsb);
	BUG_ON(tsb_paddr & (tsb_bytes - 1UL));

	/* Use the smallest page size that can map the whole TSB
	 * in one TLB entry.
	 */
	switch (tsb_bytes) {
	case 8192 << 0:
		tsb_reg = 0x0UL;
#ifdef DCACHE_ALIASING_POSSIBLE
		base += (tsb_paddr & 8192);
#endif
		page_sz = 8192;
		break;

	case 8192 << 1:
		tsb_reg = 0x1UL;
		page_sz = 64 * 1024;
		break;

	case 8192 << 2:
		tsb_reg = 0x2UL;
		page_sz = 64 * 1024;
		break;

	case 8192 << 3:
		tsb_reg = 0x3UL;
		page_sz = 64 * 1024;
		break;

	case 8192 << 4:
		tsb_reg = 0x4UL;
		page_sz = 512 * 1024;
		break;

	case 8192 << 5:
		tsb_reg = 0x5UL;
		page_sz = 512 * 1024;
		break;

	case 8192 << 6:
		tsb_reg = 0x6UL;
		page_sz = 512 * 1024;
		break;

	case 8192 << 7:
		tsb_reg = 0x7UL;
		page_sz = 4 * 1024 * 1024;
		break;

	default:
		printk(KERN_ERR "TSB[%s:%d]: Impossible TSB size %lu, killing process.\n",
		       current->comm, current->pid, tsb_bytes);
		do_exit(SIGSEGV);
	}
	tte |= pte_sz_bits(page_sz);

	if (tlb_type == cheetah_plus || tlb_type == hypervisor) {
		/* Physical mapping, no locked TLB entry for TSB.  */
		tsb_reg |= tsb_paddr;

		mm->context.tsb_block[tsb_idx].tsb_reg_val = tsb_reg;
		mm->context.tsb_block[tsb_idx].tsb_map_vaddr = 0;
		mm->context.tsb_block[tsb_idx].tsb_map_pte = 0;
	} else {
		tsb_reg |= base;
		tsb_reg |= (tsb_paddr & (page_sz - 1UL));
		tte |= (tsb_paddr & ~(page_sz - 1UL));

		mm->context.tsb_block[tsb_idx].tsb_reg_val = tsb_reg;
		mm->context.tsb_block[tsb_idx].tsb_map_vaddr = base;
		mm->context.tsb_block[tsb_idx].tsb_map_pte = tte;
	}

	if (tlb_type == hypervisor)
		sun4v_fill_tsb_descriptor(mm);
}

struct kmem_cache *pgtable_cache __read_mostly;

static struct kmem_cache *tsb_caches[8] __read_mostly;

static const char *tsb_cache_names[8] = {
	"tsb_8KB",
	"tsb_16KB",
	"tsb_32KB",
	"tsb_64KB",
	"tsb_128KB",
	"tsb_256KB",
	"tsb_512KB",
	"tsb_1MB",
};

void __init pgtable_cache_init(void)
{
	unsigned long i;

	pgtable_cache = kmem_cache_create("pgtable_cache",
					  PAGE_SIZE, PAGE_SIZE,
					  0,
					  _clear_page);
	if (!pgtable_cache) {
		prom_printf("pgtable_cache_init(): Could not create!\n");
		prom_halt();
	}

	for (i = 0; i < ARRAY_SIZE(tsb_cache_names); i++) {
		unsigned long size = 8192 << i;
		const char *name = tsb_cache_names[i];

		tsb_caches[i] = kmem_cache_create(name,
						  size, size,
						  0, NULL);
		if (!tsb_caches[i]) {
			prom_printf("Could not create %s cache\n", name);
			prom_halt();
		}
	}
}

int sysctl_tsb_ratio = -2;

static unsigned long tsb_size_to_rss_limit(unsigned long new_size)
{
	unsigned long num_ents = (new_size / sizeof(struct tsb));

	if (sysctl_tsb_ratio < 0)
		return num_ents - (num_ents >> -sysctl_tsb_ratio);
	else
		return num_ents + (num_ents >> sysctl_tsb_ratio);
}

/* When the RSS of an address space exceeds tsb_rss_limit for a TSB,
 * do_sparc64_fault() invokes this routine to try and grow it.
 *
 * When we reach the maximum TSB size supported, we stick ~0UL into
 * tsb_rss_limit for that TSB so the grow checks in do_sparc64_fault()
 * will not trigger any longer.
 *
 * The TSB can be anywhere from 8K to 1MB in size, in increasing powers
 * of two.  The TSB must be aligned to it's size, so f.e. a 512K TSB
 * must be 512K aligned.  It also must be physically contiguous, so we
 * cannot use vmalloc().
 *
 * The idea here is to grow the TSB when the RSS of the process approaches
 * the number of entries that the current TSB can hold at once.  Currently,
 * we trigger when the RSS hits 3/4 of the TSB capacity.
 */
void tsb_grow(struct mm_struct *mm, unsigned long tsb_index, unsigned long rss)
{
	unsigned long max_tsb_size = 1 * 1024 * 1024;
	unsigned long new_size, old_size, flags;
	struct tsb *old_tsb, *new_tsb;
	unsigned long new_cache_index, old_cache_index;
	unsigned long new_rss_limit;
	gfp_t gfp_flags;

	if (max_tsb_size > (PAGE_SIZE << MAX_ORDER))
		max_tsb_size = (PAGE_SIZE << MAX_ORDER);

	new_cache_index = 0;
	for (new_size = 8192; new_size < max_tsb_size; new_size <<= 1UL) {
		new_rss_limit = tsb_size_to_rss_limit(new_size);
		if (new_rss_limit > rss)
			break;
		new_cache_index++;
	}

	if (new_size == max_tsb_size)
		new_rss_limit = ~0UL;

retry_tsb_alloc:
	gfp_flags = GFP_KERNEL;
	if (new_size > (PAGE_SIZE * 2))
		gfp_flags |= __GFP_NOWARN | __GFP_NORETRY;

	new_tsb = kmem_cache_alloc_node(tsb_caches[new_cache_index],
					gfp_flags, numa_node_id());
	if (unlikely(!new_tsb)) {
		/* Not being able to fork due to a high-order TSB
		 * allocation failure is very bad behavior.  Just back
		 * down to a 0-order allocation and force no TSB
		 * growing for this address space.
		 */
		if (mm->context.tsb_block[tsb_index].tsb == NULL &&
		    new_cache_index > 0) {
			new_cache_index = 0;
			new_size = 8192;
			new_rss_limit = ~0UL;
			goto retry_tsb_alloc;
		}

		/* If we failed on a TSB grow, we are under serious
		 * memory pressure so don't try to grow any more.
		 */
		if (mm->context.tsb_block[tsb_index].tsb != NULL)
			mm->context.tsb_block[tsb_index].tsb_rss_limit = ~0UL;
		return;
	}

	/* Mark all tags as invalid.  */
	tsb_init(new_tsb, new_size);

	/* Ok, we are about to commit the changes.  If we are
	 * growing an existing TSB the locking is very tricky,
	 * so WATCH OUT!
	 *
	 * We have to hold mm->context.lock while committing to the
	 * new TSB, this synchronizes us with processors in
	 * flush_tsb_user() and switch_mm() for this address space.
	 *
	 * But even with that lock held, processors run asynchronously
	 * accessing the old TSB via TLB miss handling.  This is OK
	 * because those actions are just propagating state from the
	 * Linux page tables into the TSB, page table mappings are not
	 * being changed.  If a real fault occurs, the processor will
	 * synchronize with us when it hits flush_tsb_user(), this is
	 * also true for the case where vmscan is modifying the page
	 * tables.  The only thing we need to be careful with is to
	 * skip any locked TSB entries during copy_tsb().
	 *
	 * When we finish committing to the new TSB, we have to drop
	 * the lock and ask all other cpus running this address space
	 * to run tsb_context_switch() to see the new TSB table.
	 */
	spin_lock_irqsave(&mm->context.lock, flags);

	old_tsb = mm->context.tsb_block[tsb_index].tsb;
	old_cache_index =
		(mm->context.tsb_block[tsb_index].tsb_reg_val & 0x7UL);
	old_size = (mm->context.tsb_block[tsb_index].tsb_nentries *
		    sizeof(struct tsb));


	/* Handle multiple threads trying to grow the TSB at the same time.
	 * One will get in here first, and bump the size and the RSS limit.
	 * The others will get in here next and hit this check.
	 */
	if (unlikely(old_tsb &&
		     (rss < mm->context.tsb_block[tsb_index].tsb_rss_limit))) {
		spin_unlock_irqrestore(&mm->context.lock, flags);

		kmem_cache_free(tsb_caches[new_cache_index], new_tsb);
		return;
	}

	mm->context.tsb_block[tsb_index].tsb_rss_limit = new_rss_limit;

	if (old_tsb) {
		extern void copy_tsb(unsigned long old_tsb_base,
				     unsigned long old_tsb_size,
				     unsigned long new_tsb_base,
				     unsigned long new_tsb_size);
		unsigned long old_tsb_base = (unsigned long) old_tsb;
		unsigned long new_tsb_base = (unsigned long) new_tsb;

		if (tlb_type == cheetah_plus || tlb_type == hypervisor) {
			old_tsb_base = __pa(old_tsb_base);
			new_tsb_base = __pa(new_tsb_base);
		}
		copy_tsb(old_tsb_base, old_size, new_tsb_base, new_size);
	}

	mm->context.tsb_block[tsb_index].tsb = new_tsb;
	setup_tsb_params(mm, tsb_index, new_size);

	spin_unlock_irqrestore(&mm->context.lock, flags);

	/* If old_tsb is NULL, we're being invoked for the first time
	 * from init_new_context().
	 */
	if (old_tsb) {
		/* Reload it on the local cpu.  */
		tsb_context_switch(mm);

		/* Now force other processors to do the same.  */
		preempt_disable();
		smp_tsb_sync(mm);
		preempt_enable();

		/* Now it is safe to free the old tsb.  */
		kmem_cache_free(tsb_caches[old_cache_index], old_tsb);
	}
}

#if defined(CONFIG_HUGETLB_PAGE) || defined(CONFIG_TRANSPARENT_HUGEPAGE)
static void capture_and_clear_huge_pte_counts(mm_context_t *mm_context,
					      unsigned long *capture_array)
{
	unsigned int hugepage_idx;

	for (hugepage_idx = 0UL; hugepage_idx != MM_NUM_HUGEPAGE_SIZES;
		hugepage_idx++) {
		capture_array[hugepage_idx] =
			mm_context->huge_pte_count[hugepage_idx];
		mm_context->huge_pte_count[hugepage_idx] = 0UL;
	}
}

static void
captured_hugepage_pte_count_grow_tsb(struct mm_struct *mm,
				     unsigned long *capture_huge_pte_count)
{
	if (unlikely(capture_huge_pte_count[MM_PTES_HUGE]))
		tsb_grow(mm, MM_TSB_HUGE,
			capture_huge_pte_count[MM_PTES_HUGE]);

	if (unlikely(capture_huge_pte_count[MM_PTES_XLHUGE]))
		tsb_grow(mm, MM_TSB_XLHUGE,
			capture_huge_pte_count[MM_PTES_XLHUGE]);
}
#else
static void capture_and_clear_huge_pte_counts(mm_context_t *mm_context,
					      unsigned long *capture_array) {}
static void
captured_hugepage_pte_count_grow_tsb(struct mm_struct *mm,
				     unsigned long *capture_huge_pte_count) {}
#endif /* CONFIG_HUGETLB_PAGE || CONFIG_TRANSPARENT_HUGEPAGE */

int init_new_context(struct task_struct *tsk, struct mm_struct *mm)
{
	unsigned long capture_huge_pte_count[MM_NUM_HUGEPAGE_SIZES];
	unsigned int i;

	spin_lock_init(&mm->context.lock);

	mm->context.sparc64_ctx_val = 0UL;

	/* We reset it to zero because the fork() page copying
	 * will re-increment the counters as the parent PTEs are
	 * copied into the child address space.
	 */
	capture_and_clear_huge_pte_counts(&mm->context, capture_huge_pte_count);

	/* copy_mm() copies over the parent's mm_struct before calling
	 * us, so we need to zero out the TSB pointer or else tsb_grow()
	 * will be confused and think there is an older TSB to free up.
	 */
	for (i = 0; i < MM_NUM_TSBS; i++)
		mm->context.tsb_block[i].tsb = NULL;

	/* If this is fork, inherit the parent's TSB size.  We would
	 * grow it to that size on the first page fault anyways.
	 */
	tsb_grow(mm, MM_TSB_BASE, get_mm_rss(mm));

	captured_hugepage_pte_count_grow_tsb(mm, capture_huge_pte_count);

	if (unlikely(!mm->context.tsb_block[MM_TSB_BASE].tsb))
		return -ENOMEM;

	return 0;
}

static void tsb_destroy_one(struct tsb_config *tp)
{
	unsigned long cache_index;

	if (!tp->tsb)
		return;
	cache_index = tp->tsb_reg_val & 0x7UL;
	kmem_cache_free(tsb_caches[cache_index], tp->tsb);
	tp->tsb = NULL;
	tp->tsb_reg_val = 0UL;
}

void destroy_context(struct mm_struct *mm)
{
	unsigned long flags, i;

	for (i = 0; i < MM_NUM_TSBS; i++)
		tsb_destroy_one(&mm->context.tsb_block[i]);

	spin_lock_irqsave(&ctx_alloc_lock, flags);

	if (CTX_VALID(mm->context)) {
		unsigned long nr = CTX_NRBITS(mm->context);
		mmu_context_bmap[nr>>6] &= ~(1UL << (nr & 63));
	}

	spin_unlock_irqrestore(&ctx_alloc_lock, flags);
}
