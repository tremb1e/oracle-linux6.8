/*
 * FILE:	cyclic.c
 * DESCRIPTION:	Minimal cyclic implementation
 *
 * Copyright (C) 2010, 2011, 2012, 2013 Oracle Corporation
 */

#include <linux/cpu.h>
#include <linux/cyclic.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>

static DEFINE_SPINLOCK(cyclic_lock);
static int		omni_enabled = 0;

#define _CYCLIC_CPU_UNDEF		(-1)
#define _CYCLIC_CPU_OMNI		(-2)
#define CYCLIC_IS_OMNI(cyc)		((cyc)->cpu == _CYCLIC_CPU_OMNI)

typedef struct cyclic {
	struct list_head		list;
	int				cpu;
	union {
		struct {
			cyc_time_t		when;
			cyc_handler_t		hdlr;
			uint32_t		pend;
			struct hrtimer		timr;
			struct tasklet_struct	task;
		} cyc;
		struct {
			cyc_omni_handler_t	hdlr;
			struct list_head	cycl;
		} omni;
	};
} cyclic_t;

static LIST_HEAD(cyclics);

static void cyclic_fire(uintptr_t arg)
{
	cyclic_t	*cyc = (cyclic_t *)arg;
	uint32_t	cpnd, npnd;

	do {
		/*
		 * We know that the 'pend' counter for the cyclic is non-zero.
		 * So, we can start with calling the handler at least once.
		 */
		(*cyc->cyc.hdlr.cyh_func)(cyc->cyc.hdlr.cyh_arg);

again:
		/*
		 * The 'pend' counter may be modified by cyclic_expire() while
		 * we go through this loop.  We use an atomic compare-and-set
		 * instruction to determine whether it got changed.  If so, we
		 * retrieve the updated 'pend' value and try this again.
		 *
		 * Note that when the cyclic is being removed, the hrtimer will
		 * be cancelled first, which ensures that 'pend' will no longer
		 * be incremented.  When that happens, this loop will simply
		 * run through the remaining pending calls, and terminate.
		 */
		cpnd = cyc->cyc.pend;
		npnd = cpnd - 1;
		if (cmpxchg(&cyc->cyc.pend, cpnd, npnd) != cpnd)
			goto again;
	} while (npnd > 0);
}

/*
 * Timer expiration handler for cyclic hrtimers.  Cyclic worker functions must
 * be able to perform a variety of tasks (including calling functions that
 * could sleep), and therefore they cannot be called from interrupt context.
 *
 * We schedule a tasklet to do the actual work.
 *
 * But... under heavy load it is possible that the hrtimer will expire again
 * before the tasklet had a chance to run.  That would lead to missed events
 * which isn't quite acceptable.  Therefore, we use a counter to record how
 * many times the timer has expired vs how many times the handler has been
 * called.  The counter is incremented by this function upon hrtimer expiration
 * and decremented by the tasklet.  Note that the tasklet is responsible for
 * calling the handler multiple times if the counter indicates that multiple
 * invocation are pending.
 *
 * This function is called as hrtimer handler, and therefore runs in interrupt
 * context, which by definition will ensure that manipulation of the 'pend'
 * counter in the cyclic can be done without locking, and changes will appear
 * atomic to the tasklet.
 *
 * Moral of the story: the handler may not get called at the absolute times as
 * requested, but it will be called the correct number of times.
 */
static enum hrtimer_restart cyclic_expire(struct hrtimer *timr)
{
	cyclic_t		*cyc = container_of(timr, cyclic_t, cyc.timr);

	/*
	 * High priority cyclics call directly into their handler.  This means
	 * that the handler must satisfy all requirements for executing code in
	 * interrupt context.
	 */
	if (cyc->cyc.hdlr.cyh_level == CY_HIGH_LEVEL) {
		(*cyc->cyc.hdlr.cyh_func)(cyc->cyc.hdlr.cyh_arg);
		goto done;
	}

	/*
	 * Increment the 'pend' counter, in case the tasklet is already set to
	 * run.  If the counter was 0 upon entry, we need to schedule the
	 * tasklet.  If the increment wraps the counter back to 0, we admit
	 * defeat, and reset it to its max value.
	 */
	if (cyc->cyc.pend++ == 0)
		tasklet_hi_schedule(&cyc->cyc.task);
	else if (cyc->cyc.pend == 0)
		cyc->cyc.pend = UINT_MAX;

done:
	/*
	 * Prepare the timer for the next expiration.
	 */
	hrtimer_forward_now(timr, cyc->cyc.when.cyt_interval);

	return HRTIMER_RESTART;
}

cyclic_t *cyclic_new(int omni)
{
	cyclic_t	*cyc;

	cyc = kmalloc(sizeof(cyclic_t), GFP_KERNEL);
	if (cyc == NULL)
		return NULL;

	INIT_LIST_HEAD(&cyc->list);

	if (!omni) {
		cyc->cpu = _CYCLIC_CPU_UNDEF;
		cyc->cyc.pend = 0;
		hrtimer_init(&cyc->cyc.timr, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
		cyc->cyc.timr.function = cyclic_expire;
		tasklet_init(&cyc->cyc.task, cyclic_fire, (uintptr_t)cyc);
	} else {
		cyc->cpu = _CYCLIC_CPU_OMNI;
		INIT_LIST_HEAD(&cyc->omni.cycl);
	}

	return cyc;
}

/*
 * Add a new cyclic to the system.
 */
cyclic_id_t cyclic_add(cyc_handler_t *hdlr, cyc_time_t *when)
{
	cyclic_t	*cyc;

	if (hdlr == NULL || when == NULL)
		return CYCLIC_NONE;

	cyc = cyclic_new(0);
	if (cyc == NULL)
		return CYCLIC_NONE;

	list_add(&cyc->list, &cyclics);
	cyc->cpu = smp_processor_id();
	cyc->cyc.when = *when;
	cyc->cyc.hdlr = *hdlr;

	if (cyc->cyc.when.cyt_when.tv64 == 0)
		hrtimer_start(&cyc->cyc.timr, cyc->cyc.when.cyt_interval,
			      HRTIMER_MODE_REL_PINNED);
	else
		hrtimer_start(&cyc->cyc.timr, cyc->cyc.when.cyt_when,
			      HRTIMER_MODE_ABS_PINNED);

	return (cyclic_id_t)cyc;
}
EXPORT_SYMBOL(cyclic_add);

static void cyclic_omni_xcall(cyclic_t *cyc)
{
	if (cyc->cyc.when.cyt_when.tv64 == 0)
		hrtimer_start(&cyc->cyc.timr, cyc->cyc.when.cyt_interval,
			      HRTIMER_MODE_REL_PINNED);
	else
		hrtimer_start(&cyc->cyc.timr, cyc->cyc.when.cyt_when,
			      HRTIMER_MODE_ABS_PINNED);
}

/*
 * Add a new cyclic to the system.
 */
static void cyclic_add_pinned(int cpu, cyclic_t *omni,
			      cyc_handler_t *hdlr, cyc_time_t *when)
{
	cyclic_t	*cyc;

	cyc = cyclic_new(0);
	if (cyc == NULL)
		return;

	list_add(&cyc->list, &omni->omni.cycl);
	cyc->cpu = cpu;
	cyc->cyc.when = *when;
	cyc->cyc.hdlr = *hdlr;

	smp_call_function_single(cpu, (smp_call_func_t)cyclic_omni_xcall,
				 cyc, 1);
}

/*
 * Start a cyclic on a specific CPU as sub-cyclic to an omni-present cyclic.
 */
static void cyclic_omni_start(cyclic_t *omni, int cpu)
{
	cyc_time_t	when;
	cyc_handler_t	hdlr;

	omni->omni.hdlr.cyo_online(omni->omni.hdlr.cyo_arg, cpu, &hdlr, &when);
	cyclic_add_pinned(cpu, omni, &hdlr, &when);
}

#ifdef CONFIG_HOTPLUG_CPU
static void cyclic_cpu_offline(int cpu)
{
	cyclic_t	*cyc;

	list_for_each_entry(cyc, &cyclics, list) {
		cyclic_t	*c, *n;

		if (!CYCLIC_IS_OMNI(cyc))
			continue;

		list_for_each_entry_safe(c, n, &cyc->omni.cycl, list) {
			if (c->cpu == cpu)
				cyclic_remove((cyclic_id_t)c);
		}
	}
}

static void cyclic_cpu_online(int cpu)
{
	cyclic_t	*cyc;

	list_for_each_entry(cyc, &cyclics, list) {
		cyclic_t	*c, *n;

		if (!CYCLIC_IS_OMNI(cyc))
			continue;

		list_for_each_entry_safe(c, n, &cyc->omni.cycl, list) {
			if (c->cpu == cpu)
				break;
		}

		if (c->cpu == cpu)
			continue;

		cyclic_omni_start(cyc, cpu);
	}
}

static int cyclic_cpu_notifier(struct notifier_block *nb, unsigned long val,
			       void *args)
{
	unsigned int	cpu = (unsigned int)(long)args;

	switch (val & 0x000f) {
	case CPU_ONLINE:
		cyclic_cpu_online(cpu);
		break;
	case CPU_DYING:
		cyclic_cpu_offline(cpu);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block	cpu_notifier = {
	.notifier_call = cyclic_cpu_notifier,
};
#endif

/*
 * Add a new omnipresent cyclic to the system.
 */
cyclic_id_t cyclic_add_omni(cyc_omni_handler_t *omni)
{
	int		cpu;
	cyclic_t	*cyc;
	unsigned long	flags;

	cyc = cyclic_new(1);
	if (cyc == NULL)
		return CYCLIC_NONE;

	list_add(&cyc->list, &cyclics);
	cyc->omni.hdlr = *omni;

	for_each_online_cpu(cpu)
		cyclic_omni_start(cyc, cpu);

#ifdef CONFIG_HOTPLUG_CPU
	spin_lock_irqsave(&cyclic_lock, flags);
	if (!omni_enabled) {
		register_cpu_notifier(&cpu_notifier);
		omni_enabled = 1;
	}
	spin_unlock_irqrestore(&cyclic_lock, flags);
#endif

	return (cyclic_id_t)cyc;
}
EXPORT_SYMBOL(cyclic_add_omni);

/*
 * Remove a specific cyclic from the system.
 */
void cyclic_remove(cyclic_id_t id)
{
	cyclic_t	*cyc = (cyclic_t *)id;

	if (CYCLIC_IS_OMNI(cyc)) {
		cyclic_t	*child, *n;

		/*
		 * If this is an omni-present cyclic, we first need to remove
		 * all the associated per-CPU cyclics.  Note that the recursive
		 * call into cyclic_remove() for a child cyclic will remove it
		 * from the list of per-CPU cyclics associated with the
		 * omni-present cyclic, so we do not need to handle that here.
		 */
		list_for_each_entry_safe(child, n, &cyc->omni.cycl, list)
			cyclic_remove((cyclic_id_t)child);
	} else {
		/*
		 * We know that hrtimer_cancel() will wait for the timer
		 * callback to finish if it is being executed at the time of
		 * making this call.  It is therefore guaranteed that 'pend'
		 * will no longer get incremented.
		 *
		 * The call to tasklet_kill() will wait for the tasklet handler
		 * to finish also, and since the handler always brings 'pend'
		 * down to zero prior to returning, it is guaranteed that
		 * (1) all pending handler calls will be made before
		 *     cyclic_remove() returns
		 * (2) the amount of work to do before returning is finite.
		 */
		hrtimer_cancel(&cyc->cyc.timr);
		tasklet_kill(&cyc->cyc.task);
	}

	list_del(&cyc->list);
	kfree(cyc);
}
EXPORT_SYMBOL(cyclic_remove);

static void *s_start(struct seq_file *seq, loff_t *pos)
{
	loff_t		n = *pos;
	cyclic_t	*cyc;

	list_for_each_entry(cyc, &cyclics, list) {
		if (n == 0)
			return cyc;

		n--;
	}

	return NULL;
}

static void *s_next(struct seq_file *seq, void *p, loff_t *pos)
{
	cyclic_t	*cyc = p;

	++*pos;

	cyc = list_entry(cyc->list.next, cyclic_t, list);
	if (&cyc->list == &cyclics)
		return NULL;

	return cyc;
}

static void s_stop(struct seq_file *seq, void *p)
{
}

static int s_show(struct seq_file *seq, void *p)
{
	cyclic_t	*cyc = p;

	if (CYCLIC_IS_OMNI(cyc)) {
		cyclic_t	*c;

		seq_printf(seq, "Omni-present cyclic:\n");
		list_for_each_entry(c, &cyc->omni.cycl, list)
			seq_printf(seq,
				   "  CPU-%d: %c %lluns hdlr %pB arg %llx\n",
				   c->cpu,
				   c->cyc.hdlr.cyh_level == CY_HIGH_LEVEL
					? 'H' : 'l',
				   c->cyc.when.cyt_interval.tv64,
				   c->cyc.hdlr.cyh_func,
				   (uint64_t)c->cyc.hdlr.cyh_arg);
	} else
		seq_printf(seq, "CPU-%d: %c %lluns hdlr %pB arg %llx\n",
			   cyc->cpu,
			   cyc->cyc.hdlr.cyh_level == CY_HIGH_LEVEL
				? 'H' : 'l',
			   cyc->cyc.when.cyt_interval.tv64,
			   cyc->cyc.hdlr.cyh_func,
			   (uint64_t)cyc->cyc.hdlr.cyh_arg);

	return 0;
}

static const struct seq_operations	cyclicinfo_ops = {
	.start	= s_start,
	.next	= s_next,
	.stop	= s_stop,
	.show	= s_show,
};

static int cyclicinfo_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &cyclicinfo_ops);
}

static const struct file_operations	proc_cyclicinfo_ops = {
	.open		= cyclicinfo_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init proc_cyclicinfo_init(void)
{
	proc_create("cyclicinfo", S_IRUSR, NULL, &proc_cyclicinfo_ops);
	return 0;
}
module_init(proc_cyclicinfo_init);
