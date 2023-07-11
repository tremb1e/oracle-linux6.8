/*
 * FILE:        dtrace_sdt_core.c
 * DESCRIPTION: Dynamic Tracing: SDT probe point registration
 *
 * Copyright (C) 2010-2014 Oracle Corporation
 */

#include <linux/kernel.h>
#include <linux/memory.h>
#include <linux/module.h>
#include <linux/dtrace_os.h>
#include <linux/dtrace_sdt.h>
#include <linux/sdt.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm-generic/bitsperlong.h>
#include <asm-generic/sections.h>

const char		*sdt_prefix = "__dtrace_probe_";

static int sdt_probe_set(sdt_probedesc_t *sdp, char *name, char *func,
			 uintptr_t addr, asm_instr_t **paddr,\
			 sdt_probedesc_t *prv)
{
	if ((sdp->sdpd_name = kstrdup(name, GFP_KERNEL)) == NULL) {
		kfree(sdp);
		return 1;
	}

	if ((sdp->sdpd_func = kstrdup(func, GFP_KERNEL)) == NULL) {
		kfree(sdp->sdpd_name);
		kfree(sdp);
		return 1;
	}

	sdp->sdpd_offset = addr;
	sdp->sdpd_next = NULL;

	*paddr = (asm_instr_t *)addr;

	if (prv && strcmp(prv->sdpd_name, sdp->sdpd_name) == 0
		&& strcmp(prv->sdpd_func, sdp->sdpd_func) == 0)
		prv->sdpd_next = sdp;

	return 0;
}

/*
 * Register the SDT probes for the core kernel, i.e. SDT probes that reside in
 * vmlinux.  For SDT probes in kernel modules, we use dtrace_mod_notifier().
 */
void dtrace_sdt_register(struct module *mp)
{
	int			i, cnt;
	dtrace_sdt_probeinfo_t	*pi =
				(dtrace_sdt_probeinfo_t *)&dtrace_sdt_probes;
	void			*nextpi;
	sdt_probedesc_t		*sdps;
	asm_instr_t		**addrs;

	if (mp == NULL) {
		pr_warning("%s: no module provided - nothing registered\n",
			   __func__);
		return;
	}

	/*
	 * Just in case we run into failures further on...
	 */
	mp->sdt_probes = NULL;
	mp->sdt_probec = 0;

	if (dtrace_sdt_nprobes == 0)
		return;

	/*
	 * Allocate the array of SDT probe descriptions to be registered in the
	 * vmlinux pseudo-module.
	 */
	sdps = (sdt_probedesc_t *)vmalloc(dtrace_sdt_nprobes *
				          sizeof(sdt_probedesc_t));
	if (sdps == NULL) {
		pr_warning("%s: cannot allocate SDT probe array\n", __func__);
		return;
	}

	/*
	 * Create a list of addresses (SDT probe locations) that need to be
	 * patched with a NOP instruction (or instruction sequence).
	 */
	addrs = (asm_instr_t **)vmalloc(dtrace_sdt_nprobes *
					sizeof(asm_instr_t *));
	if (addrs == NULL) {
		pr_warning("%s: cannot allocate SDT probe address list\n",
			   __func__);
		vfree(sdps);
		return;
	}

	for (i = cnt = 0; cnt < dtrace_sdt_nprobes; i++) {
		char	*func = pi->name + pi->name_len + 1;

		if (sdt_probe_set(&sdps[cnt], pi->name, func, pi->addr,
				  &addrs[cnt],
				  cnt > 0 ? &sdps[cnt - 1] : NULL))
			pr_warning("%s: failed to add SDT probe %s\n",
				   __func__, pi->name);
		else
			cnt++;

		nextpi = (void *)pi + sizeof(dtrace_sdt_probeinfo_t)
			+ roundup(pi->name_len + 1 +
				  pi->func_len + 1, BITS_PER_LONG / 8);
		pi = nextpi;
	}

	mp->sdt_probes = sdps;
	mp->sdt_probec = cnt;

	dtrace_sdt_nop_multi(addrs, cnt);

	vfree(addrs);
}

static int __init nosdt(char *str)
{
        dtrace_sdt_nprobes = 0;

        return 0;
}

early_param("nosdt", nosdt);

void dtrace_sdt_register_module(struct module *mp)
{
	int			i, cnt;
	sdt_probedesc_t		*sdp;
	asm_instr_t		**addrs;

	if (mp->sdt_probec == 0 || mp->sdt_probes == NULL)
		return;

	/*
	 * Create a list of addresses (SDT probe locations) that need to be
	 * patched with a NOP instruction (or instruction sequence).
	 */
	addrs = (asm_instr_t **)vmalloc(mp->sdt_probec *
					sizeof(asm_instr_t *));
	if (addrs == NULL) {
		pr_warning("%s: cannot allocate SDT probe address list (%s)\n",
			   __func__, mp->name);
		return;
	}

	for (i = cnt = 0, sdp = mp->sdt_probes; i < mp->sdt_probec;
	     i++, sdp++)
		addrs[cnt++] = (asm_instr_t *)sdp->sdpd_offset;

	dtrace_sdt_nop_multi(addrs, cnt);

	vfree(addrs);
}

void dtrace_sdt_init(void)
{
	dtrace_sdt_init_arch();
}

#if defined(CONFIG_DT_DT_PERF) || defined(CONFIG_DT_DT_PERF_MODULE)
void dtrace_sdt_perf(void)
{
	DTRACE_PROBE(measure);
}
EXPORT_SYMBOL(dtrace_sdt_perf);
#endif
