/*
 * Copyright (c) 2006 Oracle.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <rdma/rdma_cm.h>

#include "rds.h"
#include "ib.h"

unsigned int rds_ib_srq_max_wr = RDS_IB_DEFAULT_SRQ_MAX_WR;
unsigned int rds_ib_srq_hwm_refill = RDS_IB_DEFAULT_SRQ_HWM_REFILL;
unsigned int rds_ib_srq_lwm_refill = RDS_IB_DEFAULT_SRQ_LWM_REFILL;
unsigned int rds_ib_srq_enabled = 0;

module_param(rds_ib_srq_enabled, int, 0444);
MODULE_PARM_DESC(rds_ib_srq_enabled, "Set to enabled SRQ");
module_param(rds_ib_srq_max_wr, int, 0444);
MODULE_PARM_DESC(rds_ib_srq_max_wr, "Max number of SRQ WRs");
module_param(rds_ib_srq_hwm_refill, int, 0444);
MODULE_PARM_DESC(rds_ib_srq_hwm_refill, "SRQ HWM refill");
module_param(rds_ib_srq_lwm_refill, int, 0444);
MODULE_PARM_DESC(rds_ib_srq_lwm_refill, "SRQ LWM refill");

static struct kmem_cache *rds_ib_incoming_slab;
static struct kmem_cache *rds_ib_frag_slab;
static atomic_t	rds_ib_allocation = ATOMIC_INIT(0);
static unsigned long rds_ib_allocation_warn = 1;

void rds_ib_recv_init_ring(struct rds_ib_connection *ic)
{
	struct rds_ib_recv_work *recv;
	u32 i;

	for (i = 0, recv = ic->i_recvs; i < ic->i_recv_ring.w_nr; i++, recv++) {
		struct ib_sge *sge;

		recv->r_ibinc = NULL;
		recv->r_frag = NULL;

		recv->r_wr.next = NULL;
		recv->r_wr.wr_id = i;
		recv->r_wr.sg_list = recv->r_sge;
		recv->r_wr.num_sge = RDS_IB_RECV_SGE;

		sge = &recv->r_sge[0];
		sge->addr = ic->i_recv_hdrs_dma + (i * sizeof(struct rds_header));
		sge->length = sizeof(struct rds_header);
		sge->lkey = ic->i_mr->lkey;

		sge = &recv->r_sge[1];
		sge->addr = 0;
		sge->length = ic->i_frag_sz;
		sge->lkey = ic->i_mr->lkey;
	}
}

/*
 * The entire 'from' list, including the from element itself, is put on
 * to the tail of the 'to' list.
 */
static void list_splice_entire_tail(struct list_head *from,
				    struct list_head *to)
{
	struct list_head *from_last = from->prev;

	list_splice_tail(from_last, to);
	list_add_tail(from_last, to);
}

static void rds_ib_cache_xfer_to_ready(struct rds_ib_refill_cache *cache)
{
	struct list_head *tmp;

	tmp = xchg(&cache->xfer, NULL);
	if (tmp) {
		if (cache->ready)
			list_splice_entire_tail(tmp, cache->ready);
		else
			cache->ready = tmp;
	}
}

static int rds_ib_recv_alloc_cache(struct rds_ib_refill_cache *cache)
{
	struct rds_ib_cache_head *head;
	int cpu;

	cache->percpu = alloc_percpu(struct rds_ib_cache_head);
	if (!cache->percpu)
		return -ENOMEM;

	for_each_possible_cpu(cpu) {
		head = per_cpu_ptr(cache->percpu, cpu);
		head->first = NULL;
		head->count = 0;
	}
	cache->xfer = NULL;
	cache->ready = NULL;

	return 0;
}

int rds_ib_recv_alloc_caches(struct rds_ib_connection *ic)
{
	int ret;

	ret = rds_ib_recv_alloc_cache(&ic->i_cache_incs);
	if (!ret) {
		ret = rds_ib_recv_alloc_cache(&ic->i_cache_frags);
		if (ret)
			free_percpu(ic->i_cache_incs.percpu);
	}

	return ret;
}

static void rds_ib_cache_splice_all_lists(struct rds_ib_refill_cache *cache,
					  struct list_head *caller_list)
{
	struct rds_ib_cache_head *head;
	int cpu;

	for_each_possible_cpu(cpu) {
		head = per_cpu_ptr(cache->percpu, cpu);
		if (head->first) {
			list_splice_entire_tail(head->first, caller_list);
			head->first = NULL;
		}
	}

	if (cache->ready) {
		list_splice_entire_tail(cache->ready, caller_list);
		cache->ready = NULL;
	}
}

/* Detach and free frags */
static void rds_ib_recv_free_frag(struct rds_page_frag *frag)
{
	rdsdebug("RDS/IB: frag %p page %p\n", frag, sg_page(&frag->f_sg));
	list_del_init(&frag->f_item);
	__free_pages(sg_page(&frag->f_sg), get_order(frag->f_sg.length));
}

void rds_ib_recv_free_caches(struct rds_ib_connection *ic)
{
	struct rds_ib_incoming *inc;
	struct rds_ib_incoming *inc_tmp;
	struct rds_page_frag *frag;
	struct rds_page_frag *frag_tmp;
	LIST_HEAD(list);

	rds_ib_cache_xfer_to_ready(&ic->i_cache_incs);
	rds_ib_cache_splice_all_lists(&ic->i_cache_incs, &list);
	free_percpu(ic->i_cache_incs.percpu);

	list_for_each_entry_safe(inc, inc_tmp, &list, ii_cache_entry) {
		list_del(&inc->ii_cache_entry);
		WARN_ON(!list_empty(&inc->ii_frags));
		kmem_cache_free(rds_ib_incoming_slab, inc);
	}

	rds_ib_cache_xfer_to_ready(&ic->i_cache_frags);
	rds_ib_cache_splice_all_lists(&ic->i_cache_frags, &list);
	free_percpu(ic->i_cache_frags.percpu);

	list_for_each_entry_safe(frag, frag_tmp, &list, f_cache_entry) {
		list_del(&frag->f_cache_entry);
		WARN_ON(!list_empty(&frag->f_item));
		rds_ib_recv_free_frag(frag);
		atomic_sub(ic->i_frag_pages, &rds_ib_allocation);
		kmem_cache_free(rds_ib_frag_slab, frag);
		atomic_sub(ic->i_frag_sz / 1024, &ic->i_cache_allocs);
		rds_ib_stats_add(s_ib_recv_removed_from_cache, ic->i_frag_sz);
	}
}

/* Called form rds_ib_conn_complete() and takes action only
 * if new connection needs different frag size than what is used.
 */
void rds_ib_recv_rebuild_caches(struct rds_ib_connection *ic)
{
	/* init it with the used frag size */
	if (!ic->i_frag_cache_sz) {
		ic->i_frag_cache_sz = ic->i_frag_sz;
		return;
	}

	/* check if existing cache can be re-used */
	if (ic->i_frag_cache_sz == ic->i_frag_sz)
		return;

	/* Now re-build the caches */
	rds_ib_recv_free_caches(ic);
	rds_ib_recv_alloc_caches(ic);

	pr_debug("RDS/IB: Rebuild caches for ic %p i_cm_id %p, frag{%d->%d}\n",
		 ic, ic->i_cm_id, ic->i_frag_cache_sz, ic->i_frag_sz);
	ic->i_frag_cache_sz = ic->i_frag_sz;
}

/* fwd decl */
static void rds_ib_recv_cache_put(struct list_head *new_item,
				  struct rds_ib_refill_cache *cache);
static struct list_head *rds_ib_recv_cache_get(struct rds_ib_refill_cache *cache);


/* Recycle frag and attached recv buffer f_sg */
static void rds_ib_frag_free(struct rds_ib_connection *ic,
			     struct rds_page_frag *frag)
{
	rdsdebug("frag %p page %p\n", frag, sg_page(&frag->f_sg));

	rds_ib_recv_cache_put(&frag->f_cache_entry, &ic->i_cache_frags);
	atomic_add(ic->i_frag_sz/1024, &ic->i_cache_allocs);
	rds_ib_stats_add(s_ib_recv_added_to_cache, ic->i_frag_sz);
}

/* Recycle inc after freeing attached frags */
void rds_ib_inc_free(struct rds_incoming *inc)
{
	struct rds_ib_incoming *ibinc;
	struct rds_page_frag *frag;
	struct rds_page_frag *pos;
	struct rds_ib_connection *ic = inc->i_conn->c_transport_data;

	ibinc = container_of(inc, struct rds_ib_incoming, ii_inc);

	/* Free attached frags */
	list_for_each_entry_safe(frag, pos, &ibinc->ii_frags, f_item) {
		list_del_init(&frag->f_item);
		rds_ib_frag_free(ic, frag);
	}
	BUG_ON(!list_empty(&ibinc->ii_frags));

	rdsdebug("freeing ibinc %p inc %p\n", ibinc, inc);
	rds_ib_recv_cache_put(&ibinc->ii_cache_entry, &ic->i_cache_incs);
}

static void rds_ib_recv_clear_one(struct rds_ib_connection *ic,
				  struct rds_ib_recv_work *recv)
{
	if (recv->r_ibinc) {
		rds_inc_put(&recv->r_ibinc->ii_inc);
		recv->r_ibinc = NULL;
	}
	if (recv->r_frag) {
		ib_dma_unmap_sg(ic->i_cm_id->device, &recv->r_frag->f_sg, 1, DMA_FROM_DEVICE);
		rds_ib_frag_free(ic, recv->r_frag);
		recv->r_frag = NULL;
	}
}

void rds_ib_recv_clear_ring(struct rds_ib_connection *ic)
{
	u32 i;

	for (i = 0; i < ic->i_recv_ring.w_nr; i++)
		rds_ib_recv_clear_one(ic, &ic->i_recvs[i]);
}

static struct rds_ib_incoming *rds_ib_refill_one_inc(struct rds_ib_connection *ic,
						     gfp_t slab_mask)
{
	struct rds_ib_incoming *ibinc;
	struct list_head *cache_item;

	cache_item = rds_ib_recv_cache_get(&ic->i_cache_incs);
	if (cache_item) {
		ibinc = container_of(cache_item, struct rds_ib_incoming, ii_cache_entry);
	} else {
		ibinc = kmem_cache_alloc(rds_ib_incoming_slab, slab_mask);
		if (!ibinc)
			return NULL;
		rds_ib_stats_inc(s_ib_rx_total_incs);
	}
	INIT_LIST_HEAD(&ibinc->ii_frags);
	rds_inc_init(&ibinc->ii_inc, ic->conn, ic->conn->c_faddr);

	return ibinc;
}

static struct rds_page_frag *rds_ib_refill_one_frag(struct rds_ib_connection *ic,
						    gfp_t slab_mask, gfp_t page_mask)
{
	struct rds_page_frag *frag;
	struct list_head *cache_item;
	int ret;
	int avail_allocs;

	cache_item = rds_ib_recv_cache_get(&ic->i_cache_frags);
	if (cache_item) {
		frag = container_of(cache_item, struct rds_page_frag, f_cache_entry);
		atomic_sub(ic->i_frag_sz/1024, &ic->i_cache_allocs);
		rds_ib_stats_add(s_ib_recv_removed_from_cache, ic->i_frag_sz);
	} else {
		frag = kmem_cache_alloc(rds_ib_frag_slab, slab_mask);
		if (!frag)
			return NULL;

		avail_allocs = atomic_add_unless(&rds_ib_allocation,
						 ic->i_frag_pages,
						 rds_ib_sysctl_max_recv_allocation);
		if (!avail_allocs) {
			if (test_and_clear_bit(0, &rds_ib_allocation_warn)) {
				printk(KERN_NOTICE "RDS/IB: WARNING - "
				"recv memory exceeded max_recv_allocation %d\n",
				atomic_read(&rds_ib_allocation));
			}
			rds_ib_stats_inc(s_ib_rx_alloc_limit);
			kmem_cache_free(rds_ib_frag_slab, frag);
			return NULL;
		}

		sg_init_table(&frag->f_sg, 1);
		ret = rds_page_remainder_alloc(&frag->f_sg,
					       ic->i_frag_sz, page_mask, true);
		if (ret) {
			kmem_cache_free(rds_ib_frag_slab, frag);
			atomic_sub(ic->i_frag_pages, &rds_ib_allocation);
			return NULL;
		}
		rds_ib_stats_inc(s_ib_rx_total_frags);
	}

	INIT_LIST_HEAD(&frag->f_item);

	return frag;
}

static int rds_ib_recv_refill_one(struct rds_connection *conn,
				  struct rds_ib_recv_work *recv, gfp_t gfp)
{
	struct rds_ib_connection *ic = conn->c_transport_data;
	struct ib_sge *sge;
	int ret = -ENOMEM;
	gfp_t slab_mask = GFP_NOWAIT;
	gfp_t page_mask = GFP_NOWAIT;

	if (gfp & __GFP_WAIT) {
		slab_mask = GFP_KERNEL;
		page_mask = GFP_HIGHUSER;
	}

	if (!ic->i_cache_incs.ready)
		rds_ib_cache_xfer_to_ready(&ic->i_cache_incs);
	if (!ic->i_cache_frags.ready)
		rds_ib_cache_xfer_to_ready(&ic->i_cache_frags);

	/*
	 * ibinc was taken from recv if recv contained the start of a message.
	 * recvs that were continuations will still have this allocated.
	 */
	if (!recv->r_ibinc) {
		recv->r_ibinc = rds_ib_refill_one_inc(ic, slab_mask);
		if (!recv->r_ibinc)
			goto out;
	}

	WARN_ON_ONCE(recv->r_frag); /* leak! */
	recv->r_frag = rds_ib_refill_one_frag(ic, slab_mask, page_mask);
	if (!recv->r_frag)
		goto out;

	ret = ib_dma_map_sg(ic->i_cm_id->device, &recv->r_frag->f_sg,
			    1, DMA_FROM_DEVICE);
	WARN_ON(ret != 1);

	sge = &recv->r_sge[0];
	sge->addr = ic->i_recv_hdrs_dma + (recv - ic->i_recvs) * sizeof(struct rds_header);
	sge->length = sizeof(struct rds_header);

	sge = &recv->r_sge[1];
	sge->addr = sg_dma_address(&recv->r_frag->f_sg);
	sge->length = sg_dma_len(&recv->r_frag->f_sg);

	ret = 0;
out:
	return ret;
}

static void rds_ib_srq_clear_one(struct rds_ib_srq *srq,
				struct rds_ib_recv_work *recv)
{
	if (recv->r_ibinc) {
		if (recv->r_ic)
			rds_inc_put(&recv->r_ibinc->ii_inc);
		else
			kmem_cache_free(rds_ib_incoming_slab, recv->r_ibinc);
		recv->r_ibinc = NULL;
	}
	if (recv->r_frag) {
		ib_dma_unmap_sg(srq->rds_ibdev->dev, &recv->r_frag->f_sg,
				1, DMA_FROM_DEVICE);
		if (recv->r_ic)
			rds_ib_frag_free(recv->r_ic, recv->r_frag);
		else
			kmem_cache_free(rds_ib_frag_slab, recv->r_frag);
		recv->r_frag = NULL;
		recv->r_posted = 0;
	}
}

static int rds_ib_srq_refill_one(struct rds_ib_srq *srq,
				struct rds_ib_connection *ic,
				struct rds_ib_recv_work *recv, gfp_t gfp)
{
	struct ib_sge *sge;
	int ret = -ENOMEM;
	gfp_t slab_mask = GFP_NOWAIT;
	gfp_t page_mask = GFP_NOWAIT;

	if (gfp & __GFP_WAIT) {
		slab_mask = GFP_KERNEL;
		page_mask = GFP_HIGHUSER;
	}

	if (!ic->i_cache_incs.ready)
		rds_ib_cache_xfer_to_ready(&ic->i_cache_incs);
	if (!ic->i_cache_frags.ready)
		rds_ib_cache_xfer_to_ready(&ic->i_cache_frags);

	/*
	* ibinc was taken from recv if recv contained the start of a message.
	* recvs that were continuations will still have this allocated.
	*/

	if (!recv->r_ibinc) {
		recv->r_ibinc = rds_ib_refill_one_inc(ic, slab_mask);
		if (!recv->r_ibinc)
			goto out;
	}

	WARN_ON_ONCE(recv->r_frag); /* leak! */
	recv->r_frag = rds_ib_refill_one_frag(ic, slab_mask, page_mask);
	if (!recv->r_frag)
		goto out;

	ret = ib_dma_map_sg(srq->rds_ibdev->dev, &recv->r_frag->f_sg,
			1, DMA_FROM_DEVICE);

	WARN_ON(ret != 1);

	sge = &recv->r_sge[0];

	sge->addr = srq->s_recv_hdrs_dma +
		(recv - srq->s_recvs) *
		sizeof(struct rds_header);

	sge->length = sizeof(struct rds_header);

	sge = &recv->r_sge[1];
	sge->addr = sg_dma_address(&recv->r_frag->f_sg);
	sge->length = sg_dma_len(&recv->r_frag->f_sg);

	ret = 0;
out:
	return ret;
}

static int rds_ib_srq_prefill_one(struct rds_ib_device *rds_ibdev,
				struct rds_ib_recv_work *recv, int prefill)
{
	struct ib_sge *sge;
	int ret = -ENOMEM;
	gfp_t slab_mask = GFP_NOWAIT;
	gfp_t page_mask = GFP_NOWAIT;

	if (prefill) {
		slab_mask = GFP_KERNEL;
		page_mask = GFP_HIGHUSER;
	}

	if (!recv->r_ibinc) {
		recv->r_ibinc = kmem_cache_alloc(rds_ib_incoming_slab, slab_mask);
		if (!recv->r_ibinc)
			goto out;
		rds_ib_stats_inc(s_ib_rx_total_incs);
		INIT_LIST_HEAD(&recv->r_ibinc->ii_frags);
	}

	WARN_ON_ONCE(recv->r_frag); /* leak! */
	recv->r_frag = kmem_cache_alloc(rds_ib_frag_slab, slab_mask);
	if (!recv->r_frag)
		goto out;
	sg_init_table(&recv->r_frag->f_sg, 1);
	if (recv->r_ic)
		ret = rds_page_remainder_alloc(&recv->r_frag->f_sg,
				recv->r_ic->i_frag_sz, page_mask, true);
	else
		ret = rds_page_remainder_alloc(&recv->r_frag->f_sg,
				RDS_FRAG_SIZE, page_mask, true);
	if (ret) {
		kmem_cache_free(rds_ib_frag_slab, recv->r_frag);
		goto out;
	}

	rds_ib_stats_inc(s_ib_rx_total_frags);
	INIT_LIST_HEAD(&recv->r_frag->f_item);

	ret = ib_dma_map_sg(rds_ibdev->dev, &recv->r_frag->f_sg,
			1, DMA_FROM_DEVICE);
	WARN_ON(ret != 1);

	sge = &recv->r_sge[0];
	sge->addr = rds_ibdev->srq->s_recv_hdrs_dma +
			(recv - rds_ibdev->srq->s_recvs) *
			sizeof(struct rds_header);
	sge->length = sizeof(struct rds_header);
	sge->lkey = rds_ibdev->mr->lkey;

	sge = &recv->r_sge[1];
	sge->addr = sg_dma_address(&recv->r_frag->f_sg);
	sge->length = sg_dma_len(&recv->r_frag->f_sg);
	sge->lkey = rds_ibdev->mr->lkey;

	ret = 0;
out:
	return ret;
}



static int acquire_refill(struct rds_connection *conn)
{
	return test_and_set_bit(RDS_RECV_REFILL, &conn->c_flags) == 0;
}

static void release_refill(struct rds_connection *conn)
{
	clear_bit(RDS_RECV_REFILL, &conn->c_flags);
	smp_mb__after_atomic();
	/*
	 * We don't use wait_on_bit()/wake_up_bit() because our waking is in a
	 * hot path and finding waiters is very rare.  We don't want to walk
	 * the system-wide hashed waitqueue buckets in the fast path only to
	 * almost never find waiters.
	 */
	if (waitqueue_active(&conn->c_waitq))
		wake_up_all(&conn->c_waitq);
}


/*
 * This tries to allocate and post unused work requests after making sure that
 * they have all the allocations they need to queue received fragments into
 * sockets.
 *
 * -1 is returned if posting fails due to temporary resource exhaustion.
 */
void rds_ib_recv_refill(struct rds_connection *conn, int prefill, gfp_t gfp)
{
	struct rds_ib_connection *ic = conn->c_transport_data;
	struct rds_ib_recv_work *recv;
	struct ib_recv_wr *failed_wr;
	unsigned int posted = 0;
	unsigned int flowctl_credits = 0;
	/* For the time being, 16 seems to be a good starting number to
	 * perform flow control update.
	 */
	unsigned int flow_cntl_log2_cnt = 16;
	int ret = 0;
	int can_wait = gfp & __GFP_WAIT;
	int must_wake = 0;
	int ring_low = 0;
	int ring_empty = 0;
	u32 pos;

	/*
	 * the goal here is to just make sure that someone, somewhere
	 * is posting buffers.  If we can't get the refill lock,
	 * let them do their thing
	 */
	if (!acquire_refill(conn))
		return;

	ring_low = rds_ib_ring_low(&ic->i_recv_ring);
	ring_empty = rds_ib_ring_empty(&ic->i_recv_ring);

	/* If we ever end up with a really empty receive ring, we're
	 * in deep trouble, as the sender will definitely see RNR
	 * timeouts. */
	if (ring_empty)
		rds_ib_stats_inc(s_ib_rx_ring_empty);

	/*
	 * if we're called from the tasklet, can_wait will be zero.  We only
	 * want to refill if we're getting low in this case
	 */
	if (!ring_low && !can_wait)
		goto release_out;

	while ((prefill || rds_conn_up(conn))
			&& rds_ib_ring_alloc(&ic->i_recv_ring, 1, &pos)) {
		if (pos >= ic->i_recv_ring.w_nr) {
			printk(KERN_NOTICE "Argh - ring alloc returned pos=%u\n",
					pos);
			break;
		}

		recv = &ic->i_recvs[pos];
		ret = rds_ib_recv_refill_one(conn, recv, gfp);
		if (ret)
			break;

		/* XXX when can this fail? */
		ret = ib_post_recv(ic->i_cm_id->qp, &recv->r_wr, &failed_wr);
		rdsdebug("recv %p ibinc %p page %p addr %lu ret %d\n", recv,
			 recv->r_ibinc, sg_page(&recv->r_frag->f_sg),
			 (long) sg_dma_address(&recv->r_frag->f_sg), ret);
		if (ret) {
			conn->c_drop_source = DR_IB_POST_RECV_FAIL;
			rds_ib_conn_error(conn, "recv post on "
			       "%pI4 returned %d, disconnecting and "
			       "reconnecting\n", &conn->c_faddr,
			       ret);
			break;
		}

		posted++;
		if (ic->i_flowctl) {
			flowctl_credits++;
			/* Decide whether to send an update to the peer now.
			 * If we would send a credit update for every single
			 * buffer we post, we would end up with an ACK
			 * storm (ACK arrives,consumes buffer, we refill
			 * the ring, send ACK to remote advertising the
			 * newly posted buffer... ad inf)
			 *
			 * Performance pretty much depends on how often we send
			 * credit updates - too frequent updates mean lots of
			 * ACKs. Too infrequent updates, and the peer will run
			 * out of credits and has to throttle.
			 * For the time being, incremental cnt << 4 is used.
			 */
			if (flowctl_credits == flow_cntl_log2_cnt) {
				rds_ib_advertise_credits(conn, flowctl_credits);
				flow_cntl_log2_cnt <<= 4;
				flowctl_credits = 0;
			}
		}

		if ((posted > 128 && need_resched()) || posted > 8192) {
			must_wake = 1;
			break;
		}
	}

	/* read ring_low and ring_empty before we drop our lock */
	ring_low = rds_ib_ring_low(&ic->i_recv_ring);
	ring_empty = rds_ib_ring_empty(&ic->i_recv_ring);

	/* We're doing flow control - update the window. */
	if (ic->i_flowctl && flowctl_credits)
		rds_ib_advertise_credits(conn, flowctl_credits);

	if (ret)
		rds_ib_ring_unalloc(&ic->i_recv_ring, 1);

release_out:
	release_refill(conn);

	/* if we're called from the softirq handler, we'll be GFP_NOWAIT.
	 * in this case the ring being low is going to lead to more interrupts
	 * and we can safely let the softirq code take care of it unless the
	 * ring is completely empty.
	 *
	 * if we're called from krdsd, we'll be GFP_KERNEL.  In this case
	 * we might have raced with the softirq code while we had the refill
	 * lock held.  Use rds_ib_ring_low() instead of ring_empty to decide
	 * if we should requeue.
	 */
	if (rds_conn_up(conn) &&
	   (must_wake || (can_wait && ring_low)
			|| rds_ib_ring_empty(&ic->i_recv_ring))) {
		queue_delayed_work(rds_wq, &conn->c_recv_w, 1);
	}
	if (can_wait)
		cond_resched();
}

/*
 * We want to recycle several types of recv allocations, like incs and frags.
 * To use this, the *_free() function passes in the ptr to a list_head within
 * the recyclee, as well as the cache to put it on.
 *
 * First, we put the memory on a percpu list. When this reaches a certain size,
 * We move it to an intermediate non-percpu list in a lockless manner, with some
 * xchg/compxchg wizardry.
 *
 * N.B. Instead of a list_head as the anchor, we use a single pointer, which can
 * be NULL and xchg'd. The list is actually empty when the pointer is NULL, and
 * list_empty() will return true with one element is actually present.
 */
static void rds_ib_recv_cache_put(struct list_head *new_item,
				 struct rds_ib_refill_cache *cache)
{
	unsigned long flags;
	struct rds_ib_cache_head *chp;
	struct list_head *old;

	local_irq_save(flags);

	chp = per_cpu_ptr(cache->percpu, smp_processor_id());
	if (!chp->first)
		INIT_LIST_HEAD(new_item);
	else /* put on front */
		list_add_tail(new_item, chp->first);
	chp->first = new_item;
	chp->count++;

	if (chp->count < RDS_IB_RECYCLE_BATCH_COUNT)
		goto end;

	/*
	 * Return our per-cpu first list to the cache's xfer by atomically
	 * grabbing the current xfer list, appending it to our per-cpu list,
	 * and then atomically returning that entire list back to the
	 * cache's xfer list as long as it's still empty.
	 */
	do {
		old = xchg(&cache->xfer, NULL);
		if (old)
			list_splice_entire_tail(old, chp->first);
		old = cmpxchg(&cache->xfer, NULL, chp->first);
	} while (old);

	chp->first = NULL;
	chp->count = 0;
end:
	local_irq_restore(flags);
}

static struct list_head *rds_ib_recv_cache_get(struct rds_ib_refill_cache *cache)
{
	struct list_head *head = cache->ready;

	if (head) {
		if (!list_empty(head)) {
			cache->ready = head->next;
			list_del_init(head);
		} else
			cache->ready = NULL;
	}

	return head;
}

int rds_ib_inc_copy_to_user(struct rds_incoming *inc, struct iov_iter *to)
{
	struct rds_ib_connection *ic = inc->i_conn->c_transport_data;
	struct rds_ib_incoming *ibinc;
	struct rds_page_frag *frag;
	unsigned long to_copy;
	unsigned long frag_off = 0;
	int copied = 0;
	int ret;
	u32 len;

	ibinc = container_of(inc, struct rds_ib_incoming, ii_inc);
	frag = list_entry(ibinc->ii_frags.next, struct rds_page_frag, f_item);
	len = be32_to_cpu(inc->i_hdr.h_len);

	while (iov_iter_count(to) && copied < len) {
		if (frag_off == ic->i_frag_sz) {
			frag = list_entry(frag->f_item.next,
					  struct rds_page_frag, f_item);
			frag_off = 0;
		}
		to_copy = min_t(unsigned long, iov_iter_count(to),
				ic->i_frag_sz - frag_off);
		to_copy = min_t(unsigned long, to_copy, len - copied);

		/* XXX needs + offset for multiple recvs per page */
		rds_stats_add(s_copy_to_user, to_copy);
		ret = copy_page_to_iter(sg_page(&frag->f_sg),
					frag->f_sg.offset + frag_off,
					to_copy,
					to);
		if (ret != to_copy)
			return -EFAULT;

		frag_off += to_copy;
		copied += to_copy;
	}

	return copied;
}

/* ic starts out kzalloc()ed */
void rds_ib_recv_init_ack(struct rds_ib_connection *ic)
{
	struct ib_send_wr *wr = &ic->i_ack_wr;
	struct ib_sge *sge = &ic->i_ack_sge;

	sge->addr = ic->i_ack_dma;
	sge->length = sizeof(struct rds_header);
	sge->lkey = ic->i_mr->lkey;

	wr->sg_list = sge;
	wr->num_sge = 1;
	wr->opcode = IB_WR_SEND;
	wr->wr_id = RDS_IB_ACK_WR_ID;
	wr->send_flags = IB_SEND_SIGNALED | IB_SEND_SOLICITED;
}

/*
 * You'd think that with reliable IB connections you wouldn't need to ack
 * messages that have been received.  The problem is that IB hardware generates
 * an ack message before it has DMAed the message into memory.  This creates a
 * potential message loss if the HCA is disabled for any reason between when it
 * sends the ack and before the message is DMAed and processed.  This is only a
 * potential issue if another HCA is available for fail-over.
 *
 * When the remote host receives our ack they'll free the sent message from
 * their send queue.  To decrease the latency of this we always send an ack
 * immediately after we've received messages.
 *
 * For simplicity, we only have one ack in flight at a time.  This puts
 * pressure on senders to have deep enough send queues to absorb the latency of
 * a single ack frame being in flight.  This might not be good enough.
 *
 * This is implemented by have a long-lived send_wr and sge which point to a
 * statically allocated ack frame.  This ack wr does not fall under the ring
 * accounting that the tx and rx wrs do.  The QP attribute specifically makes
 * room for it beyond the ring size.  Send completion notices its special
 * wr_id and avoids working with the ring in that case.
 */
#ifndef KERNEL_HAS_ATOMIC64
void rds_ib_set_ack(struct rds_ib_connection *ic, u64 seq,
				int ack_required)
{
	unsigned long flags;

	spin_lock_irqsave(&ic->i_ack_lock, flags);
	ic->i_ack_next = seq;
	if (ack_required)
		set_bit(IB_ACK_REQUESTED, &ic->i_ack_flags);
	spin_unlock_irqrestore(&ic->i_ack_lock, flags);
}

static u64 rds_ib_get_ack(struct rds_ib_connection *ic)
{
	unsigned long flags;
	u64 seq;

	clear_bit(IB_ACK_REQUESTED, &ic->i_ack_flags);

	spin_lock_irqsave(&ic->i_ack_lock, flags);
	seq = ic->i_ack_next;
	spin_unlock_irqrestore(&ic->i_ack_lock, flags);

	return seq;
}
#else
void rds_ib_set_ack(struct rds_ib_connection *ic, u64 seq,
				int ack_required)
{
	atomic64_set(&ic->i_ack_next, seq);
	if (ack_required) {
		smp_mb__before_atomic();
		set_bit(IB_ACK_REQUESTED, &ic->i_ack_flags);
	}
}

static u64 rds_ib_get_ack(struct rds_ib_connection *ic)
{
	clear_bit(IB_ACK_REQUESTED, &ic->i_ack_flags);
	smp_mb__after_atomic();

	return atomic64_read(&ic->i_ack_next);
}
#endif


static void rds_ib_send_ack(struct rds_ib_connection *ic, unsigned int adv_credits)
{
	struct rds_header *hdr = ic->i_ack;
	struct ib_send_wr *failed_wr;
	u64 seq;
	int ret;

	seq = rds_ib_get_ack(ic);

	rdsdebug("send_ack: ic %p ack %llu\n", ic, (unsigned long long) seq);
	rds_message_populate_header(hdr, 0, 0, 0);
	hdr->h_ack = cpu_to_be64(seq);
	hdr->h_credit = adv_credits;
	rds_message_make_checksum(hdr);
	ic->i_ack_queued = jiffies;

	ret = ib_post_send(ic->i_cm_id->qp, &ic->i_ack_wr, &failed_wr);
	if (unlikely(ret)) {
		/* Failed to send. Release the WR, and
		 * force another ACK.
		 */
		clear_bit(IB_ACK_IN_FLIGHT, &ic->i_ack_flags);
		set_bit(IB_ACK_REQUESTED, &ic->i_ack_flags);

		rds_ib_stats_inc(s_ib_ack_send_failure);

		ic->conn->c_drop_source = DR_IB_SEND_ACK_FAIL;
		rds_ib_conn_error(ic->conn, "sending ack failed\n");
	} else
		rds_ib_stats_inc(s_ib_ack_sent);
}

/*
 * There are 3 ways of getting acknowledgements to the peer:
 *  1.	We call rds_ib_attempt_ack from the recv completion handler
 *	to send an ACK-only frame.
 *	However, there can be only one such frame in the send queue
 *	at any time, so we may have to postpone it.
 *  2.	When another (data) packet is transmitted while there's
 *	an ACK in the queue, we piggyback the ACK sequence number
 *	on the data packet.
 *  3.	If the ACK WR is done sending, we get called from the
 *	send queue completion handler, and check whether there's
 *	another ACK pending (postponed because the WR was on the
 *	queue). If so, we transmit it.
 *
 * We maintain 2 variables:
 *  -	i_ack_flags, which keeps track of whether the ACK WR
 *	is currently in the send queue or not (IB_ACK_IN_FLIGHT)
 *  -	i_ack_next, which is the last sequence number we received
 *
 * Potentially, send queue and receive queue handlers can run concurrently.
 * It would be nice to not have to use a spinlock to synchronize things,
 * but the one problem that rules this out is that 64bit updates are
 * not atomic on all platforms. Things would be a lot simpler if
 * we had atomic64 or maybe cmpxchg64 everywhere.
 *
 * Reconnecting complicates this picture just slightly. When we
 * reconnect, we may be seeing duplicate packets. The peer
 * is retransmitting them, because it hasn't seen an ACK for
 * them. It is important that we ACK these.
 *
 * ACK mitigation adds a header flag "ACK_REQUIRED"; any packet with
 * this flag set *MUST* be acknowledged immediately.
 */

/*
 * When we get here, we're called from the recv queue handler.
 * Check whether we ought to transmit an ACK.
 */
void rds_ib_attempt_ack(struct rds_ib_connection *ic)
{
	unsigned int adv_credits;

	if (!test_bit(IB_ACK_REQUESTED, &ic->i_ack_flags))
		return;

	if (test_and_set_bit(IB_ACK_IN_FLIGHT, &ic->i_ack_flags)) {
		rds_ib_stats_inc(s_ib_ack_send_delayed);
		return;
	}

	/* Can we get a send credit? */
	if (!rds_ib_send_grab_credits(ic, 1, &adv_credits, 0)) {
		rds_ib_stats_inc(s_ib_tx_throttle);
		clear_bit(IB_ACK_IN_FLIGHT, &ic->i_ack_flags);
		return;
	}

	clear_bit(IB_ACK_REQUESTED, &ic->i_ack_flags);
	rds_ib_send_ack(ic, adv_credits);
}

/*
 * We get here from the send completion handler, when the
 * adapter tells us the ACK frame was sent.
 */
void rds_ib_ack_send_complete(struct rds_ib_connection *ic)
{
	clear_bit(IB_ACK_IN_FLIGHT, &ic->i_ack_flags);
	rds_ib_attempt_ack(ic);
}

/*
 * This is called by the regular xmit code when it wants to piggyback
 * an ACK on an outgoing frame.
 */
u64 rds_ib_piggyb_ack(struct rds_ib_connection *ic)
{
	if (test_and_clear_bit(IB_ACK_REQUESTED, &ic->i_ack_flags))
		rds_ib_stats_inc(s_ib_ack_send_piggybacked);
	return rds_ib_get_ack(ic);
}

/*
 * It's kind of lame that we're copying from the posted receive pages into
 * long-lived bitmaps.  We could have posted the bitmaps and rdma written into
 * them.  But receiving new congestion bitmaps should be a *rare* event, so
 * hopefully we won't need to invest that complexity in making it more
 * efficient.  By copying we can share a simpler core with TCP which has to
 * copy.
 */
static void rds_ib_cong_recv(struct rds_connection *conn,
			      struct rds_ib_incoming *ibinc)
{
	struct rds_ib_connection *ic = conn->c_transport_data;
	struct rds_cong_map *map;
	unsigned int map_off;
	unsigned int map_page;
	struct rds_page_frag *frag;
	unsigned long frag_off;
	unsigned long to_copy;
	unsigned long copied;
	uint64_t uncongested = 0;
	void *addr;

	/* catch completely corrupt packets */
	if (be32_to_cpu(ibinc->ii_inc.i_hdr.h_len) != RDS_CONG_MAP_BYTES)
		return;

	map = conn->c_fcong;
	map_page = 0;
	map_off = 0;

	frag = list_entry(ibinc->ii_frags.next, struct rds_page_frag, f_item);
	frag_off = 0;

	copied = 0;

	while (copied < RDS_CONG_MAP_BYTES) {
		uint64_t *src, *dst;
		unsigned int k;

		to_copy = min(ic->i_frag_sz - frag_off, RDS_CONG_PAGE_SIZE - map_off);
		BUG_ON(to_copy & 7); /* Must be 64bit aligned. */

		addr = kmap_atomic(sg_page(&frag->f_sg));

		src = addr + frag->f_sg.offset + frag_off;
		dst = (void *)map->m_page_addrs[map_page] + map_off;
		for (k = 0; k < to_copy; k += 8) {
			/* Record ports that became uncongested, ie
			 * bits that changed from 0 to 1. */
			uncongested |= ~(*src) & *dst;
			*dst++ = *src++;
		}
		kunmap_atomic(addr);

		copied += to_copy;

		map_off += to_copy;
		if (map_off == RDS_CONG_PAGE_SIZE) {
			map_off = 0;
			map_page++;
		}

		frag_off += to_copy;
		if (frag_off == ic->i_frag_sz) {
			frag = list_entry(frag->f_item.next,
					  struct rds_page_frag, f_item);
			frag_off = 0;
		}
	}

	/* the congestion map is in little endian order */
	uncongested = le64_to_cpu(uncongested);

	rds_cong_map_updated(map, uncongested);
}

static void rds_ib_process_recv(struct rds_connection *conn,
				struct rds_ib_recv_work *recv, u32 data_len,
				struct rds_ib_ack_state *state)
{
	struct rds_ib_connection *ic = conn->c_transport_data;
	struct rds_ib_incoming *ibinc = ic->i_ibinc;
	struct rds_header *ihdr, *hdr;

	/* XXX shut down the connection if port 0,0 are seen? */

	rdsdebug("ic %p ibinc %p recv %p byte len %u\n", ic, ibinc, recv,
		 data_len);

	if (data_len < sizeof(struct rds_header)) {
		conn->c_drop_source = DR_IB_HEADER_MISSING;
		rds_ib_conn_error(conn, "incoming message "
		       "from %pI4 didn't inclue a "
		       "header, disconnecting and "
		       "reconnecting\n",
		       &conn->c_faddr);
		return;
	}
	data_len -= sizeof(struct rds_header);

	ihdr = &ic->i_recv_hdrs[recv - ic->i_recvs];

	/* Validate the checksum. */
	if (!rds_message_verify_checksum(ihdr)) {
		conn->c_drop_source = DR_IB_HEADER_CORRUPTED;
		rds_ib_conn_error(conn, "incoming message "
		       "from %pI4 has corrupted header - "
		       "forcing a reconnect\n",
		       &conn->c_faddr);
		rds_stats_inc(s_recv_drop_bad_checksum);
		return;
	}

	/* Process the ACK sequence which comes with every packet */
	state->ack_recv = be64_to_cpu(ihdr->h_ack);
	state->ack_recv_valid = 1;

	/* Process the credits update if there was one */
	if (ihdr->h_credit)
		rds_ib_send_add_credits(conn, ihdr->h_credit);

	if (ihdr->h_sport == 0 && ihdr->h_dport == 0 && data_len == 0 &&
		ihdr->h_flags == 0) {
		/* This is an ACK-only packet. The fact that it gets
		 * special treatment here is that historically, ACKs
		 * were rather special beasts.
		 */
		rds_ib_stats_inc(s_ib_ack_received);

		/*
		 * Usually the frags make their way on to incs and are then freed as
		 * the inc is freed.  We don't go that route, so we have to drop the
		 * page ref ourselves.  We can't just leave the page on the recv
		 * because that confuses the dma mapping of pages and each recv's use
		 * of a partial page.
		 *
		 * FIXME: Fold this into the code path below.
		 */
		rds_ib_frag_free(ic, recv->r_frag);
		recv->r_frag = NULL;
		return;
	}

	/*
	 * If we don't already have an inc on the connection then this
	 * fragment has a header and starts a message.. copy its header
	 * into the inc and save the inc so we can hang upcoming fragments
	 * off its list.
	 */
	if (!ibinc) {
		ibinc = recv->r_ibinc;
		recv->r_ibinc = NULL;
		ic->i_ibinc = ibinc;

		hdr = &ibinc->ii_inc.i_hdr;
		ibinc->ii_inc.i_rx_lat_trace[RDS_MSG_RX_HDR] =
				local_clock();
		memcpy(hdr, ihdr, sizeof(*hdr));
		ic->i_recv_data_rem = be32_to_cpu(hdr->h_len);
		ibinc->ii_inc.i_rx_lat_trace[RDS_MSG_RX_START] =
				local_clock();

		rdsdebug("ic %p ibinc %p rem %u flag 0x%x\n", ic, ibinc,
			 ic->i_recv_data_rem, hdr->h_flags);
	} else {
		hdr = &ibinc->ii_inc.i_hdr;
		/* We can't just use memcmp here; fragments of a
		 * single message may carry different ACKs */
		if (hdr->h_sequence != ihdr->h_sequence
		 || hdr->h_len != ihdr->h_len
		 || hdr->h_sport != ihdr->h_sport
		 || hdr->h_dport != ihdr->h_dport) {
			conn->c_drop_source = DR_IB_FRAG_HEADER_MISMATCH;
			rds_ib_conn_error(conn,
				"fragment header mismatch; forcing reconnect\n");
			return;
		}
	}

	list_add_tail(&recv->r_frag->f_item, &ibinc->ii_frags);
	recv->r_frag = NULL;

	if (ic->i_recv_data_rem > ic->i_frag_sz)
		ic->i_recv_data_rem -= ic->i_frag_sz;
	else {
		ic->i_recv_data_rem = 0;
		ic->i_ibinc = NULL;

		if (ibinc->ii_inc.i_hdr.h_flags == RDS_FLAG_CONG_BITMAP)
			rds_ib_cong_recv(conn, ibinc);
		else {
			rds_recv_incoming(conn, conn->c_faddr, conn->c_laddr,
					  &ibinc->ii_inc, GFP_ATOMIC);
			state->ack_next = be64_to_cpu(hdr->h_sequence);
			state->ack_next_valid = 1;
		}

		/* Evaluate the ACK_REQUIRED flag *after* we received
		 * the complete frame, and after bumping the next_rx
		 * sequence. */
		if (hdr->h_flags & RDS_FLAG_ACK_REQUIRED) {
			rds_stats_inc(s_recv_ack_required);
			state->ack_required = 1;
		}

		rds_inc_put(&ibinc->ii_inc);
	}
}

void rds_ib_srq_process_recv(struct rds_connection *conn,
				struct rds_ib_recv_work *recv, u32 data_len,
				struct rds_ib_ack_state *state)
{
	struct rds_ib_connection *ic = conn->c_transport_data;
	struct rds_ib_incoming *ibinc = ic->i_ibinc;
	struct rds_header *ihdr, *hdr;

	if (data_len < sizeof(struct rds_header)) {
		printk(KERN_WARNING "RDS: from %pI4 didn't inclue a "
			"header, disconnecting and "
			"reconnecting\n",
			&conn->c_faddr);
		rds_ib_frag_free(ic, recv->r_frag);
		recv->r_frag = NULL;
		return;
	}
	data_len -= sizeof(struct rds_header);

	ihdr = &ic->rds_ibdev->srq->s_recv_hdrs[recv->r_wr.wr_id];

	/* Validate the checksum. */
	if (!rds_message_verify_checksum(ihdr)) {
		printk(KERN_WARNING "RDS: from %pI4 has corrupted header - "
			"forcing a reconnect\n",
			&conn->c_faddr);
		rds_stats_inc(s_recv_drop_bad_checksum);
		rds_ib_frag_free(ic, recv->r_frag);
		recv->r_frag = NULL;
		return;
	}

	/* Process the ACK sequence which comes with every packet */
	state->ack_recv = be64_to_cpu(ihdr->h_ack);
	state->ack_recv = be64_to_cpu(ihdr->h_ack);
	state->ack_recv_valid = 1;

	if (ihdr->h_sport == 0 && ihdr->h_dport == 0 && data_len == 0) {
		rds_ib_stats_inc(s_ib_ack_received);
		rds_ib_frag_free(ic, recv->r_frag);
		recv->r_frag = NULL;
		return;
	}

	if (!ibinc) {
		ibinc = recv->r_ibinc;
		rds_inc_init(&ibinc->ii_inc, ic->conn, ic->conn->c_faddr);
		recv->r_ibinc = NULL;
		ic->i_ibinc = ibinc;
		hdr = &ibinc->ii_inc.i_hdr;
		memcpy(hdr, ihdr, sizeof(*hdr));
		ic->i_recv_data_rem = be32_to_cpu(hdr->h_len);
	} else {
		hdr = &ibinc->ii_inc.i_hdr;
		if (hdr->h_sequence != ihdr->h_sequence
			|| hdr->h_len != ihdr->h_len
			|| hdr->h_sport != ihdr->h_sport
			|| hdr->h_dport != ihdr->h_dport) {
				printk(KERN_WARNING "RDS: fragment header mismatch; "
					"forcing reconnect\n");
				rds_ib_frag_free(ic, recv->r_frag);
				recv->r_frag = NULL;
				return;
		}
	}

	list_add_tail(&recv->r_frag->f_item, &ibinc->ii_frags);

	recv->r_frag = NULL;

	if (ic->i_recv_data_rem > ic->i_frag_sz)
		ic->i_recv_data_rem -= ic->i_frag_sz;
	else {
		ic->i_recv_data_rem = 0;
		ic->i_ibinc = NULL;

		if (ibinc->ii_inc.i_hdr.h_flags == RDS_FLAG_CONG_BITMAP)
			rds_ib_cong_recv(conn, ibinc);
		else {
			rds_recv_incoming(conn, conn->c_faddr, conn->c_laddr,
					&ibinc->ii_inc, GFP_ATOMIC);

			state->ack_next = be64_to_cpu(hdr->h_sequence);
			state->ack_next_valid = 1;
		}
		if (hdr->h_flags & RDS_FLAG_ACK_REQUIRED) {
			rds_stats_inc(s_recv_ack_required);
			state->ack_required = 1;
		}
		rds_inc_put(&ibinc->ii_inc);
	}
}

void rds_ib_recv_cqe_handler(struct rds_ib_connection *ic,
			     struct ib_wc *wc,
			     struct rds_ib_ack_state *state)
{
	struct rds_connection *conn = ic->conn;
	struct rds_ib_recv_work *recv;
	struct rds_ib_device *rds_ibdev = ic->rds_ibdev;

	rdsdebug("wc wr_id 0x%llx status %u (%s) byte_len %u imm_data %u\n",
		 (unsigned long long)wc->wr_id, wc->status,
		 rds_ib_wc_status_str(wc->status), wc->byte_len,
		 be32_to_cpu(wc->ex.imm_data));

	rds_ib_stats_inc(s_ib_rx_cq_event);

	if (rds_ib_srq_enabled) {
		recv = &rds_ibdev->srq->s_recvs[wc->wr_id];
		atomic_dec(&rds_ibdev->srq->s_num_posted);
	} else
		recv = &ic->i_recvs[rds_ib_ring_oldest(&ic->i_recv_ring)];

	ib_dma_unmap_sg(ic->i_cm_id->device, &recv->r_frag->f_sg, 1, DMA_FROM_DEVICE);

	if (wc->status == IB_WC_SUCCESS) {
		if (rds_ib_srq_enabled)
			rds_ib_srq_process_recv(conn, recv, wc->byte_len, state);
		else
			rds_ib_process_recv(conn, recv, wc->byte_len, state);
	} else {
		/* We expect errors as the qp is drained during shutdown */
		if (rds_conn_up(conn) || rds_conn_connecting(conn)) {
			conn->c_drop_source = DR_IB_RECV_COMP_ERR;
			rds_ib_conn_error(conn, "recv completion "
					"<%pI4,%pI4,%d> had status %u "
					"vendor_err 0x%x, disconnecting and "
					"reconnecting\n",
					&conn->c_laddr,
					&conn->c_faddr,
					conn->c_tos,
					wc->status, wc->vendor_err);
			rds_rtd(RDS_RTD_ERR, "status %u => %s\n", wc->status,
				rds_ib_wc_status_str(wc->status));
		}
	}

	/*
	 * rds_ib_process_recv() doesn't always consume the frag, and
	 * we might not have called it at all if the wc didn't indicate
	 * success.  We already unmapped the frag's pages, though, and the
	 * following rds_ib_ring_free() call tells the refill path that it
	 * will not find an allocated frag here.  Make sure we keep that
	 * promise by freeing a frag that's still on the ring.
	 */
	if (recv->r_frag) {
		rds_ib_frag_free(ic, recv->r_frag);
		recv->r_frag = NULL;
	}

	if (!rds_ib_srq_enabled) {
		rds_ib_ring_free(&ic->i_recv_ring, 1);
		rds_ib_recv_refill(conn, 0, GFP_NOWAIT);
	} else {
		recv->r_ic = ic;
		recv->r_posted = 0;
	}
}

void rds_ib_srq_refill(struct work_struct *work)
{
	struct rds_ib_srq *srq = container_of(work, struct rds_ib_srq, s_refill_w.work);
	struct rds_ib_recv_work *prv = NULL, *cur = NULL, *tmp;
	struct ib_recv_wr *bad_wr;
	int i, refills = 0, total_refills = 0;

	if (!test_bit(0, &srq->s_refill_gate))
		return;

	rds_ib_stats_inc(s_ib_srq_refills);

	for (i = 0; i < srq->s_n_wr; i++) {
		tmp = &srq->s_recvs[i];
		if (tmp->r_posted)
			continue;

		if (rds_ib_srq_refill_one(srq, tmp->r_ic, tmp, GFP_NOWAIT)) {
			printk(KERN_ERR "rds_ib_srq_refill_one failed\n");
			break;
		}
		cur = tmp;

		if (!prv) {
			prv = cur;
			prv->r_wr.next = NULL;
		} else {
			cur->r_wr.next = &prv->r_wr;
			prv = cur;
		}
		cur->r_posted = 1;

		total_refills++;
		if (++refills == RDS_IB_SRQ_POST_BATCH_COUNT) {
			if (ib_post_srq_recv(srq->s_srq, &cur->r_wr, &bad_wr)) {
				struct ib_recv_wr *wr;
				struct rds_ib_recv_work *recv;

				for (wr = &cur->r_wr; wr; wr = wr->next) {
					recv = container_of(wr, struct rds_ib_recv_work, r_wr);
					rds_ib_srq_clear_one(srq, recv);
				}
				printk(KERN_ERR "ib_post_srq_recv failed\n");
				goto out;
			}
			atomic_add(refills, &srq->s_num_posted);
			prv = NULL;
			refills = 0;
			cur = NULL;
		}
	}
	if (cur) {
		if (ib_post_srq_recv(srq->s_srq, &cur->r_wr, &bad_wr)) {
			struct ib_recv_wr *wr;
			struct rds_ib_recv_work *recv;

			for (wr = &cur->r_wr; wr; wr = wr->next) {
				recv = container_of(wr, struct rds_ib_recv_work, r_wr);
				rds_ib_srq_clear_one(srq, recv);
			}
			printk(KERN_ERR "ib_post_srq_recv failed\n");
			goto out;
		}
		atomic_add(refills, &srq->s_num_posted);
	}

	if (!total_refills)
		rds_ib_stats_inc(s_ib_srq_empty_refills);
out:
	clear_bit(0, &srq->s_refill_gate);
}

int rds_ib_srq_prefill_ring(struct rds_ib_device *rds_ibdev)
{
	struct rds_ib_recv_work *recv;
	struct ib_recv_wr *bad_wr;
	u32 i;
	int ret;

	for (i = 0, recv = rds_ibdev->srq->s_recvs;
		i < rds_ibdev->srq->s_n_wr; i++, recv++) {
		recv->r_wr.next = NULL;
		recv->r_wr.wr_id = i;
		recv->r_wr.sg_list = recv->r_sge;
		recv->r_wr.num_sge = RDS_IB_RECV_SGE;
		recv->r_ibinc = NULL;
		recv->r_frag = NULL;
		recv->r_ic = NULL;

		if (rds_ib_srq_prefill_one(rds_ibdev, recv, 1))
			return 1;

		ret = ib_post_srq_recv(rds_ibdev->srq->s_srq,
				&recv->r_wr, &bad_wr);
		if (ret) {
			printk(KERN_WARNING "RDS: ib_post_srq_recv failed %d\n", ret);
			return 1;
		}
		atomic_inc(&rds_ibdev->srq->s_num_posted);
		recv->r_posted = 1;
	}
	return 0;
}

static void rds_ib_srq_clear_ring(struct rds_ib_device *rds_ibdev)
{
	u32 i;
	struct rds_ib_recv_work *recv;

	for (i = 0, recv = rds_ibdev->srq->s_recvs;
		i < rds_ibdev->srq->s_n_wr; i++, recv++)
			rds_ib_srq_clear_one(rds_ibdev->srq, recv);
}


int rds_ib_recv(struct rds_connection *conn)
{
	struct rds_ib_connection *ic = conn->c_transport_data;
	int ret = 0;

	rdsdebug("conn %p\n", conn);
	if (!rds_ib_srq_enabled && rds_conn_up(conn)) {
		rds_ib_attempt_ack(ic);
		rds_ib_recv_refill(conn, 0, GFP_KERNEL);
	}

	return ret;
}

int rds_ib_recv_init(void)
{
	struct sysinfo si;

	/* Default to 30% of all available RAM for recv memory */
	si_meminfo(&si);
	rds_ib_sysctl_max_recv_allocation = si.totalram / 3 * PAGE_SIZE / RDS_FRAG_SIZE;

	rds_ib_incoming_slab = kmem_cache_create("rds_ib_incoming",
					sizeof(struct rds_ib_incoming),
					0, SLAB_HWCACHE_ALIGN, NULL);
	if (!rds_ib_incoming_slab)
		return -ENOMEM;

	rds_ib_frag_slab = kmem_cache_create("rds_ib_frag",
					sizeof(struct rds_page_frag),
					0, SLAB_HWCACHE_ALIGN, NULL);
	if (!rds_ib_frag_slab) {
		kmem_cache_destroy(rds_ib_incoming_slab);
		rds_ib_incoming_slab = NULL;
		return -ENOMEM;
	}
	return 0;
}

void rds_ib_recv_exit(void)
{
	kmem_cache_destroy(rds_ib_incoming_slab);
	kmem_cache_destroy(rds_ib_frag_slab);
}

void rds_ib_srq_rearm(struct work_struct *work)
{
	struct rds_ib_srq *srq = container_of(work, struct rds_ib_srq, s_rearm_w.work);
	struct ib_srq_attr srq_attr;

	srq_attr.srq_limit = rds_ib_srq_lwm_refill;
	if (ib_modify_srq(srq->s_srq, &srq_attr, IB_SRQ_LIMIT)) {
		printk(KERN_ERR "RDS: ib_modify_srq failed\n");
		return;
	}
}

static void rds_ib_srq_event(struct ib_event *event,
				void *ctx)
{
	struct rds_ib_device *rds_ibdev = ctx;

	switch (event->event) {
	case IB_EVENT_SRQ_ERR:
		printk(KERN_ERR "RDS: event IB_EVENT_SRQ_ERR unhandled\n");
		break;
	case IB_EVENT_SRQ_LIMIT_REACHED:
		rds_ib_stats_inc(s_ib_srq_lows);
		queue_delayed_work(rds_wq, &rds_ibdev->srq->s_rearm_w, HZ);

		if (!test_and_set_bit(0, &rds_ibdev->srq->s_refill_gate))
			queue_delayed_work(rds_wq, &rds_ibdev->srq->s_refill_w, 0);
		break;
	default:
		break;
	}
}

/* Setup SRQ for a device */
int rds_ib_srq_init(struct rds_ib_device *rds_ibdev)
{
	struct ib_srq_init_attr srq_init_attr = {
		rds_ib_srq_event,
		(void *)rds_ibdev,
		.attr = {
			.max_wr = rds_ib_srq_max_wr - 1,
			.max_sge = rds_ibdev->max_sge
		}
	};

	/* This is called in two paths
	 * 1) during insmod of rds_rdma module
	 * 2) rds_rdma module is ready, a new ib_device added to kernel
	 */
	if (!rds_ib_srq_enabled)
		return 0;

	pr_warn("RDS/IB: SRQ support is experimental\n");

	rds_ibdev->srq = kmalloc(sizeof(struct rds_ib_srq), GFP_KERNEL);
	if (!rds_ibdev->srq) {
		pr_warn("RDS: allocating srq failed\n");
		return 1;
	}

	rds_ibdev->srq->rds_ibdev = rds_ibdev;

	rds_ibdev->srq->s_n_wr =  rds_ib_srq_max_wr - 1;
	rds_ibdev->srq->s_srq = ib_create_srq(rds_ibdev->pd,
				&srq_init_attr);

	if (IS_ERR(rds_ibdev->srq->s_srq)) {
		printk(KERN_WARNING "RDS: ib_create_srq failed %ld\n",
			PTR_ERR(rds_ibdev->srq->s_srq));
		return 1;
	}

	rds_ibdev->srq->s_recv_hdrs = ib_dma_alloc_coherent(rds_ibdev->dev,
				rds_ibdev->srq->s_n_wr *
				sizeof(struct rds_header),
				&rds_ibdev->srq->s_recv_hdrs_dma, GFP_KERNEL);
	if (!rds_ibdev->srq->s_recv_hdrs) {
		printk(KERN_WARNING "ib_dma_alloc_coherent failed\n");
		return 1;
	}

	rds_ibdev->srq->s_recvs = vmalloc(rds_ibdev->srq->s_n_wr *
				sizeof(struct rds_ib_recv_work));

	if (!rds_ibdev->srq->s_recvs) {
		printk(KERN_WARNING "RDS: vmalloc failed\n");
		return 1;
	}

	memset(rds_ibdev->srq->s_recvs, 0, rds_ibdev->srq->s_n_wr *
				sizeof(struct rds_ib_recv_work));

	atomic_set(&rds_ibdev->srq->s_num_posted, 0);
	clear_bit(0, &rds_ibdev->srq->s_refill_gate);

	if (rds_ib_srq_prefill_ring(rds_ibdev))
		return 1;

	INIT_DELAYED_WORK(&rds_ibdev->srq->s_refill_w, rds_ib_srq_refill);

	INIT_DELAYED_WORK(&rds_ibdev->srq->s_rearm_w, rds_ib_srq_rearm);

	queue_delayed_work(rds_wq, &rds_ibdev->srq->s_rearm_w, 0);

	return 0;
}

void rds_ib_srq_exit(struct rds_ib_device *rds_ibdev)
{
	int ret;

	ret = ib_destroy_srq(rds_ibdev->srq->s_srq);
	if (ret)
		printk(KERN_WARNING "RDS: ib_destroy_srq failed %d\n", ret);
	rds_ibdev->srq->s_srq = NULL;

	if (rds_ibdev->srq->s_recv_hdrs)
		ib_dma_free_coherent(rds_ibdev->dev,
				rds_ibdev->srq->s_n_wr *
				sizeof(struct rds_header),
				rds_ibdev->srq->s_recv_hdrs,
				rds_ibdev->srq->s_recv_hdrs_dma);

	rds_ib_srq_clear_ring(rds_ibdev);
	vfree(rds_ibdev->srq->s_recvs);
	rds_ibdev->srq->s_recvs = NULL;
}

