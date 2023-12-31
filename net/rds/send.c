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
#include <net/sock.h>
#include <linux/in.h>
#include <linux/list.h>

#include "rds.h"
#include "tcp.h"

/* When transmitting messages in rds_send_xmit, we need to emerge from
 * time to time and briefly release the CPU. Otherwise the softlock watchdog
 * will kick our shin.
 * Also, it seems fairer to not let one busy connection stall all the
 * others.
 *
 * send_batch_count is the number of times we'll loop in send_xmit. Setting
 * it to 0 will restore the old behavior (where we looped until we had
 * drained the queue).
 */
static int send_batch_count = 1024;
module_param(send_batch_count, int, 0444);
MODULE_PARM_DESC(send_batch_count, " batch factor when working the send queue");

unsigned int rds_async_send_enabled = 0;
module_param(rds_async_send_enabled, int, 0444);
MODULE_PARM_DESC(rds_async_send_enabled, "Set to enable Async Send");

/*
 * Reset the send state.  Callers must ensure that this doesn't race with
 * rds_send_xmit().
 */
void rds_send_reset(struct rds_connection *conn)
{
	struct rds_message *rm, *tmp;
	unsigned long flags;
	int     failed_op = 0;

	if (conn->c_xmit_rm) {
		rm = conn->c_xmit_rm;
		conn->c_xmit_rm = NULL;
		/* Tell the user the RDMA op is no longer mapped by the
		 * transport. This isn't entirely true (it's flushed out
		 * independently) but as the connection is down, there's
		 * no ongoing RDMA to/from that memory */
		if (!rds_async_send_enabled) {
			rds_message_unmapped(rm);
			rds_message_put(rm);
		}
	}

	conn->c_xmit_sg = 0;
	conn->c_xmit_hdr_off = 0;
	conn->c_xmit_data_off = 0;
	conn->c_xmit_atomic_sent = 0;
	conn->c_xmit_rdma_sent = 0;
	conn->c_xmit_data_sent = 0;

	conn->c_map_queued = 0;

	conn->c_unacked_packets = rds_sysctl_max_unacked_packets;
	conn->c_unacked_bytes = rds_sysctl_max_unacked_bytes;

	/* Mark messages as retransmissions, and move them to the send q */
	spin_lock_irqsave(&conn->c_lock, flags);
	list_for_each_entry_safe(rm, tmp, &conn->c_retrans, m_conn_item) {
		set_bit(RDS_MSG_ACK_REQUIRED, &rm->m_flags);
		set_bit(RDS_MSG_RETRANSMITTED, &rm->m_flags);

		/* flush internal HB msgs */
		if ((rm->m_inc.i_hdr.h_flags == RDS_FLAG_HB_PONG) ||
			(rm->m_inc.i_hdr.h_flags == RDS_FLAG_HB_PING))
			set_bit(RDS_MSG_FLUSH, &rm->m_flags);

		/* check for failed op */
		if (rds_async_send_enabled && (rm->rdma.op_active ||
			(rm->data.op_active && rm->data.op_async)))
				failed_op = 1;
	}
	list_splice_init(&conn->c_retrans, &conn->c_send_queue);

	/* if there was a failed op, flush all async ops */
	if (failed_op) {
		list_for_each_entry_safe(rm, tmp, &conn->c_send_queue,
				m_conn_item) {
			if (rm->rdma.op_active) {
				if (rm->rdma.op_notifier) {
					struct rds_notifier *notifier;

					notifier = rm->rdma.op_notifier;
					notifier->n_conn = conn;
					if (test_bit(RDS_MSG_RETRANSMITTED,
						&rm->m_flags) &&
						!notifier->n_status) {
							notifier->n_status =
							RDS_RDMA_REMOTE_ERROR;
					}

					if (!test_bit(RDS_MSG_FLUSH,
						&rm->m_flags)) {
						conn->c_pending_flush++;
					}
				}
				set_bit(RDS_MSG_FLUSH, &rm->m_flags);
			}
			if (rm->data.op_active && rm->data.op_async) {
				if (rm->data.op_notifier) {
					rm->data.op_notifier->n_conn = conn;
					if (!test_bit(RDS_MSG_FLUSH,
						&rm->m_flags)) {
						conn->c_pending_flush++;
					}
				}
				set_bit(RDS_MSG_FLUSH, &rm->m_flags);
			}
		}
	}
	spin_unlock_irqrestore(&conn->c_lock, flags);
}

static int acquire_in_xmit(struct rds_connection *conn)
{
	return test_and_set_bit(RDS_IN_XMIT, &conn->c_flags) == 0;
}

static void release_in_xmit(struct rds_connection *conn)
{
	clear_bit(RDS_IN_XMIT, &conn->c_flags);
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
 * We're making the concious trade-off here to only send one message
 * down the connection at a time.
 *   Pro:
 *      - tx queueing is a simple fifo list
 *      - reassembly is optional and easily done by transports per conn
 *      - no per flow rx lookup at all, straight to the socket
 *	- less per-frag memory and wire overhead
 *   Con:
 *      - queued acks can be delayed behind large messages
 *   Depends:
 *      - small message latency is higher behind queued large messages
 *      - large message latency isn't starved by intervening small sends
 */
int rds_send_xmit(struct rds_connection *conn)
{
	struct rds_message *rm;
	unsigned long flags;
	unsigned int tmp;
	struct scatterlist *sg;
	int ret = 0;
	LIST_HEAD(to_be_dropped);
	int same_rm = 0;
	int batch_count;
	unsigned long send_gen = 0;

restart:

	batch_count = 0;

	/*
	 * sendmsg calls here after having queued its message on the send
	 * queue.  We only have one task feeding the connection at a time.  If
	 * another thread is already feeding the queue then we back off.  This
	 * avoids blocking the caller and trading per-connection data between
	 * caches per message.
	 */
	if (!acquire_in_xmit(conn)) {
		rds_stats_inc(s_send_lock_contention);
		ret = -ENOMEM;
		goto out;
	}

	/*
	 * we record the send generation after doing the xmit acquire.
	 * if someone else manages to jump in and do some work, we'll use
	 * this to avoid a goto restart farther down.
	 *
	 * we don't need a lock because the counter is only incremented
	 * while we have the in_xmit bit held.
	 */
	conn->c_send_gen++;
	send_gen = conn->c_send_gen;

	/*
	 * rds_conn_shutdown() sets the conn state and then tests RDS_IN_XMIT,
	 * we do the opposite to avoid races.
	 */
	if (!rds_conn_up(conn)) {
		release_in_xmit(conn);
		ret = 0;
		goto out;
	}

	if (conn->c_trans->xmit_prepare)
		conn->c_trans->xmit_prepare(conn);

	/*
	 * spin trying to push headers and data down the connection until
	 * the connection doesn't make forward progress.
	 */
	while (1) {

		rm = conn->c_xmit_rm;

		if (!rm) {
			same_rm = 0;
		} else {
			same_rm++;
			if ((same_rm >= 4096) && printk_ratelimit()) {
				printk(KERN_ERR "RDS: Stuck rm\n");
				ret = -EAGAIN;
				break;
			}
		}

		/*
		 * If between sending messages, we can send a pending congestion
		 * map update.
		 */
		if (!rm && test_and_clear_bit(0, &conn->c_map_queued)) {
			rm = rds_cong_update_alloc(conn);
			if (IS_ERR(rm)) {
				ret = PTR_ERR(rm);
				break;
			}
			rm->data.op_active = 1;

			conn->c_xmit_rm = rm;
		}

		/*
		 * If not already working on one, grab the next message.
		 *
		 * c_xmit_rm holds a ref while we're sending this message down
		 * the connction.  We can use this ref while holding the
		 * send_sem.. rds_send_reset() is serialized with it.
		 */
		if (!rm) {
			unsigned int len;

			batch_count++;

			/* we want to process as big a batch as we can, but
			 * we also want to avoid softlockups.  If we've been
			 * through a lot of messages, lets back off and see
			 * if anyone else jumps in
			 */
			if (batch_count >= send_batch_count)
				goto over_batch;

			spin_lock_irqsave(&conn->c_lock, flags);

			if (!list_empty(&conn->c_send_queue)) {
				rm = list_entry(conn->c_send_queue.next,
						struct rds_message,
						m_conn_item);
				rds_message_addref(rm);

				/*
				 * Move the message from the send queue to the retransmit
				 * list right away.
				 */
				list_move_tail(&rm->m_conn_item, &conn->c_retrans);
			}

			spin_unlock_irqrestore(&conn->c_lock, flags);

			if (!rm)
				break;

			/* Unfortunately, the way Infiniband deals with
			 * RDMA to a bad MR key is by moving the entire
			 * queue pair to error state. We cold possibly
			 * recover from that, but right now we drop the
			 * connection. Therefore, we never retransmit messages
			 * with RDMA ops.
			 */

			if (test_bit(RDS_MSG_FLUSH, &rm->m_flags) ||
				(rm->rdma.op_active &&
				test_bit(RDS_MSG_RETRANSMITTED,
					&rm->m_flags))) {
				spin_lock_irqsave(&conn->c_lock, flags);
				if (test_and_clear_bit(RDS_MSG_ON_CONN,
					&rm->m_flags))
					list_move_tail(&rm->m_conn_item,
						&to_be_dropped);
				spin_unlock_irqrestore(&conn->c_lock, flags);
				continue;
			}

			/* Require an ACK every once in a while */
			len = ntohl(rm->m_inc.i_hdr.h_len);
			if (conn->c_unacked_packets == 0
			 || conn->c_unacked_bytes < len) {
				__set_bit(RDS_MSG_ACK_REQUIRED, &rm->m_flags);

				conn->c_unacked_packets = rds_sysctl_max_unacked_packets;
				conn->c_unacked_bytes = rds_sysctl_max_unacked_bytes;
				rds_stats_inc(s_send_ack_required);
			} else {
				conn->c_unacked_bytes -= len;
				conn->c_unacked_packets--;
			}

			conn->c_xmit_rm = rm;
		}

		/* The transport either sends the whole rdma or none of it */
		if (rm->rdma.op_active && !conn->c_xmit_rdma_sent) {
			rm->m_final_op = &rm->rdma;
			/* The transport owns the mapped memory for now.
			 * You can't unmap it while it's on the send queue */
			set_bit(RDS_MSG_MAPPED, &rm->m_flags);
			ret = conn->c_trans->xmit_rdma(conn, &rm->rdma);
			if (ret) {
				clear_bit(RDS_MSG_MAPPED, &rm->m_flags);
				wake_up_interruptible(&rm->m_flush_wait);
				break;
			}
			conn->c_xmit_rdma_sent = 1;

		}

		if (rm->atomic.op_active && !conn->c_xmit_atomic_sent) {
			rm->m_final_op = &rm->atomic;
			/* The transport owns the mapped memory for now.
			 * You can't unmap it while it's on the send queue */
			set_bit(RDS_MSG_MAPPED, &rm->m_flags);
			ret = conn->c_trans->xmit_atomic(conn, &rm->atomic);
			if (ret) {
				clear_bit(RDS_MSG_MAPPED, &rm->m_flags);
				wake_up_interruptible(&rm->m_flush_wait);
				break;
			}
			conn->c_xmit_atomic_sent = 1;

		}

		/*
		 * A number of cases require an RDS header to be sent
		 * even if there is no data.
		 * We permit 0-byte sends; rds-ping depends on this.
		 * However, if there are exclusively attached silent ops,
		 * we skip the hdr/data send, to enable silent operation.
		 */
		if (rm->data.op_nents == 0) {
			int ops_present;
			int all_ops_are_silent = 1;

			ops_present = (rm->atomic.op_active || rm->rdma.op_active);
			if (rm->atomic.op_active && !rm->atomic.op_silent)
				all_ops_are_silent = 0;
			if (rm->rdma.op_active && !rm->rdma.op_silent)
				all_ops_are_silent = 0;

			if (ops_present && all_ops_are_silent
			    && !rm->m_rdma_cookie)
				rm->data.op_active = 0;
		}

		if (rm->data.op_active && !conn->c_xmit_data_sent) {
			rm->m_final_op = &rm->data;
			ret = conn->c_trans->xmit(conn, rm,
						  conn->c_xmit_hdr_off,
						  conn->c_xmit_sg,
						  conn->c_xmit_data_off);
			if (ret <= 0)
				break;

			if (conn->c_xmit_hdr_off < sizeof(struct rds_header)) {
				tmp = min_t(int, ret,
					    sizeof(struct rds_header) -
					    conn->c_xmit_hdr_off);
				conn->c_xmit_hdr_off += tmp;
				ret -= tmp;
			}

			sg = &rm->data.op_sg[conn->c_xmit_sg];
			while (ret) {
				tmp = min_t(int, ret, sg->length -
						      conn->c_xmit_data_off);
				conn->c_xmit_data_off += tmp;
				ret -= tmp;
				if (conn->c_xmit_data_off == sg->length) {
					conn->c_xmit_data_off = 0;
					sg++;
					conn->c_xmit_sg++;
					BUG_ON(ret != 0 &&
					       conn->c_xmit_sg == rm->data.op_nents);
				}
			}

			if (conn->c_xmit_hdr_off == sizeof(struct rds_header) &&
			    (conn->c_xmit_sg == rm->data.op_nents))
				conn->c_xmit_data_sent = 1;
		}

		/*
		 * A rm will only take multiple times through this loop
		 * if there is a data op. Thus, if the data is sent (or there was
		 * none), then we're done with the rm.
		 */
		if (!rm->data.op_active || conn->c_xmit_data_sent) {
			conn->c_xmit_rm = NULL;
			conn->c_xmit_sg = 0;
			conn->c_xmit_hdr_off = 0;
			conn->c_xmit_data_off = 0;
			conn->c_xmit_rdma_sent = 0;
			conn->c_xmit_atomic_sent = 0;
			conn->c_xmit_data_sent = 0;

			rds_message_put(rm);
		}
	}

over_batch:
	if (conn->c_trans->xmit_complete)
		conn->c_trans->xmit_complete(conn);
	release_in_xmit(conn);

	/* Nuke any messages we decided not to retransmit. */
	if (!list_empty(&to_be_dropped)) {
		/* irqs on here, so we can put(), unlike above */
		list_for_each_entry(rm, &to_be_dropped, m_conn_item) {
			if (rds_async_send_enabled && rm->rdma.op_implicit_mr)
				rds_rdma_unuse(rm->m_rs, rds_rdma_cookie_key(rm->m_rdma_cookie), 1);
			rds_message_unmapped(rm);
			rds_message_put(rm);
		}
		rds_send_remove_from_sock(&to_be_dropped, RDS_RDMA_SEND_DROPPED);
	}

	/*
	 * Other senders can queue a message after we last test the send queue
	 * but before we clear RDS_IN_XMIT.  In that case they'd back off and
	 * not try and send their newly queued message.  We need to check the
	 * send queue after having cleared RDS_IN_XMIT so that their message
	 * doesn't get stuck on the send queue.
	 *
	 * If the transport cannot continue (i.e ret != 0), then it must
	 * call us when more room is available, such as from the tx
	 * completion handler.
	 *
	 * We have an extra generation check here so that if someone manages
	 * to jump in after our release_in_xmit, we'll see that they have done
	 * some work and we will skip our goto
	 */
	if (ret == 0) {
		smp_mb();
		if ((test_bit(0, &conn->c_map_queued) ||
		     !list_empty(&conn->c_send_queue)) &&
		    send_gen == conn->c_send_gen) {
			rds_stats_inc(s_send_lock_queue_raced);
			if (batch_count < send_batch_count)
				goto restart;
			queue_delayed_work(rds_wq, &conn->c_send_w, 1);
		}
	}
out:
	return ret;
}
EXPORT_SYMBOL_GPL(rds_send_xmit);

static void rds_send_sndbuf_remove(struct rds_sock *rs, struct rds_message *rm)
{
	u32 len = be32_to_cpu(rm->m_inc.i_hdr.h_len);

	assert_spin_locked(&rs->rs_lock);

	BUG_ON(rs->rs_snd_bytes < len);
	rs->rs_snd_bytes -= len;

	if (rs->rs_snd_bytes == 0)
		rds_stats_inc(s_send_queue_empty);
}

static inline int rds_send_is_acked(struct rds_message *rm, u64 ack,
				    is_acked_func is_acked)
{
	if (is_acked)
		return is_acked(rm, ack);
	return be64_to_cpu(rm->m_inc.i_hdr.h_sequence) <= ack;
}

void rds_asend_complete(struct rds_message *rm, int status)
{
	struct rds_sock *rs = NULL;
	struct rm_data_op *so;
	struct rds_notifier *notifier;
	unsigned long flags;

	spin_lock_irqsave(&rm->m_rs_lock, flags);

	so = &rm->data;
	if (test_bit(RDS_MSG_ON_SOCK, &rm->m_flags) &&
		so->op_active && so->op_notifier && so->op_notify) {
		notifier = so->op_notifier;
		rs = rm->m_rs;
		debug_sock_hold(rds_rs_to_sk(rs));

		notifier->n_status = status;
		if (!status) {
			spin_lock(&rs->rs_lock);
			list_add_tail(&notifier->n_list, &rs->rs_notify_queue);
			spin_unlock(&rs->rs_lock);
			so->op_notifier = NULL;
		}
	}

	spin_unlock_irqrestore(&rm->m_rs_lock, flags);

	if (rs) {
		rds_wake_sk_sleep(rs);
		debug_sock_put(rds_rs_to_sk(rs));
	}
}
EXPORT_SYMBOL_GPL(rds_asend_complete);

/*
 * This is pretty similar to what happens below in the ACK
 * handling code - except that we call here as soon as we get
 * the IB send completion on the RDMA op and the accompanying
 * message.
 */
void rds_rdma_send_complete(struct rds_message *rm, int status)
{
	struct rds_sock *rs = NULL;
	struct rm_rdma_op *ro;
	struct rds_notifier *notifier;
	unsigned long flags;

	spin_lock_irqsave(&rm->m_rs_lock, flags);

	ro = &rm->rdma;
	if (test_bit(RDS_MSG_ON_SOCK, &rm->m_flags) &&
	   ro->op_active && ro->op_notifier && ro->op_notify) {
		notifier = ro->op_notifier;
		rs = rm->m_rs;
		debug_sock_hold(rds_rs_to_sk(rs));

		notifier->n_status = status;

		if (!ro->op_remote_complete) {
			if (!rds_async_send_enabled ||
				(rds_async_send_enabled && !status)) {
				spin_lock(&rs->rs_lock);
				list_add_tail(&notifier->n_list,
					&rs->rs_notify_queue);
				spin_unlock(&rs->rs_lock);
				ro->op_notifier = NULL;
			}
		}
	}

	spin_unlock_irqrestore(&rm->m_rs_lock, flags);

	if (rs) {
		rds_wake_sk_sleep(rs);
		debug_sock_put(rds_rs_to_sk(rs));
	}
}
EXPORT_SYMBOL_GPL(rds_rdma_send_complete);

/*
 * Just like above, except looks at atomic op
 */
void rds_atomic_send_complete(struct rds_message *rm, int status)
{
	struct rds_sock *rs = NULL;
	struct rm_atomic_op *ao;
	struct rds_notifier *notifier;
	unsigned long flags;

	spin_lock_irqsave(&rm->m_rs_lock, flags);

	ao = &rm->atomic;
	if (test_bit(RDS_MSG_ON_SOCK, &rm->m_flags) &&
	    ao->op_active && ao->op_notify && ao->op_notifier) {
		notifier = ao->op_notifier;
		rs = rm->m_rs;
		debug_sock_hold(rds_rs_to_sk(rs));

		notifier->n_status = status;
		if (!rds_async_send_enabled ||
			(rds_async_send_enabled && !status)) {
			spin_lock(&rs->rs_lock);
			list_add_tail(&notifier->n_list,
				&rs->rs_notify_queue);
			spin_unlock(&rs->rs_lock);
			ao->op_notifier = NULL;
		}
	}

	spin_unlock_irqrestore(&rm->m_rs_lock, flags);

	if (rs) {
		rds_wake_sk_sleep(rs);
		debug_sock_put(rds_rs_to_sk(rs));
	}
}
EXPORT_SYMBOL_GPL(rds_atomic_send_complete);

/*
 * This is the same as rds_rdma_send_complete except we
 * don't do any locking - we have all the ingredients (message,
 * socket, socket lock) and can just move the notifier.
 */
static inline void
__rds_send_complete(struct rds_sock *rs, struct rds_message *rm, int status)
{
	struct rm_rdma_op *ro;
	struct rm_atomic_op *ao;
	struct rm_data_op *so;

	ro = &rm->rdma;
	if (ro->op_active && ro->op_notify && ro->op_notifier) {
		ro->op_notifier->n_status = status;
		list_add_tail(&ro->op_notifier->n_list, &rs->rs_notify_queue);
		ro->op_notifier = NULL;
	}

	ao = &rm->atomic;
	if (ao->op_active && ao->op_notify && ao->op_notifier) {
		ao->op_notifier->n_status = status;
		list_add_tail(&ao->op_notifier->n_list, &rs->rs_notify_queue);
		ao->op_notifier = NULL;
	}

	so = &rm->data;
	if (so->op_active && so->op_notifier) {
		so->op_notifier->n_status = status;
		list_add_tail(&so->op_notifier->n_list, &rs->rs_notify_queue);
		so->op_notifier = NULL;
	}

	/* No need to wake the app - caller does this */
}

/*
 * This is called from the IB send completion when we detect
 * a RDMA operation that failed with remote access error.
 * So speed is not an issue here.
 */
struct rds_message *rds_send_get_message(struct rds_connection *conn,
					 struct rm_rdma_op *op)
{
	struct rds_message *rm, *tmp, *found = NULL;
	unsigned long flags;

	spin_lock_irqsave(&conn->c_lock, flags);

	list_for_each_entry_safe(rm, tmp, &conn->c_retrans, m_conn_item) {
		if (&rm->rdma == op) {
			atomic_inc(&rm->m_refcount);
			found = rm;
			goto out;
		}
	}

	list_for_each_entry_safe(rm, tmp, &conn->c_send_queue, m_conn_item) {
		if (&rm->rdma == op) {
			atomic_inc(&rm->m_refcount);
			found = rm;
			break;
		}
	}

out:
	spin_unlock_irqrestore(&conn->c_lock, flags);

	return found;
}
EXPORT_SYMBOL_GPL(rds_send_get_message);

/*
 * This removes messages from the socket's list if they're on it.  The list
 * argument must be private to the caller, we must be able to modify it
 * without locks.  The messages must have a reference held for their
 * position on the list.  This function will drop that reference after
 * removing the messages from the 'messages' list regardless of if it found
 * the messages on the socket list or not.
 */
void rds_send_remove_from_sock(struct list_head *messages, int status)
{
	unsigned long flags;
	struct rds_sock *rs = NULL;
	struct rds_message *rm;

	while (!list_empty(messages)) {
		int was_on_sock = 0;

		rm = list_entry(messages->next, struct rds_message,
				m_conn_item);
		list_del_init(&rm->m_conn_item);

		/*
		 * If we see this flag cleared then we're *sure* that someone
		 * else beat us to removing it from the sock.  If we race
		 * with their flag update we'll get the lock and then really
		 * see that the flag has been cleared.
		 *
		 * The message spinlock makes sure nobody clears rm->m_rs
		 * while we're messing with it. It does not prevent the
		 * message from being removed from the socket, though.
		 */

		spin_lock_irqsave(&rm->m_rs_lock, flags);
		if (!test_bit(RDS_MSG_ON_SOCK, &rm->m_flags))
			goto unlock_and_drop;

		if (rs != rm->m_rs) {
			if (rs) {
				rds_wake_sk_sleep(rs);
				debug_sock_put(rds_rs_to_sk(rs));
			}
			rs = rm->m_rs;
			debug_sock_hold(rds_rs_to_sk(rs));
		}
		spin_lock(&rs->rs_lock);

		if (test_and_clear_bit(RDS_MSG_ON_SOCK, &rm->m_flags)) {
			list_del_init(&rm->m_sock_item);
			rds_send_sndbuf_remove(rs, rm);

			if (rm->rdma.op_active && rm->rdma.op_notifier) {
				struct rm_rdma_op *ro = &rm->rdma;
				struct rds_notifier *notifier;

				if (ro->op_notify || status) {
					notifier = ro->op_notifier;
					list_add_tail(&notifier->n_list,
							&rs->rs_notify_queue);
					if (!notifier->n_status)
						notifier->n_status = status;
				} else
					kfree(rm->rdma.op_notifier);
				rm->rdma.op_notifier = NULL;
			} else if (rm->atomic.op_active && rm->atomic.op_notifier) {
				struct rm_atomic_op *ao = &rm->atomic;
				struct rds_notifier *notifier;

				if (ao->op_notify || status) {
					notifier = ao->op_notifier;
					list_add_tail(&notifier->n_list,
						&rs->rs_notify_queue);
					if (!notifier->n_status)
						notifier->n_status = status;
				} else
					kfree(rm->atomic.op_notifier);
				rm->atomic.op_notifier = NULL;
			} else if (rm->data.op_active && rm->data.op_notifier) {
				struct rm_data_op *so = &rm->data;
				struct rds_notifier *notifier;

				if (so->op_notify || status) {
					notifier = so->op_notifier;
					list_add_tail(&notifier->n_list,
						&rs->rs_notify_queue);
					if (!notifier->n_status)
						notifier->n_status = status;
				} else
					kfree(rm->data.op_notifier);
				rm->data.op_notifier = NULL;
			}

			was_on_sock = 1;
			rm->m_rs = NULL;
		}
		spin_unlock(&rs->rs_lock);

unlock_and_drop:
		spin_unlock_irqrestore(&rm->m_rs_lock, flags);
		rds_message_put(rm);
		if (was_on_sock)
			rds_message_put(rm);
	}

	if (rs) {
		rds_wake_sk_sleep(rs);
		debug_sock_put(rds_rs_to_sk(rs));
	}
}

/*
 * Transports call here when they've determined that the receiver queued
 * messages up to, and including, the given sequence number.  Messages are
 * moved to the retrans queue when rds_send_xmit picks them off the send
 * queue. This means that in the TCP case, the message may not have been
 * assigned the m_ack_seq yet - but that's fine as long as tcp_is_acked
 * checks the RDS_MSG_HAS_ACK_SEQ bit.
 *
 * XXX It's not clear to me how this is safely serialized with socket
 * destruction.  Maybe it should bail if it sees SOCK_DEAD.
 */
void rds_send_drop_acked(struct rds_connection *conn, u64 ack,
			 is_acked_func is_acked)
{
	struct rds_message *rm, *tmp;
	unsigned long flags;
	LIST_HEAD(list);

	spin_lock_irqsave(&conn->c_lock, flags);

	list_for_each_entry_safe(rm, tmp, &conn->c_retrans, m_conn_item) {
		if (!rds_send_is_acked(rm, ack, is_acked))
			break;

		list_move(&rm->m_conn_item, &list);
		clear_bit(RDS_MSG_ON_CONN, &rm->m_flags);
	}

	/* order flag updates with spin locks */
	if (!list_empty(&list))
		smp_mb__after_atomic();

	spin_unlock_irqrestore(&conn->c_lock, flags);

	/* now remove the messages from the sock list as needed */
	rds_send_remove_from_sock(&list, RDS_RDMA_SEND_SUCCESS);
}
EXPORT_SYMBOL_GPL(rds_send_drop_acked);

void rds_send_drop_to(struct rds_sock *rs, struct sockaddr_in *dest)
{
	struct rds_message *rm, *tmp;
	struct rds_connection *conn;
	unsigned long flags;
	LIST_HEAD(list);

	/* get all the messages we're dropping under the rs lock */
	spin_lock_irqsave(&rs->rs_lock, flags);

	list_for_each_entry_safe(rm, tmp, &rs->rs_send_queue, m_sock_item) {
		if (dest && (dest->sin_addr.s_addr != rm->m_daddr ||
			     dest->sin_port != rm->m_inc.i_hdr.h_dport))
			continue;

		list_move(&rm->m_sock_item, &list);
		rds_send_sndbuf_remove(rs, rm);
		clear_bit(RDS_MSG_ON_SOCK, &rm->m_flags);
	}

	/* order flag updates with the rs lock */
	smp_mb__after_atomic();

	spin_unlock_irqrestore(&rs->rs_lock, flags);

	if (list_empty(&list))
		return;

	/* Remove the messages from the conn */
	list_for_each_entry(rm, &list, m_sock_item) {

		conn = rm->m_inc.i_conn;

		spin_lock_irqsave(&conn->c_lock, flags);
		/*
		 * Maybe someone else beat us to removing rm from the conn.
		 * If we race with their flag update we'll get the lock and
		 * then really see that the flag has been cleared.
		 */
		if (!test_and_clear_bit(RDS_MSG_ON_CONN, &rm->m_flags)) {
			spin_unlock_irqrestore(&conn->c_lock, flags);
			continue;
		}
		list_del_init(&rm->m_conn_item);
		spin_unlock_irqrestore(&conn->c_lock, flags);

		/*
		 * Couldn't grab m_rs_lock in top loop (lock ordering),
		 * but we can now.
		 */
		spin_lock_irqsave(&rm->m_rs_lock, flags);

		spin_lock(&rs->rs_lock);
		__rds_send_complete(rs, rm, RDS_RDMA_SEND_CANCELED);
		spin_unlock(&rs->rs_lock);

		rm->m_rs = NULL;
		spin_unlock_irqrestore(&rm->m_rs_lock, flags);

		rds_message_put(rm);
	}

	rds_wake_sk_sleep(rs);

	while (!list_empty(&list)) {
		rm = list_entry(list.next, struct rds_message, m_sock_item);
		list_del_init(&rm->m_sock_item);
		rds_message_wait(rm);

		/*
		 * just in case the code above skipped this message
		 * because RDS_MSG_ON_CONN wasn't set, run it again here
		 * taking m_rs_lock is the only thing that keeps us
		 * from racing with ack processing.
		 */
		spin_lock_irqsave(&rm->m_rs_lock, flags);

		spin_lock(&rs->rs_lock);
		__rds_send_complete(rs, rm, RDS_RDMA_SEND_CANCELED);
		spin_unlock(&rs->rs_lock);

		rm->m_rs = NULL;
		spin_unlock_irqrestore(&rm->m_rs_lock, flags);

		rds_message_put(rm);
	}
}

/*
 * we only want this to fire once so we use the callers 'queued'.  It's
 * possible that another thread can race with us and remove the
 * message from the flow with RDS_CANCEL_SENT_TO.
 */
static int rds_send_queue_rm(struct rds_sock *rs, struct rds_connection *conn,
			     struct rds_message *rm, __be16 sport,
			     __be16 dport, int *queued)
{
	unsigned long flags;
	u32 len;

	if (*queued)
		goto out;

	len = be32_to_cpu(rm->m_inc.i_hdr.h_len);

	/* this is the only place which holds both the socket's rs_lock
	 * and the connection's c_lock */
	spin_lock_irqsave(&rs->rs_lock, flags);

	/*
	 * If there is a little space in sndbuf, we don't queue anything,
	 * and userspace gets -EAGAIN. But poll() indicates there's send
	 * room. This can lead to bad behavior (spinning) if snd_bytes isn't
	 * freed up by incoming acks. So we check the *old* value of
	 * rs_snd_bytes here to allow the last msg to exceed the buffer,
	 * and poll() now knows no more data can be sent.
	 */
	if (rs->rs_snd_bytes < rds_sk_sndbuf(rs)) {
		rs->rs_snd_bytes += len;

		/* let recv side know we are close to send space exhaustion.
		 * This is probably not the optimal way to do it, as this
		 * means we set the flag on *all* messages as soon as our
		 * throughput hits a certain threshold.
		 */
		if (rs->rs_snd_bytes >= rds_sk_sndbuf(rs) / 2)
			__set_bit(RDS_MSG_ACK_REQUIRED, &rm->m_flags);

		list_add_tail(&rm->m_sock_item, &rs->rs_send_queue);
		set_bit(RDS_MSG_ON_SOCK, &rm->m_flags);
		rds_message_addref(rm);
		rm->m_rs = rs;

		/* The code ordering is a little weird, but we're
		   trying to minimize the time we hold c_lock */
		rds_message_populate_header(&rm->m_inc.i_hdr, sport, dport, 0);
		rm->m_inc.i_conn = conn;
		rds_message_addref(rm);

		spin_lock(&conn->c_lock);
		if (conn->c_pending_flush) {
			spin_unlock(&conn->c_lock);
			spin_unlock_irqrestore(&rs->rs_lock, flags);
			goto out;
		}
		rm->m_inc.i_hdr.h_sequence = cpu_to_be64(conn->c_next_tx_seq++);
		list_add_tail(&rm->m_conn_item, &conn->c_send_queue);
		set_bit(RDS_MSG_ON_CONN, &rm->m_flags);

		spin_unlock(&conn->c_lock);

		rdsdebug("queued msg %p len %d, rs %p bytes %d seq %llu\n",
			 rm, len, rs, rs->rs_snd_bytes,
			 (unsigned long long)be64_to_cpu(rm->m_inc.i_hdr.h_sequence));

		*queued = 1;
	}

	spin_unlock_irqrestore(&rs->rs_lock, flags);
out:
	return *queued;
}

/*
 * rds_message is getting to be quite complicated, and we'd like to allocate
 * it all in one go. This figures out how big it needs to be up front.
 */
static int rds_rm_size(struct msghdr *msg, int data_len)
{
	struct cmsghdr *cmsg;
	int size = 0;
	int cmsg_groups = 0;
	int retval;

	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;

		if (cmsg->cmsg_level != SOL_RDS)
			continue;

		switch (cmsg->cmsg_type) {
		case RDS_CMSG_RDMA_ARGS:
			cmsg_groups |= 1;
			retval = rds_rdma_extra_size(CMSG_DATA(cmsg));
			if (retval < 0)
				return retval;
			size += retval;

			break;

		case RDS_CMSG_RDMA_DEST:
		case RDS_CMSG_RDMA_MAP:
		case RDS_CMSG_ASYNC_SEND:
			cmsg_groups |= 2;
			/* these are valid but do no add any size */
			break;

		case RDS_CMSG_ATOMIC_CSWP:
		case RDS_CMSG_ATOMIC_FADD:
			cmsg_groups |= 1;
			size += sizeof(struct scatterlist);
			break;

		default:
			return -EINVAL;
		}

	}

	size += ceil(data_len, PAGE_SIZE) * sizeof(struct scatterlist);

	/* Ensure (DEST, MAP) are never used with (ARGS, ATOMIC) */
	if (cmsg_groups == 3)
		return -EINVAL;

	return size;
}

static int rds_cmsg_asend(struct rds_sock *rs, struct rds_message *rm,
		struct cmsghdr *cmsg)
{
	struct rds_asend_args *args;

	if (!rds_async_send_enabled)
		return -EINVAL;

	if (cmsg->cmsg_len < CMSG_LEN(sizeof(struct rds_asend_args)))
		return -EINVAL;

	args = CMSG_DATA(cmsg);
	rm->data.op_notifier = kzalloc(sizeof(*rm->data.op_notifier), GFP_KERNEL);
	if (!rm->data.op_notifier)
		return -ENOMEM;

	rm->data.op_notify = !!(args->flags & RDS_SEND_NOTIFY_ME);
	rm->data.op_notifier->n_user_token = args->user_token;
	rm->data.op_notifier->n_status = RDS_RDMA_SEND_SUCCESS;
	rm->data.op_async = 1;

	return 0;
}

static int rds_cmsg_send(struct rds_sock *rs, struct rds_message *rm,
			 struct msghdr *msg, int *allocated_mr)
{
	struct cmsghdr *cmsg;
	int ret = 0;

	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;

		if (cmsg->cmsg_level != SOL_RDS)
			continue;

		/* As a side effect, RDMA_DEST and RDMA_MAP will set
		 * rm->rdma.m_rdma_cookie and rm->rdma.m_rdma_mr.
		 */
		switch (cmsg->cmsg_type) {
		case RDS_CMSG_RDMA_ARGS:
			ret = rds_cmsg_rdma_args(rs, rm, cmsg);
			break;

		case RDS_CMSG_RDMA_DEST:
			ret = rds_cmsg_rdma_dest(rs, rm, cmsg);
			break;

		case RDS_CMSG_RDMA_MAP:
			ret = rds_cmsg_rdma_map(rs, rm, cmsg);
			if (!ret)
				*allocated_mr = 1;
			else if (ret == -ENODEV)
				/* Accomodate the get_mr() case which can fail
				 * if connection isn't established yet.
				 */
				ret = -EAGAIN;
			break;
		case RDS_CMSG_ATOMIC_CSWP:
		case RDS_CMSG_ATOMIC_FADD:
			ret = rds_cmsg_atomic(rs, rm, cmsg);
			break;

		case RDS_CMSG_ASYNC_SEND:
			ret = rds_cmsg_asend(rs, rm, cmsg);
			break;

		default:
			return -EINVAL;
		}

		if (ret)
			break;
	}

	return ret;
}

static inline unsigned int rds_rdma_bytes(struct msghdr *msg)
{
	struct rds_rdma_args *args;
	struct cmsghdr *cmsg;
	unsigned int rdma_bytes = 0;

	for_each_cmsghdr(cmsg, msg) {
		if (cmsg->cmsg_type == RDS_CMSG_RDMA_ARGS) {
			args = CMSG_DATA(cmsg);
			rdma_bytes += args->remote_vec.bytes;
		}
	}

	return rdma_bytes;
}

int rds_sendmsg(struct socket *sock, struct msghdr *msg, size_t payload_len)
{
	struct sock *sk = sock->sk;
	struct rds_sock *rs = rds_sk_to_rs(sk);
	struct sockaddr_in *usin = (struct sockaddr_in *)msg->msg_name;
	__be32 daddr;
	__be16 dport;
	struct rds_message *rm = NULL;
	struct rds_connection *conn;
	int ret = 0;
	int queued = 0, allocated_mr = 0;
	int nonblock = msg->msg_flags & MSG_DONTWAIT;
	long timeo = sock_sndtimeo(sk, nonblock);
	size_t total_payload_len = payload_len;
	bool large_page;

	/* Mirror Linux UDP mirror of BSD error message compatibility */
	/* XXX: Perhaps MSG_MORE someday */
	if (msg->msg_flags & ~(MSG_DONTWAIT | MSG_CMSG_COMPAT)) {
		printk(KERN_INFO "msg_flags 0x%08X\n", msg->msg_flags);
		ret = -EOPNOTSUPP;
		goto out;
	}

	if (msg->msg_namelen) {
		/* XXX fail non-unicast destination IPs? */
		if (msg->msg_namelen < sizeof(*usin) || usin->sin_family != AF_INET) {
			ret = -EINVAL;
			goto out;
		}
		daddr = usin->sin_addr.s_addr;
		dport = usin->sin_port;
	} else {
		/* We only care about consistency with ->connect() */
		lock_sock(sk);
		daddr = rs->rs_conn_addr;
		dport = rs->rs_conn_port;
		release_sock(sk);
	}

	lock_sock(sk);
	large_page = rs->rs_large_page;
	if (daddr == 0 || rs->rs_bound_addr == 0) {
		release_sock(sk);
		ret = -ENOTCONN; /* XXX not a great errno */
		goto out;
	}
	release_sock(sk);

	if (payload_len > rds_sk_sndbuf(rs)) {
		ret = -EMSGSIZE;
		goto out;
	}

	/* size of rm including all sgs */
	ret = rds_rm_size(msg, payload_len);
	if (ret < 0)
		goto out;

	rm = rds_message_alloc(ret, GFP_KERNEL);
	if (!rm) {
		ret = -ENOMEM;
		goto out;
	}

	/* Attach data to the rm */
	if (payload_len) {
		rm->data.op_sg = rds_message_alloc_sgs(rm, ceil(payload_len, PAGE_SIZE));
		ret = rds_message_copy_from_user(rm, &msg->msg_iter, GFP_KERNEL,
						 large_page);
		if (ret)
			goto out;
	}
	rm->data.op_active = 1;

	rm->m_daddr = daddr;

	/* For RDMA operation(s), add up rmda bytes to payload to make
	 * sure its within system QoS threshold limits.
	 */
	if (rm->rdma.op_active)
		total_payload_len += rds_rdma_bytes(msg);

	if (rds_check_qos_threshold(rs->rs_tos, total_payload_len)) {
		ret = -EINVAL;
		goto out;
	}

	/* rds_conn_create has a spinlock that runs with IRQ off.
	 * Caching the conn in the socket helps a lot. */
	if (rs->rs_conn && rs->rs_conn->c_faddr == daddr &&
			rs->rs_tos == rs->rs_conn->c_tos)
		conn = rs->rs_conn;
	else {
		conn = rds_conn_create_outgoing(sock_net(sock->sk),
						rs->rs_bound_addr, daddr,
					rs->rs_transport, rs->rs_tos,
					sock->sk->sk_allocation);
		if (IS_ERR(conn)) {
			ret = PTR_ERR(conn);
			goto out;
		}

		if (rs->rs_tos && !conn->c_base_conn) {
			conn->c_base_conn = rds_conn_create_outgoing(
					sock_net(sock->sk),
					rs->rs_bound_addr, daddr,
					rs->rs_transport, 0,
					sock->sk->sk_allocation);
			if (IS_ERR(conn->c_base_conn)) {
				ret = PTR_ERR(conn->c_base_conn);
				goto out;
			}
			rds_rtd(RDS_RTD_CM_EXT, "checking conn %p\n",
				conn->c_base_conn);
			rds_conn_connect_if_down(conn->c_base_conn);
		}
		rs->rs_conn = conn;
	}

	if (conn->c_tos && !rds_conn_up(conn)) {
		if (!rds_conn_up(conn->c_base_conn)) {
			ret = -EAGAIN;
			goto out;
		} else if (conn->c_base_conn->c_version ==
				RDS_PROTOCOL_COMPAT_VERSION) {
			if (!conn->c_reconnect ||
				conn->c_route_to_base)
				conn = conn->c_base_conn;
			else {
				ret = -EAGAIN;
				goto out;
			}
		}
	}

	/* Parse any control messages the user may have included. */
	ret = rds_cmsg_send(rs, rm, msg, &allocated_mr);
	if (ret) {
		/* Trigger connection so that its ready for the next retry */
		if ( ret ==  -EAGAIN)
			rds_conn_connect_if_down(conn);
		goto out;
	}

	if (test_bit(RDS_DESTROY_PENDING, &conn->c_flags)) {
		ret = -EAGAIN;
		goto out;
	}

	/* Not accepting new sends until all the failed ops have been reaped */
	if (rds_async_send_enabled && conn->c_pending_flush) {
		ret = -EAGAIN;
		goto out;
	}

	if (rm->rdma.op_active && !conn->c_trans->xmit_rdma) {
		if (printk_ratelimit())
			printk(KERN_NOTICE "rdma_op %p conn xmit_rdma %p\n",
			       &rm->rdma, conn->c_trans->xmit_rdma);
		ret = -EOPNOTSUPP;
		goto out;
	}

	if (rm->atomic.op_active && !conn->c_trans->xmit_atomic) {
		if (printk_ratelimit())
			printk(KERN_NOTICE "atomic_op %p conn xmit_atomic %p\n",
			       &rm->atomic, conn->c_trans->xmit_atomic);
		ret = -EOPNOTSUPP;
		goto out;
	}

	if (rds_conn_state(conn) == RDS_CONN_DOWN)
		rds_rtd(RDS_RTD_CM_EXT, "checking conn in down state %p\n",
			conn);
	rds_conn_connect_if_down(conn);

	ret = rds_cong_wait(conn->c_fcong, dport, nonblock, rs);
	if (ret) {
		rs->rs_seen_congestion = 1;
		goto out;
	}

	if (conn->c_rdsinfo_pending) {
		ret = -EAGAIN;
		goto out;
	}

	while (!rds_send_queue_rm(rs, conn, rm, rs->rs_bound_port,
				  dport, &queued)) {
		rds_stats_inc(s_send_queue_full);

		if (nonblock) {
			ret = -EAGAIN;
			goto out;
		}
		if (conn->c_pending_flush) {
			ret = -EAGAIN;
			goto out;
		}

		timeo = wait_event_interruptible_timeout(*sk_sleep(sk),
					rds_send_queue_rm(rs, conn, rm,
							  rs->rs_bound_port,
							  dport,
							  &queued),
					timeo);
		rdsdebug("sendmsg woke queued %d timeo %ld\n", queued, timeo);
		if (timeo > 0 || timeo == MAX_SCHEDULE_TIMEOUT)
			continue;

		ret = timeo;
		if (ret == 0)
			ret = -ETIMEDOUT;
		goto out;
	}

	/*
	 * By now we've committed to the send.  We reuse rds_send_worker()
	 * to retry sends in the rds thread if the transport asks us to.
	 */
	rds_stats_inc(s_send_queued);

	ret = rds_send_xmit(conn);
	if (ret == -ENOMEM || ret == -EAGAIN)
		queue_delayed_work(rds_wq, &conn->c_send_w, 1);


	rds_message_put(rm);
	return payload_len;

out:
	/* If the user included a RDMA_MAP cmsg, we allocated a MR on the fly.
	 * If the sendmsg goes through, we keep the MR. If it fails with EAGAIN
	 * or in any other way, we need to destroy the MR again */
	if (allocated_mr)
		rds_rdma_unuse(rs, rds_rdma_cookie_key(rm->m_rdma_cookie), 1);

	if (rm)
		rds_message_put(rm);
	return ret;
}

/* this function and rds_sendmsg can likely be folded together into a single function that understand to package
 * up a message for transmission either from the user or from an internal source.
 *
 * Also there is potentially a need to allow either for a retry of the send attempt if we are at a high enough level
 * in the stack, or for only a single shot attempt for the send if we are low enough in the stack that we cannot afford
 * to sleep or block forever.
 *
 * At present this form of the code will only ever do a single shot at the send and it assumes that the source is internal
 */

int rds_send_internal(struct rds_connection *conn, struct rds_sock *rs,
		      struct sk_buff *skb, gfp_t gfp)
{
	struct rds_nf_hdr *dst;
	struct rds_message *rm = NULL;
	struct scatterlist *sg;
	skb_frag_t *frags;
	int ret = 0;
	int queued = 0;
	int i;

	/* pull out the destination info */
	dst = rds_nf_hdr_dst(skb);

	/* size of rm including all sgs */
	ret = ceil(skb->len, PAGE_SIZE) * sizeof(struct scatterlist);
	if (ret < 0)
		goto out;

	/* create ourselves a new message to send out the data */
	rm = rds_message_alloc(ret, gfp);
	if (!rm) {
		rds_rtd(RDS_RTD_ERR, "failed to allocate resp message rs %p",
			rs);
		ret = -ENOMEM;
		goto out;
	}

	/* Attach data to the rm */
	if (skb->len) {
		/* innitialize the segments we need to use */
		rm->data.op_sg = rds_message_alloc_sgs(rm, ceil(skb->len, PAGE_SIZE));

		/* copy out all the pages from the skb */
		for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
			/* one to one mapping from skb info to rm info */
			frags = &skb_shinfo(skb)->frags[i];
			sg    = &rm->data.op_sg[i];

			/* just save the pieces directly */
			sg_set_page(sg, frags->page.p, frags->size, frags->page_offset);

			/* and take an extra reference on the page */
			get_page(frags->page.p);
		}

		/* finalization of the pieces of the message */
		rm->m_inc.i_hdr.h_len = cpu_to_be32(skb->len);
		rm->data.op_nents     = skb_shinfo(skb)->nr_frags;
	}

	rdsdebug("Created send rm %p, nents %d, len %d, skbLen %d\n",
		 rm, rm->data.op_nents, be32_to_cpu(rm->m_inc.i_hdr.h_len), skb->len);

	/* initializes all the subpieces of the message */
	rm->data.op_active = 1;
	rm->m_daddr = dst->daddr;

	if (rm->rdma.op_active && !conn->c_trans->xmit_rdma) {
		if (printk_ratelimit())
			printk(KERN_NOTICE "rdma_op %p conn xmit_rdma %p\n",
			       &rm->rdma, conn->c_trans->xmit_rdma);
		ret = -EOPNOTSUPP;
		goto out;
	}

	if (rm->atomic.op_active && !conn->c_trans->xmit_atomic) {
		if (printk_ratelimit())
			printk(KERN_NOTICE "atomic_op %p conn xmit_atomic %p\n",
			       &rm->atomic, conn->c_trans->xmit_atomic);
		ret = -EOPNOTSUPP;
		goto out;
	}

	/* retry the connection if it hasn't actually been made */
	rds_rtd(RDS_RTD_CM_EXT, "checking conn %p\n", conn);
	rds_conn_connect_if_down(conn);

	/* simple congestion check */
	ret = rds_cong_wait(conn->c_fcong, dst->dport, 1, rs);
	if (ret) {
		rs->rs_seen_congestion = 1;
		goto out;
	}

	/* only take a single pass */
	if (!rds_send_queue_rm(rs, conn, rm, rs->rs_bound_port,
			       dst->dport, &queued)) {
		rds_rtd(RDS_RTD_SND, "cannot block on internal send rs %p", rs);
		rds_stats_inc(s_send_queue_full);

		/* force a requeue of the work for later */
		queue_delayed_work(rds_wq, &conn->c_send_w, 1);

		ret = -EAGAIN;
		goto out;
	}

	/*
	 * By now we've committed to the send.  We reuse rds_send_worker()
	 * to retry sends in the rds thread if the transport asks us to.
	 */
	rds_stats_inc(s_send_queued);

	/* always hand the send off to the worker thread */
	queue_delayed_work(rds_wq, &conn->c_send_w, 0);

	rdsdebug("message sent for rs %p, conn %p, len %d, %u.%u.%u.%u : %u -> %u.%u.%u.%u : %u\n",
		 rs, conn, skb->len, NIPQUAD(dst->saddr), dst->sport, NIPQUAD(dst->daddr), dst->dport);
	ret = skb->len;

out:
	/* on error free up page references but don't allow the pages to be freed */
	if (ret < 0 && rm) {
		for (i = 0; i < rm->data.op_nents; i++) {
			sg = &rm->data.op_sg[i];
			put_page(sg_page(sg));
			sg_set_page(sg, NULL, 0, 0);
		}
		rm->data.op_nents = 0;
	}

	if (rm)
		rds_message_put(rm);
	return ret;
}

/*
 * Reply to a ping packet.
 */
int
rds_send_pong(struct rds_connection *conn, __be16 dport)
{
	struct rds_message *rm;
	unsigned long flags;
	int ret = 0;

	rm = rds_message_alloc(0, GFP_ATOMIC);
	if (!rm) {
		ret = -ENOMEM;
		goto out;
	}

	rm->m_daddr = conn->c_faddr;
	rm->data.op_active = 1;

	rds_rtd(RDS_RTD_CM_EXT, "checking conn %p\n", conn);
	rds_conn_connect_if_down(conn);

	ret = rds_cong_wait(conn->c_fcong, dport, 1, NULL);
	if (ret)
		goto out;

	spin_lock_irqsave(&conn->c_lock, flags);
	list_add_tail(&rm->m_conn_item, &conn->c_send_queue);
	set_bit(RDS_MSG_ON_CONN, &rm->m_flags);
	rds_message_addref(rm);
	rm->m_inc.i_conn = conn;

	rds_message_populate_header(&rm->m_inc.i_hdr, 0, dport,
				    conn->c_next_tx_seq);
	conn->c_next_tx_seq++;
	spin_unlock_irqrestore(&conn->c_lock, flags);

	rds_stats_inc(s_send_queued);
	rds_stats_inc(s_send_pong);

	if (!test_bit(RDS_LL_SEND_FULL, &conn->c_flags))
		queue_delayed_work(rds_wq, &conn->c_send_w, 0);

	rds_message_put(rm);
	return 0;

out:
	if (rm)
		rds_message_put(rm);
	return ret;
}

int
rds_send_hb(struct rds_connection *conn, int response)
{
	struct rds_message *rm;
	unsigned long flags;
	int ret = 0;

	if (conn->c_trans->t_type == RDS_TRANS_TCP)
		return 0;

	rm = rds_message_alloc(0, GFP_ATOMIC);
	if (!rm)
		return -ENOMEM;

	rm->m_daddr = conn->c_faddr;
	rm->data.op_active = 1;

	spin_lock_irqsave(&conn->c_lock, flags);
	list_add_tail(&rm->m_conn_item, &conn->c_send_queue);
	set_bit(RDS_MSG_ON_CONN, &rm->m_flags);
	rds_message_addref(rm);
	rm->m_inc.i_conn = conn;

	rds_message_populate_header(&rm->m_inc.i_hdr, 0, 0,
				conn->c_next_tx_seq);

	if (response)
		rm->m_inc.i_hdr.h_flags |= RDS_FLAG_HB_PONG;
	else
		rm->m_inc.i_hdr.h_flags |= RDS_FLAG_HB_PING;

	rm->m_inc.i_hdr.h_flags |= RDS_FLAG_ACK_REQUIRED;

	conn->c_next_tx_seq++;
	spin_unlock_irqrestore(&conn->c_lock, flags);

	ret = rds_send_xmit(conn);
	if (ret == -ENOMEM || ret == -EAGAIN)
		queue_delayed_work(rds_wq, &conn->c_send_w, 1);

	rds_message_put(rm);
	return 0;
}

void rds_route_to_base(struct rds_connection *conn)
{
	struct rds_message *rm, *tmp;
	struct rds_connection *base_conn = conn->c_base_conn;
	unsigned long flags;

	BUG_ON(!conn->c_tos || rds_conn_up(conn) || !base_conn ||
		!list_empty(&conn->c_retrans));

	spin_lock_irqsave(&base_conn->c_lock, flags);
	list_for_each_entry_safe(rm, tmp, &conn->c_send_queue, m_conn_item) {
		list_del_init(&rm->m_conn_item);
		rm->m_inc.i_conn = base_conn;
		rm->m_inc.i_hdr.h_sequence =
			cpu_to_be64(base_conn->c_next_tx_seq++);
		list_add_tail(&rm->m_conn_item, &base_conn->c_send_queue);
	}
	spin_unlock_irqrestore(&base_conn->c_lock, flags);
	conn->c_route_to_base = 1;
	queue_delayed_work(rds_wq, &base_conn->c_send_w, 0);
}
