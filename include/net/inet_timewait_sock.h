/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for a generic INET TIMEWAIT sock
 *
 *		From code originally in net/tcp.h
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _INET_TIMEWAIT_SOCK_
#define _INET_TIMEWAIT_SOCK_


#include <linux/kmemcheck.h>
#include <linux/list.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/workqueue.h>

#include <net/inet_sock.h>
#include <net/sock.h>
#include <net/tcp_states.h>
#include <net/timewait_sock.h>

#include <linux/atomic.h>

struct inet_hashinfo;

struct inet_timewait_death_row {
	atomic_t		tw_count;

	struct inet_hashinfo 	*hashinfo ____cacheline_aligned_in_smp;
	int			sysctl_tw_recycle;
	int			sysctl_max_tw_buckets;
};

struct inet_bind_bucket;

/*
 * This is a TIME_WAIT sock. It works around the memory consumption
 * problems of sockets in such a state on heavily loaded servers, but
 * without violating the protocol specification.
 */
struct inet_timewait_sock {
	/*
	 * Now struct sock also uses sock_common, so please just
	 * don't add nothing before this first member (__tw_common) --acme
	 */
	struct sock_common	__tw_common;
#define tw_family		__tw_common.skc_family
#define tw_state		__tw_common.skc_state
#define tw_reuse		__tw_common.skc_reuse
#define tw_ipv6only		__tw_common.skc_ipv6only
#define tw_bound_dev_if		__tw_common.skc_bound_dev_if
#define tw_node			__tw_common.skc_nulls_node
#define tw_bind_node		__tw_common.skc_bind_node
#define tw_refcnt		__tw_common.skc_refcnt
#define tw_hash			__tw_common.skc_hash
#define tw_prot			__tw_common.skc_prot
#define tw_net			__tw_common.skc_net
#define tw_daddr        	__tw_common.skc_daddr
#define tw_v6_daddr		__tw_common.skc_v6_daddr
#define tw_rcv_saddr    	__tw_common.skc_rcv_saddr
#define tw_v6_rcv_saddr    	__tw_common.skc_v6_rcv_saddr
#define tw_dport		__tw_common.skc_dport
#define tw_num			__tw_common.skc_num
#define tw_cookie		__tw_common.skc_cookie

	int			tw_timeout;
	volatile unsigned char	tw_substate;
	unsigned char		tw_rcv_wscale;

	/* Socket demultiplex comparisons on incoming packets. */
	/* these three are in inet_sock */
	__be16			tw_sport;
	kmemcheck_bitfield_begin(flags);
	/* And these are ours. */
	unsigned int		tw_kill		: 1,
				tw_transparent  : 1,
				tw_flowlabel	: 20,
				tw_pad		: 2,	/* 2 bits hole */
				tw_tos		: 8;
	kmemcheck_bitfield_end(flags);
	struct timer_list	tw_timer;
	struct inet_bind_bucket	*tw_tb;
	struct inet_timewait_death_row *tw_dr;
};
#define tw_tclass tw_tos

static inline struct inet_timewait_sock *inet_twsk(const struct sock *sk)
{
	return (struct inet_timewait_sock *)sk;
}

void inet_twsk_free(struct inet_timewait_sock *tw);
void inet_twsk_put(struct inet_timewait_sock *tw);

int inet_twsk_unhash(struct inet_timewait_sock *tw);

int inet_twsk_bind_unhash(struct inet_timewait_sock *tw,
			  struct inet_hashinfo *hashinfo);

struct inet_timewait_sock *inet_twsk_alloc(const struct sock *sk,
					   struct inet_timewait_death_row *dr,
					   const int state);

void __inet_twsk_hashdance(struct inet_timewait_sock *tw, struct sock *sk,
			   struct inet_hashinfo *hashinfo);

void __inet_twsk_schedule(struct inet_timewait_sock *tw, int timeo,
			  bool rearm);

static void inline inet_twsk_schedule(struct inet_timewait_sock *tw, int timeo)
{
	__inet_twsk_schedule(tw, timeo, false);
}

static void inline inet_twsk_reschedule(struct inet_timewait_sock *tw, int timeo)
{
	__inet_twsk_schedule(tw, timeo, true);
}

void inet_twsk_deschedule(struct inet_timewait_sock *tw);

void inet_twsk_purge(struct inet_hashinfo *hashinfo,
		     struct inet_timewait_death_row *twdr, int family);

static inline
struct net *twsk_net(const struct inet_timewait_sock *twsk)
{
	return read_pnet(&twsk->tw_net);
}

static inline
void twsk_net_set(struct inet_timewait_sock *twsk, struct net *net)
{
	write_pnet(&twsk->tw_net, net);
}
#endif	/* _INET_TIMEWAIT_SOCK_ */