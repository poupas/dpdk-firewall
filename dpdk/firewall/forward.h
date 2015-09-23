/*-
 *   BSD LICENSE
 *
 *   Copyright (c) 2015, SAPO. All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef FORWARD_H_
#define FORWARD_H_

#include <errno.h>

#include <rte_debug.h>
#include <rte_memory.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_ring.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_pci.h>
#include <rte_mbuf.h>
#include <exec-env/rte_kni_common.h>
#include <rte_kni.h>

#include "util.h"
#include "packet.h"
#include "routing.h"

#define uint32_to_char(ip, a, b, c, d) do {\
		*a = (unsigned char)(ip >> 24 & 0xff);\
		*b = (unsigned char)(ip >> 16 & 0xff);\
		*c = (unsigned char)(ip >> 8 & 0xff);\
		*d = (unsigned char)(ip & 0xff);\
	} while (0)

static inline
__attribute__((always_inline))
	void
	     fwd_nic_pkt(struct rte_mbuf *m, struct worker_lc_cfg *lp)
{
	uint32_t n_mbufs, burst;
	int ret;
	uint8_t port;

	if (likely(!(m->udata64 & PKT_META_ROUTED))) {
		struct ether_hdr *eh;
		struct ether_addr *ea;

		eh = rte_pktmbuf_mtod(m, struct ether_hdr *);
		ea = rt_select_gw(m, eh, &lp->rt);
		if (unlikely(lp->rt.gws_ts != cfg.gws_ts)) {
			rt_refresh_gws(&lp->rt);
			ea = rt_select_gw(m, eh, &lp->rt);
		}
		ether_addr_copy(ea, &eh->d_addr);
	}

	port = m->port;

	/* Request the NIC to place the vlan tag if required */
	if (likely((m->udata64 & PKT_META_VLAN_TAG) == 0)) {
		m->ol_flags |= PKT_TX_VLAN_PKT;
	}

	burst = cfg.worker_write_burst_size;
	n_mbufs = lp->obuf[port].n_mbufs;
	lp->obuf[port].array[n_mbufs++] = m;
	if (likely(n_mbufs < burst)) {
		lp->obuf[port].n_mbufs = n_mbufs;
		lp->pending = 1;
		return;
	}
	ret = rte_ring_sp_enqueue_bulk(
	    lp->orings[port],
	    (void **)lp->obuf[port].array,
	    burst);

	if (unlikely(ret == -ENOBUFS)) {
		util_free_mbufs_burst(lp->obuf[port].array, n_mbufs);
	}
	lp->obuf[port].n_mbufs = 0;
	lp->obuf_flush[port] = 0;

}

static inline
__attribute__((always_inline))
	void
	     fwd_ring_pkt(struct rte_mbuf *m, struct worker_lc_cfg *lp,
			   struct wrk_ring *ring)
{
	uint32_t n_mbufs, burst;
	int ret;

	burst = cfg.worker_write_burst_size;
	n_mbufs = ring->obuf.n_mbufs;

	ring->obuf.array[n_mbufs++] = m;
	if (likely(n_mbufs < burst)) {
		ring->obuf.n_mbufs = n_mbufs;
		lp->pending = 1;
		return;
	}

	ret = rte_ring_sp_enqueue_bulk(
	    ring->ring,
	    (void **)ring->obuf.array,
	    burst);

	if (unlikely(ret == -ENOBUFS)) {
		util_free_mbufs_burst(ring->obuf.array, n_mbufs);
	}
	ring->obuf.n_mbufs = 0;
	ring->obuf_flush = 0;
}

static inline
__attribute__((always_inline))
	void
	     fwd_ctrl_pkt(struct rte_mbuf *m, struct worker_lc_cfg *lp)
{
	int i;
	struct wrk_ring *ring;

	i = m->port % lp->n_crings;
	ring = &lp->crings[i];

#ifdef APP_STATS
	lp->crings_pkts[i]++;
#endif

	return fwd_ring_pkt(m, lp, ring);
}

static inline
__attribute__((always_inline))
	void
	     fwd_ol_pkt(struct rte_mbuf *m, struct worker_lc_cfg *lp)
{
	struct wrk_ring *ring;

	ring = &lp->ol_rings[m->port % lp->n_ol_rings];
	return fwd_ring_pkt(m, lp, ring);
}

static inline void
flush_nic_buffers(struct worker_lc_cfg *lp)
{
	uint32_t i;

	for (i = 0; i < MAX_NIC_PORTS; i++) {
		if (unlikely(lp->orings[i] == NULL)) {
			continue;
		}

		if (likely(lp->obuf_flush[i] == 0 ||
		    lp->obuf[i].n_mbufs == 0)) {
			lp->obuf_flush[i] = 1;
			continue;
		}
		util_flush_sp_ring_buffer(lp->orings[i], &lp->obuf[i]);

		lp->obuf_flush[i] = 1;
	}
}

static inline void
flush_ctrl_buffers(struct worker_lc_cfg *lp)
{
	uint32_t n_crings, i;

	n_crings = lp->n_crings;
	for (i = 0; i < n_crings; i++) {
		struct wrk_ring *ring = &lp->crings[i];

		if (likely(ring->obuf_flush == 0 ||
		    ring->obuf.n_mbufs == 0)) {
		    ring->obuf_flush = 1;
		    continue;
		}
		util_flush_sp_ring_buffer(ring->ring, &ring->obuf);
		ring->obuf_flush = 1;
	}
}

static inline void
flush_ol_buffers(struct worker_lc_cfg *lp)
{
	uint32_t n_ol_rings, i;

	n_ol_rings = lp->n_ol_rings;
	for (i = 0; i < n_ol_rings; i++) {
		struct wrk_ring *ring = &lp->ol_rings[i];

		if (likely(ring->obuf_flush == 0 ||
		    ring->obuf.n_mbufs == 0)) {
		    ring->obuf_flush = 1;
		    continue;
		}
		util_flush_sp_ring_buffer(ring->ring, &ring->obuf);
		ring->obuf_flush = 1;
	}
}

#endif	/* FORWARD_H_ */
