/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   Copyright(c) 2015 SAPO. All rights reserved.
 *   All rights reserved.
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
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
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

#include <errno.h>
#include <stdlib.h>

#include <rte_mbuf.h>
#include <stdint.h>
#include <rte_log.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_eth_ctrl.h>
#include <rte_ethdev.h>
#include <rte_common.h>

#include "main.h"
#include "util.h"
#include "runtime.h"
#include "packet.h"

#define FLUSH_TX_PORT(lp, port, n_pkts)					\
	do {								\
		n_pkts = rte_eth_tx_burst(				\
		    port,						\
		    0,							\
		    lp->tx.obuf[port].array,				\
		    (uint16_t)lp->tx.obuf[port].n_mbufs);		\
		    	    	    	    	    	   	   	\
		if (unlikely(n_pkts < lp->tx.obuf[port].n_mbufs)) {	\
			util_free_mbufs_burst(				\
				    lp->tx.obuf[port].array + n_pkts,	\
				    lp->tx.obuf[port].n_mbufs - n_pkts);\
		}							\
		lp->tx.obuf[port].n_mbufs = 0;				\
		lp->tx.obuf_flush[port] = 1;				\
		cfg.ifaces[port].lacp = 0;				\
	} while (0)

static inline
__attribute__((always_inline))
	void
	     send_pkts_to_worker(struct io_lc_cfg *lp, uint32_t worker,
         struct rte_mbuf *m, uint32_t burst)
{
	uint32_t n_mbufs;
	int ret;

	/* Reset packet */
	PKT_INIT(m);

	n_mbufs = lp->rx.obuf[worker].n_mbufs;
	lp->rx.obuf[worker].array[n_mbufs++] = m;
	if (likely(n_mbufs < burst)) {
		lp->rx.obuf[worker].n_mbufs = n_mbufs;
		lp->pending = 1;
		return;
	}
	ret = rte_ring_sp_enqueue_bulk(
	    lp->rx.rings[worker],
	    (void **)lp->rx.obuf[worker].array,
	    n_mbufs);

	if (unlikely(ret == -ENOBUFS)) {
		util_free_mbufs_burst(lp->rx.obuf[worker].array, n_mbufs);
		RTE_LOG(WARNING, USER1,
		    "Could not enqueue %u packets to worker %u!\n",
		    n_mbufs, worker);
	}
#if APP_STATS
	else {
		lp->rx.rings_pkts[worker] += n_mbufs;
	}
#endif

	lp->rx.obuf[worker].n_mbufs = 0;
	lp->rx.obuf_flush[worker] = 0;

}

static inline uint8_t
rx_nic_pkts(struct io_lc_cfg *lp, uint32_t n_workers,
    uint32_t r_burst, uint32_t w_burst)
{
	struct rte_mbuf *m10, *m11, *m20, *m21;
	uint32_t i;
	uint8_t is_active;

	is_active = 0;
	for (i = 0; i < lp->rx.n_nic_queues; i++) {
		uint8_t port = lp->rx.nic_queues[i].port;
		uint16_t queue = lp->rx.nic_queues[i].queue;
		uint32_t n_rx, j;

		n_rx = rte_eth_rx_burst(
		    port,
		    queue,
		    lp->rx.ibuf.array,
		    (uint16_t)r_burst);

		if (unlikely(n_rx == 0)) {
			continue;
		}
		is_active = 1;

#if APP_STATS
		lp->rx.nic_q_pkts[i] += n_rx;
#endif
		m10 = lp->rx.ibuf.array[0];
		m11 = lp->rx.ibuf.array[1];
		m20 = lp->rx.ibuf.array[2];
		m21 = lp->rx.ibuf.array[3];

		IO_RX_PREFETCH0(m20);
		IO_RX_PREFETCH0(m21);

		for (j = 0; j + 3 < n_rx; j += 2) {
			struct rte_mbuf *m00, *m01;
			uint32_t worker0, worker1;

			m00 = m10;
			m01 = m11;

			m10 = m20;
			m11 = m21;

			/* Length of ibuf.array must be > r_burst + 5 */
			m20 = lp->rx.ibuf.array[j + 4];
			m21 = lp->rx.ibuf.array[j + 5];
			IO_RX_PREFETCH0(m20);
			IO_RX_PREFETCH0(m21);

			worker0 = m00->port & (n_workers - 1);
			worker1 = m01->port & (n_workers - 1);
			send_pkts_to_worker(lp, worker0, m00, w_burst);
			send_pkts_to_worker(lp, worker1, m01, w_burst);
		}

		/*
		 * Handle the last 1, 2 (when n_rx is even) or 3 (when n_rx
		 * is odd) packets
		 */
		for (; j < n_rx; j++) {
			struct rte_mbuf *m;
			uint32_t worker;

			m = m10;
			m10 = m11;
			m11 = m20;
			m20 = m21;

			IO_RX_PREFETCH0(m10);

			worker = m->port & (n_workers - 1);
			send_pkts_to_worker(lp, worker, m, w_burst);
		}
	}

	return is_active;
}

static inline void
flush_rx_buffers(struct io_lc_cfg *lp, uint32_t n_workers)
{
	uint32_t worker;

	for (worker = 0; worker < n_workers; worker++) {
		int ret;

		if (likely((lp->rx.obuf_flush[worker] == 0) ||
		    (lp->rx.obuf[worker].n_mbufs == 0))) {
			lp->rx.obuf_flush[worker] = 1;
			continue;
		}
		ret = rte_ring_sp_enqueue_bulk(
		    lp->rx.rings[worker],
		    (void **)lp->rx.obuf[worker].array,
		    lp->rx.obuf[worker].n_mbufs);

		if (unlikely(ret < 0)) {
			util_free_mbufs_burst(lp->rx.obuf[worker].array,
			    lp->rx.obuf[worker].n_mbufs);
		}

		lp->rx.obuf[worker].n_mbufs = 0;
		lp->rx.obuf_flush[worker] = 1;
	}
}

static inline uint8_t
tx_nic_pkts(struct io_lc_cfg *lp, uint32_t n_workers,
    uint32_t r_burst, uint32_t w_burst)
{
	uint32_t i, worker;
	uint8_t is_active;

	is_active = 0;
	for (i = 0; i < lp->tx.n_nic_ports; i++) {
		uint8_t port = lp->tx.nic_ports[i];

		for (worker = 0; worker < n_workers; worker++) {
			uint32_t n_mbufs, n_pkts;

			struct rte_ring *ring = lp->tx.rings[port][worker];

			n_mbufs = lp->tx.obuf[port].n_mbufs;
			n_pkts = rte_ring_sc_dequeue_burst(
			    ring,
			    (void **)&lp->tx.obuf[port].array[n_mbufs],
			    r_burst);

			if (unlikely(n_pkts == 0)) {
				continue;
			}

			is_active = 1;
			n_mbufs += n_pkts;

			if (unlikely(n_mbufs < w_burst)) {
				lp->pending = 1;
				lp->tx.obuf[port].n_mbufs = n_mbufs;
				continue;
			}

			n_pkts = rte_eth_tx_burst(
			    port,
			    0,
			    lp->tx.obuf[port].array,
			    (uint16_t)n_mbufs);
#if APP_STATS
			lp->tx.nic_pkts[port] += n_pkts;
#endif

			if (unlikely(n_pkts < n_mbufs)) {
				util_free_mbufs_burst(
				    lp->tx.obuf[port].array + n_pkts,
				    n_mbufs - n_pkts);
			}
			lp->tx.obuf[port].n_mbufs = 0;
			lp->tx.obuf_flush[port] = 0;
			cfg.ifaces[port].lacp = 0;
		}
		if (cfg.ifaces[port].lacp) {
			uint32_t n_pkts = 0;

			FLUSH_TX_PORT(lp, port, n_pkts);
#ifdef APP_STATS
			lp->tx.nic_pkts[port] += n_pkts;
#endif
		}
	}

	return is_active;
}

static inline void
flush_tx_buffers(struct io_lc_cfg *lp)
{
	uint8_t i;

	for (i = 0; i < lp->tx.n_nic_ports; i++) {
		uint32_t n_pkts;
		uint8_t port;

		n_pkts = 0;
		port = lp->tx.nic_ports[i];

		if (likely((lp->tx.obuf_flush[port] == 0) ||
		    (lp->tx.obuf[port].n_mbufs == 0))) {
			lp->tx.obuf_flush[port] = 1;
			continue;
		}

		FLUSH_TX_PORT(lp, port, n_pkts);
#ifdef APP_STATS
		lp->tx.nic_pkts[port] += n_pkts;
#endif
	}
}

static void
rx_stats(struct io_lc_cfg *lp, uint64_t now)
{
	uint32_t i;

	for (i = 0; i < lp->rx.n_nic_queues; i++) {
		uint64_t pps;

		if (lp->rx.nic_q_pkts[0] == 0) {
			continue;
		}

		pps = lp->rx.nic_q_pkts[i] /
		    (TSC2US(now - lp->stats_tsc) / US_PER_S);
		lp->rx.nic_q_pkts[i] = 0;

		RTE_LOG(
		    DEBUG,
		    USER1,
		    "IO RX queue %" PRIu32 " stats: %" PRIu64 " pps\n", i, pps);
	}

	for (i = 0; i < lp->rx.n_rings; i++) {
		uint64_t pps;

		if (lp->rx.rings_pkts[0] == 0) {
			continue;
		}

		pps = lp->rx.rings_pkts[i] /
		    (TSC2US(now - lp->stats_tsc) / US_PER_S);
		lp->rx.rings_pkts[i] = 0;

		RTE_LOG(
		    DEBUG,
		    USER1,
		    "IO RX worker ring %" PRIu32 " stats: %" PRIu64
		    " pps\n", i, pps);
	}
}

static void
tx_stats(struct io_lc_cfg *lp, uint64_t now)
{
	if (unlikely(lp->tx.n_nic_ports == 0)) {
		return;
	}

	if (now) {
		;
	}
}

void
io_lcore_main_loop(__attribute__((unused)) void *arg)
{
	struct io_lc_cfg *lp;
	uint32_t n_wrks_rx, n_wrks_tx;
	uint32_t lcore, idle, i, stats;
	uint32_t rx_r_burst, rx_w_burst, tx_r_burst, tx_w_burst;

	lcore = rte_lcore_id();
	lp = &cfg.lcores[lcore].io;
	n_wrks_rx = lp->rx.n_rings;
	n_wrks_tx = __builtin_popcount(lp->tx.workers_mask);

	rx_r_burst = cfg.io_rx_read_burst_size;
	rx_w_burst = cfg.io_rx_write_burst_size;
	tx_r_burst = cfg.io_tx_read_burst_size;
	tx_w_burst = cfg.io_tx_write_burst_size;

	tsc_per_us = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S;

	i = 0;
	idle = 0;
	stats = 0;
	for (;;) {
		if (LCORE_IO_FLUSH && unlikely(i == LCORE_IO_FLUSH)) {
			if (lp->pending) {
				if (likely(lp->rx.n_nic_queues > 0)) {
					flush_rx_buffers(lp, n_wrks_rx);
				}
				if (likely(lp->tx.n_nic_ports > 0)) {
					flush_tx_buffers(lp);
				}
				lp->pending = 0;
			}
			i = 0;
		}

		if (APP_STATS && unlikely(stats == APP_STATS)) {
			uint64_t now = now_tsc;
			uint64_t elapsed_us = TSC2US(now - lp->stats_tsc);
			if (elapsed_us > US_PER_S) {
				rx_stats(lp, now);
				tx_stats(lp, now);
				lp->stats_tsc = now;
			}
			stats = 0;
		}

		if (likely(lp->rx.n_nic_queues > 0)) {
			if (rx_nic_pkts(lp, n_wrks_rx, rx_r_burst, rx_w_burst)) {
				idle = 0;
			}
		}
		if (likely(lp->tx.n_nic_ports > 0)) {
			if (tx_nic_pkts(lp, n_wrks_tx, tx_r_burst, tx_w_burst)) {
				idle = 0;
			}
		}
		idle_heuristic(idle);
		if (lp->pending == 0) {
			idle++;
		} else {
			idle = 0;
		}
		i++;
		stats++;
	}
}
