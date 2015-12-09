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

#ifndef RUNTIME_H_
#define RUNTIME_H_

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
#include <rte_cycles.h>
#include <rte_log.h>

#include <urcu-qsbr.h>

#include "zone.h"

#ifndef LCORE_IO_FLUSH
#define LCORE_IO_FLUSH 1000
//#define LCORE_IO_FLUSH 1000000
#endif

#ifndef LCORE_WORKER_FLUSH
#define LCORE_WORKER_FLUSH 1000
//#define LCORE_WORKER_FLUSH 1000000
#endif

#ifndef LCORE_WORKER_TASKS
#define LCORE_WORKER_TASKS 1000000
//#define LCORE_WORKER_TASKS 1000000
#endif

#ifndef APP_STATS
#define APP_STATS 1000000
#endif

#ifndef LCORE_WORKER_FLUSH_US
#define LCORE_WORKER_FLUSH_US 100	/* Drain queues every 100
					 * microseconds */
#endif

#ifndef LCORE_WORKER_TASKS_US
#define LCORE_WORKER_TASKS_US 5 * US_PER_S	/* Perform tasks every 5
						 * seconds */
#endif

#ifndef LCORE_CTRL_TASKS_US
#define LCORE_CTRL_TASKS_US 1 * US_PER_S
#endif

#define IO_RX_DROP_ALL_PACKETS 0
#define WORKER_DROP_ALL_PACKETS 0
#define IO_TX_DROP_ALL_PACKETS 0

#ifndef IO_RX_PREFETCH_ENABLE
#define IO_RX_PREFETCH_ENABLE 1
#endif

#ifndef WORKER_PREFETCH_ENABLE
#define WORKER_PREFETCH_ENABLE 1
#endif

#ifndef IO_TX_PREFETCH_ENABLE
#define IO_TX_PREFETCH_ENABLE 1
#endif

#if IO_RX_PREFETCH_ENABLE
#define IO_RX_PREFETCH0(p) rte_prefetch0(p)
#define IO_RX_PREFETCH1(p) rte_prefetch1(p)
#else
#define IO_RX_PREFETCH0(p)
#define IO_RX_PREFETCH1(p)
#endif

#if WORKER_PREFETCH_ENABLE
#define WORKER_PREFETCH0(p) rte_prefetch0(p)
#define WORKER_PREFETCH1(p) rte_prefetch1(p)
#else
#define WORKER_PREFETCH0(p)
#define WORKER_PREFETCH1(p)
#endif

#if IO_TX_PREFETCH_ENABLE
#define IO_TX_PREFETCH0(p) rte_prefetch0(p)
#define IO_TX_PREFETCH1(p) rte_prefetch1(p)
#else
#define IO_TX_PREFETCH0(p)
#define IO_TX_PREFETCH1(p)
#endif

#define IDLE_COUNT_CHK	10
#define IDLE_COUNT_SOFT	100
#define IDLE_COUNT_HARD	250

#define WORKER_REQ_RESET_CNT (1 << 1)

#define TASK_REFRESH_ARP_US	1 * US_PER_S
#define TASK_REFRESH_VLANS_US	10 * US_PER_S
#define TASK_NEGO_LACP_US 	25 * US_PER_S / MS_PER_S	/* Every 25 ms */
#define TASK_STATS_US		5 * US_PER_S
#define TASK_KNI_US		1 * US_PER_S

extern uint64_t tsc_per_us;
extern volatile uint64_t now_tsc;

static inline void
idle_heuristic(uint32_t idle)
{
	if (likely(idle < IDLE_COUNT_CHK)) {
		return;
	}
	if (idle < IDLE_COUNT_SOFT) {
		rte_delay_us(idle);
	} else if (idle >= IDLE_COUNT_SOFT && idle < IDLE_COUNT_HARD) {
		usleep(IDLE_COUNT_SOFT);
	} else {
		usleep(IDLE_COUNT_HARD);
	}
}

void io_lcore_main_loop(void *);

/* Worker functions */
void wrk_lcore_main_loop(void *);
void fw_lcore_main_loop_cnt(struct worker_lc_cfg *);
void fw_lcore_main_loop_tsc(struct worker_lc_cfg *);
void kni_lcore_main_loop(struct worker_lc_cfg *);
int wrk_update_arp_table(const struct rte_mbuf *, const uint8_t *);
void tap_lcore_main_loop(struct worker_lc_cfg *);
uint32_t tap_fwd_pkts_to_kernel(struct worker_lc_cfg *, uint32_t);
uint32_t tap_fwd_pkts_to_nic(struct worker_lc_cfg *, uint32_t);
uint32_t kni_fwd_pkts_to_kernel(struct worker_lc_cfg *, uint32_t);
uint32_t kni_fwd_pkts_to_nic(struct worker_lc_cfg *, uint32_t);
void ctrl_lcore_main_loop(struct worker_lc_cfg *);
struct gw_addr *arp_chk_gw_pkt(struct rte_mbuf *, uint64_t);
void arp_send_probes(struct worker_lc_cfg *, struct gw_addr *, uint32_t,
    uint64_t);
int scan_vlans(void);
void wrk_pkt_stats(struct worker_lc_cfg *, uint64_t *);

#endif	/* RUNTIME_H_ */
