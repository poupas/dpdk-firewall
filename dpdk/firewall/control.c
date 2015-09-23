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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>

#include <netinet/in.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>

#include <rte_log.h>

#include "main.h"
#include "packet.h"
#include "runtime.h"
#include "forward.h"

struct ctrl_cron {
	/* When these values are reached, run the job */
	uint64_t next;
	uint64_t refresh_arp;
	uint64_t update_arp;
	uint64_t refresh_vlans;
	uint64_t flush;
	uint64_t lacp;
	uint64_t kni;

	/* These timestamps specify when the job last ran */
	uint64_t last_stats;
};

uint64_t tsc_per_us;
uint64_t volatile now_tsc;

static inline void
refresh_vlans(uint64_t now, struct ctrl_cron *cron)
{

	if (likely(now < cron->refresh_vlans)) {
		return;
	}
	if (scan_vlans()) {
		cfg.vlans_ts = now;
	}
	cron->refresh_vlans = now + US2TSC(TASK_REFRESH_VLANS_US);
}

static inline void
refresh_arp_table(struct worker_lc_cfg *lp, struct ctrl_cron *cron)
{

	if (likely(now_tsc < cron->refresh_arp)) {
		return;
	}
	arp_send_probes(lp, cfg.igws, cfg.n_igws, tsc_per_us);
	arp_send_probes(lp, cfg.ogws, cfg.n_ogws, tsc_per_us);

	cron->refresh_arp = now_tsc + US2TSC(TASK_REFRESH_ARP_US);

}

static inline void
negotiate_lacp(void)
{
	int i;

	for (i = 0; i < MAX_NIC_PORTS; i++) {
		if (cfg.ifaces[i].flags & NIC_FLAG_BOND_IFACE) {
			cfg.ifaces[i].lacp = 1;
		}
	}
}

static inline void
flush_kni(struct worker_lc_cfg *lp, struct ctrl_cron *cron)
{
	enum worker_type ktype;
	uint32_t i;

	ktype = WORKER_TYPE_CTRL_KNI;

	if (likely(lp->type != ktype || now_tsc < cron->kni)) {
		return;
	}

	for (i = 0; i < lp->kni.n_kni; i++) {
		rte_kni_handle_request(lp->kni.kni[i]);
	}

	cron->kni = now_tsc + US2TSC(TASK_KNI_US);

}

static inline void
run_tasks(struct worker_lc_cfg *lp, struct ctrl_cron *cron)
{

	refresh_vlans(now_tsc, cron);
	refresh_arp_table(lp, cron);
	wrk_pkt_stats(lp, &cron->last_stats);
	flush_kni(lp, cron);

	if (unlikely(reload_fw)) {
		fw_reload();
		reload_fw = 0;
	}

	if (unlikely(dump_fw_counters)) {
		fw_dump_counters();
		dump_fw_counters = 0;
	}
}

void
ctrl_lcore_main_loop(struct worker_lc_cfg *lp)
{
	struct ctrl_cron cron = {0};
	uint32_t burst, idle;
	uint32_t (*fwd_pkts_to_kernel) (struct worker_lc_cfg *, uint32_t);
	uint32_t (*fwd_pkts_to_nic) (struct worker_lc_cfg *, uint32_t);

	burst = cfg.worker_read_burst_size;

	/* Only use the TAP for now */
	fwd_pkts_to_kernel = tap_fwd_pkts_to_kernel;
	fwd_pkts_to_nic = tap_fwd_pkts_to_nic;

	idle = 0;
	for (;;) {
		now_tsc = rte_rdtsc();

		if (unlikely(now_tsc > cron.flush)) {
			if (lp->pending) {
				flush_nic_buffers(lp);
				lp->pending = 0;
			}
			cron.flush = now_tsc + US2TSC(LCORE_WORKER_FLUSH_US);
		}
		if (unlikely(now_tsc > cron.lacp)) {
			negotiate_lacp();
			cron.lacp = now_tsc + US2TSC(TASK_NEGO_LACP_US);
		}
		if (unlikely(now_tsc > cron.next)) {
			run_tasks(lp, &cron);
			cron.next = now_tsc + US2TSC(LCORE_CTRL_TASKS_US);
		}

		/* Forward received packets to kernel */
		if (fwd_pkts_to_kernel(lp, burst)) {
			idle = 0;
		}

		/* Forward kernel packets to NIC ports */
		if (fwd_pkts_to_nic(lp, burst)) {
			idle = 0;
		}
		idle_heuristic(idle);
		if (lp->pending == 0) {
			idle++;
		} else {
			idle = 0;
		}
	}
}
