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

#include "main.h"
#include "util.h"
#include "runtime.h"

void
wrk_pkt_stats(struct worker_lc_cfg *lp, uint64_t *last_stats)
{
	uint32_t i;
	uint64_t elapsed_us;

	elapsed_us = TSC2US(now_tsc - *last_stats);
	if (elapsed_us < TASK_STATS_US)  {
		return;
	}

	for (i = 0; i < lp->n_irings; i++) {
		uint64_t pps;

		if (lp->irings_pkts[i] == 0) {
			continue;
		}

		pps = lp->irings_pkts[i] / (elapsed_us / US_PER_S);
		lp->irings_pkts[i] = 0;

		RTE_LOG(
		    DEBUG,
		    USER1,
		    "Worker %u: input ring %" PRIu32
		    " stats: %" PRIu64 " pps\n", lp->id, i, pps);
	}

	for (i = 0; i < lp->n_crings; i++) {
		uint64_t pps;

		if (lp->crings_pkts[i] == 0) {
			continue;
		}

		pps = lp->crings_pkts[i] / (elapsed_us / US_PER_S);
		lp->crings_pkts[i] = 0;

		RTE_LOG(
		    DEBUG,
		    USER1,
		    "Worker %u: control ring %" PRIu32
		    " stats: %" PRIu64 " pps\n", lp->id, i, pps);
	}

	*last_stats = now_tsc;
}

int
lcore_main_loop(__attribute__((unused)) void *arg)
{
	struct lc_cfg *lp;
	unsigned lcore;

	lcore = rte_lcore_id();
	lp = &cfg.lcores[lcore];
	tsc_per_us = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S;

	if (lp->type == LCORE_TYPE_IO) {
		RTE_LOG(DEBUG, USER1, "IO logical core %u main loop.\n", lcore);
		io_lcore_main_loop(lp);
	} else if (lp->type == LCORE_TYPE_WORKER) {
		RTE_LOG(DEBUG, USER1,
		    "Worker logical core %u (type: %u) main loop.\n",
		    lcore,
		    (unsigned)lp->worker.type);
		wrk_lcore_main_loop(lp);
	}
	return 0;
}
