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

#include <stdio.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_memory.h>
#include <rte_log.h>

#include "main.h"

void usage(const char *);

void
usage(const char *name)
{
	fprintf(stderr, "usage: %s: <config>\n", name);
}

static void
hup_signal_handler(int signum __attribute__((unused)))
{
	if (reload_fw != 0) {
		return;
	}
	reload_fw = 1;
}

static void
usr1_signal_handler(int signum __attribute__((unused)))
{
	if (dump_fw_counters != 0) {
		return;
	}
	dump_fw_counters = 1;
}

static int
install_signal_handlers(void)
{
	struct sigaction sa;
	sigset_t set;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = hup_signal_handler;
	sa.sa_flags = SA_RESTART;
	sigfillset(&sa.sa_mask);
	if (sigaction(SIGHUP, &sa, NULL) != 0) {
		RTE_LOG(CRIT, USER1, "Error registering SIGHUP handler\n");
		return -1;
	}
	sa.sa_handler = usr1_signal_handler;
	if (sigaction(SIGUSR1, &sa, NULL) != 0) {
		RTE_LOG(CRIT, USER1, "Error registering SIGUSR1 handler\n");
		return -1;
	}
	/* block (ignore) sigpipes for this and all the child threads */
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) {
		RTE_LOG(CRIT, USER1, "Error setting signal mask\n");
		return -1;
	}
	return 0;
}

int
main(int argc, char *argv[])
{
	uint32_t lcore;
	int ret;

	/* Init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		return -1;
	argc -= ret;
	argv += ret;

	/* Parse configuration file */
	if (argc < 2) {
		usage(argv[0]);
		return -1;
	}
	ret = cfg_parse_file(argv[1]);
	if (ret < 0) {
		fprintf(stderr, "Could not parse configuration file [%s]\n",
		    argv[1]);
		return ret;
	}
	if ((ret = install_signal_handlers()) != 0) {
		return ret;
	}
	/* Initialize the application */
	init_app();
	cfg_print_settings();

	/* Launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(lcore_main_loop, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore) {
		if (rte_eal_wait_lcore(lcore) < 0) {
			return -1;
		}
	}

	return 0;
}
