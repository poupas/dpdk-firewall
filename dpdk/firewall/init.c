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

#include <netinet/in.h>
#include <linux/if_tun.h>
#include <linux/if.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <assert.h>
#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_kni.h>
#include <rte_errno.h>
#include <rte_eth_bond.h>

#include "main.h"
#include "util.h"

struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.header_split = 0,	/**< Header Split disabled */
		.hw_ip_checksum = 1,	/**< IP checksum offload enabled */
		.hw_vlan_filter = 0,	/**< VLAN filtering disabled */
		.hw_vlan_strip = 1,	/**< VLAN offload enabled */
		.jumbo_frame = 0,	/**< Jumbo Frame Support disabled */
		.hw_strip_crc = 0,	/**< CRC stripped by hardware */
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IP,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

static void
init_mbuf_pools(void)
{
	uint8_t socket, lcore;

	/* Init the buffer pools */
	for (socket = 0; socket < MAX_SOCKETS; socket++) {
		char name[32];
		if (cfg_is_socket_used(socket) == 0) {
			continue;
		}
		snprintf(name, sizeof(name), "mbuf_pool_%u", socket);
		RTE_LOG(DEBUG, USER1, "Creating the mbuf pool for socket %u.\n",
		    socket);
		cfg.pools[socket] = rte_mempool_create(
		    name,
		    MEMPOOL_BUFFERS,
		    MBUF_SIZE,
		    MEMPOOL_CACHE_SIZE,
		    sizeof(struct rte_pktmbuf_pool_private),
		    rte_pktmbuf_pool_init,
		    NULL,
		    rte_pktmbuf_init,
		    NULL,
		    socket,
		    0);
		if (cfg.pools[socket] == NULL) {
			rte_panic("Cannot create mbuf pool on socket %u: %s\n",
			    socket, strerror(rte_errno));
		}
	}

	for (lcore = 0; lcore < MAX_LCORES; lcore++) {
		if (cfg.lcores[lcore].type == LCORE_TYPE_NONE) {
			continue;
		}
		socket = rte_lcore_to_socket_id(lcore);
		cfg.lcores[lcore].pool = cfg.pools[socket];
	}
}


static void
init_ol_mbuf_pools(void)
{
	uint8_t socket;
	uint32_t nb_mbuf;

	/*
	 * Allocate memory for packet reassembly At any given moment up to
	 * <max_flow_num * (MAX_FRAG_NUM)> mbufs could be stored in the
	 * fragment table.
	 */
	nb_mbuf =
	    RTE_MAX(cfg.frag_max_flow_num, 2 * cfg.io_rx_read_burst_size) *
	    MAX_FRAG_NUM;
	nb_mbuf *= (port_conf.rxmode.max_rx_pkt_len + BUF_SIZE - 1) / BUF_SIZE;
	nb_mbuf *= 2;	/* IPv4 and IPv6 */
	nb_mbuf = RTE_MAX(nb_mbuf, (uint32_t)MEMPOOL_BUFFERS);

	for (socket = 0; socket < MAX_SOCKETS; socket++) {
		char name[32];
		if (cfg_is_socket_used(socket) == 0) {
			continue;
		}
		snprintf(name, sizeof(name), "mbuf_ol_pool_%u", socket);
		RTE_LOG(DEBUG,
		    USER1,
		    "Creating the mbuf offload pool for socket %u.\n",
		    socket);
		cfg.ol_pools[socket] = rte_mempool_create(
		    name,
		    nb_mbuf,
		    MBUF_SIZE,
		    MEMPOOL_CACHE_SIZE,
		    sizeof(struct rte_pktmbuf_pool_private),
		    rte_pktmbuf_pool_init,
		    NULL,
		    rte_pktmbuf_init,
		    NULL,
		    socket,
		    0);
		if (cfg.pools[socket] == NULL) {
			rte_panic("Cannot create mbuf pool on socket %u: %s\n",
			    socket, strerror(rte_errno));
		}
	}
}

static void
init_rings_rx(void)
{
	uint8_t iolc, wlc = 0;

	/* Initialize the rings for the RX side */
	for (iolc = 0; iolc < MAX_LCORES; iolc++) {
		struct lc_cfg *lcp = &cfg.lcores[iolc];
		unsigned socket_io;

		if (lcp->type != LCORE_TYPE_IO || lcp->io.rx.n_nic_queues == 0) {
			continue;
		}
		socket_io = rte_lcore_to_socket_id(iolc);

		for (wlc = 0; wlc < MAX_LCORES; wlc++) {
			char name[32];
			struct lc_cfg *wlcp = &cfg.lcores[wlc];
			struct rte_ring *ring = NULL;

			if (wlcp->type != LCORE_TYPE_WORKER) {
				continue;
			}
			if ((lcp->io.rx.workers_mask & (1 << wlcp->worker.id))
			    == 0) {
				continue;
			}
			RTE_LOG(DEBUG, USER1, "Creating ring to connect IO RX"
			    "lcore %u (socket %u)-> worker %u (lcore %u)...\n",
			    iolc, socket_io, wlcp->worker.id, wlc);
			snprintf(name, sizeof(name), "ring_rx_s%u_io%u_w%u",
			    socket_io, iolc, wlcp->worker.id);
			ring = rte_ring_create(
			    name,
			    cfg.ring_rx_size,
			    socket_io,
			    RING_F_SP_ENQ | RING_F_SC_DEQ);
			if (ring == NULL) {
				rte_panic("Cannot create ring to connect RX IO "
				    "lcore %u with worker core %u\n",
				    iolc,
				    wlcp->worker.id);
			}
			lcp->io.rx.rings[lcp->io.rx.n_rings] = ring;
			lcp->io.rx.n_rings++;
			wlcp->worker.irings[wlcp->worker.n_irings] = ring;
			wlcp->worker.n_irings++;
		}
	}

	/*
	 * We should perform some sanity checks here. E.g., to determine if
	 * the pipeline is being correctly assembled.
	 */
}

static void
init_rings_tx(void)
{
	unsigned lcore;

	/* Initialize the rings for the TX side */
	for (lcore = 0; lcore < MAX_LCORES; lcore++) {
		struct lc_cfg *wlcp = &cfg.lcores[lcore];
		uint8_t port;

		RTE_LOG(DEBUG, USER1, "Checking lcore %u, type: %u\n", lcore, wlcp->type);
		if (wlcp->type != LCORE_TYPE_WORKER) {
			continue;
		}
		for (port = 0; port < MAX_NIC_PORTS; port++) {
			char name[32];
			struct io_lc_cfg *iolcp = NULL;
			struct rte_ring *ring;
			uint32_t socket, iolc;

			if (!(cfg.ifaces[port].flags & NIC_FLAG_TX_ON)) {
				continue;
			}
			if (cfg_lcore_for_nic_tx((uint8_t)port, &iolc) < 0) {
				rte_panic(
				    "Init error: %u has no TX core.\n", port);
			}
			iolcp = &cfg.lcores[iolc].io;
			socket = rte_lcore_to_socket_id(iolc);

			RTE_LOG(DEBUG, USER1,
			    "Creating ring to connect worker %u (lcore %u) "
			    "to TX port %u (using io lcore %u, socket: %u).\n",
			    wlcp->worker.id, lcore, port, (unsigned)iolc,
			    (unsigned)socket);

			snprintf(name, sizeof(name), "ring_tx_s%u_w%u_p%u",
			    socket, lcore, port);
			ring = rte_ring_create(
			    name,
			    cfg.ring_tx_size,
			    socket,
			    RING_F_SP_ENQ | RING_F_SC_DEQ);
			if (ring == NULL) {
				rte_panic("Cannot create ring to connect "
				    "worker core %u with TX port %u\n",
				    lcore,
				    port);
			}
			wlcp->worker.orings[port] = ring;
			iolcp->tx.rings[port][wlcp->worker.id] = ring;
			iolcp->tx.workers_mask |= 1 << wlcp->worker.id;
		}
	}

	for (lcore = 0; lcore < MAX_LCORES; lcore++) {
		struct lc_cfg *lcp = &cfg.lcores[lcore];
		unsigned i;

		if (lcp->type != LCORE_TYPE_IO || lcp->io.tx.n_nic_ports == 0) {
			continue;
		}
		for (i = 0; i < lcp->io.tx.n_nic_ports; i++) {
			unsigned port, j;
			port = lcp->io.tx.nic_ports[i];
			for (j = 0; j < cfg_lcores_worker(); j++) {
				if (lcp->io.tx.rings[port][j] == NULL) {
					rte_panic("Init error (io TX rings)\n");
				}
			}
		}
	}
}


static void
init_rings_ctrl(void)
{
	uint32_t wtype;
	uint8_t ctrl_lc, wrklc;

	wrklc = 0;
	wtype = WORKER_TYPE_CTRL_KNI | WORKER_TYPE_CTRL_TAP;

	/* Initialize the control plane rings */
	for (ctrl_lc = 0; ctrl_lc < MAX_LCORES; ctrl_lc++) {
		struct lc_cfg *lcp = &cfg.lcores[ctrl_lc];

		if (lcp->type != LCORE_TYPE_WORKER ||
		    (lcp->worker.type & wtype) == 0) {
			continue;
		}
		/* Link control path clients to control path providers */
		for (wrklc = 0; wrklc < MAX_LCORES; wrklc++) {
			char name[32];
			struct worker_lc_cfg *wlcp = NULL;
			struct rte_ring *ring;
			unsigned w_socket;

			if (cfg.lcores[wrklc].type != LCORE_TYPE_WORKER ||
			    !cfg.lcores[wrklc].worker.ctrlplane) {
				continue;
			}
			wlcp = &cfg.lcores[wrklc].worker;
			w_socket = rte_lcore_to_socket_id(wrklc);

			RTE_LOG(DEBUG, USER1, "Creating ring to worker "
			    "lcore %u (socket %u) -> control lcore %u ...\n",
			    wrklc,
			    w_socket,
			    ctrl_lc);
			snprintf(name, sizeof(name), "ring_ws%u_ctrl%u_w%u",
			    w_socket,
			    ctrl_lc,
			    wrklc);
			ring = rte_ring_create(
			    name,
			    cfg.ring_rx_size,
			    w_socket,
			    RING_F_SP_ENQ | RING_F_SC_DEQ);
			if (ring == NULL) {
				rte_panic("Cannot create ring to connect worker "
				    "lcore %u with control core %u\n",
				    wrklc,
				    ctrl_lc);
			}
			wlcp->crings[wlcp->n_crings++].ring = ring;
			lcp->worker.irings[lcp->worker.n_irings++] = ring;
		}
	}

	/*
	 * TODO: We should perform some sanity checks here. E.g., to
	 * determine if the pipeline is being correctly assembled.
	 */
}

static void
init_rings_offload(void)
{
	uint8_t olcli, olsrv = 0;

	/* Initialize the offload worker rings */
	for (olsrv = 0; olsrv < MAX_LCORES; olsrv++) {
		struct lc_cfg *srv = &cfg.lcores[olsrv];

		if (srv->type != LCORE_TYPE_WORKER ||
		    srv->worker.type != WORKER_TYPE_FW ||
		    srv->worker.ol != WORKER_OL_PROV) {
			continue;
		}
		/* Link offload clients with offload servers */
		for (olcli = 0; olcli < MAX_LCORES; olcli++) {
			char name[32];
			struct worker_lc_cfg *cli = NULL;
			struct rte_ring *ring;
			unsigned wsocket;

			if (cfg.lcores[olcli].type != LCORE_TYPE_WORKER ||
			    cfg.lcores[olcli].worker.ol != WORKER_OL_CLNT) {
				continue;
			}
			cli = &cfg.lcores[olcli].worker;
			wsocket = rte_lcore_to_socket_id(olcli);

			RTE_LOG(DEBUG, USER1, "Creating ring to worker offload "
			    "client core %u (socket %u) -> offload server core "
			    "%u ...\n",
			    olcli,
			    wsocket,
			    olsrv);
			snprintf(name, sizeof(name),
			    "ring_s%u_olcli%u_olsrv%u", wsocket, olcli, olsrv);
			ring = rte_ring_create(
			    name,
			    cfg.ring_rx_size,
			    wsocket,
			    RING_F_SP_ENQ | RING_F_SC_DEQ);
			if (ring == NULL) {
				rte_panic("Cannot create ring to connect worker "
				    "offload lcore %u with offload core %u\n",
				    olcli, olsrv);
			}
			srv->worker.irings[srv->worker.n_irings++] = ring;
			cli->ol_rings[cli->n_ol_rings++].ring = ring;
		}
	}

	/*
	 * We should perform some sanity checks here. E.g., to determine if
	 * the pipeline is being correctly assembled.
	 */
}

static void
print_link_status(uint8_t port, struct rte_eth_link *link)
{
	if (link->link_status) {
		RTE_LOG(DEBUG, USER1, "Port %d Link Up - speed %u Mbps - %s\n",
		    port, (unsigned)link->link_speed,
		    (link->link_duplex == ETH_LINK_FULL_DUPLEX) ?
		    ("full-duplex") : ("half-duplex\n"));
	} else {
		RTE_LOG(DEBUG, USER1, "Port %d Link Down\n", port);
	}
}

/* Check the link status of all ports, wait up to 9 seconds, and print them */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100	/* 100ms */
#define MAX_CHECK_TIME 90	/* 9s (90 * 100ms) in total */
	struct rte_eth_link link;
	uint32_t n_rx_queues;
	uint8_t port, count, all_ports_up, print_flag = 0;

	RTE_LOG(DEBUG, USER1, "\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (port = 0; port < port_num; port++) {
			if ((port_mask & (1 << port)) == 0)
				continue;

			n_rx_queues = cfg_nic_rx_queues_per_port(port);

			if (n_rx_queues == 0 &&
			    !(cfg.ifaces[port].flags & NIC_FLAG_TX_ON)) {
				continue;
			}
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(port, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				print_link_status(port, &link);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}
		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

static int
init_bond_slaves(uint8_t port)
{
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	struct rte_mempool *pool;
	uint32_t n_slaves, lcore;
	unsigned int socket;
	int ret;
	uint8_t slave;

	n_slaves = cfg.ifaces[port].n_slaves;
	cfg_lcore_for_nic_tx(port, &lcore);
	socket = rte_lcore_to_socket_id(lcore);
	pool = cfg.lcores[lcore].pool;

	for (slave = 0; slave < n_slaves; slave++) {
		/* Init port */
		RTE_LOG(DEBUG, USER1, "Initializing slave %d...\n", slave);
		ret = rte_eth_dev_configure(slave, 1, 1, &port_conf);
		if (ret < 0) {
			rte_panic("Slave %d config error (%d)\n", slave, ret);
		}
		/* Initialize RX queue */
		RTE_LOG(DEBUG, USER1, "Initializing slave %d RX queue %d ...\n",
		    slave, 0);
		ret = rte_eth_rx_queue_setup(slave, 0, cfg.nic_rx_ring_size,
		    socket, NULL, pool);
		if (ret < 0) {
			rte_panic("Cannot init RX queue %d on slave %d (%d)\n",
			    0, slave, ret);
		}
		/* Initialize TX queue */
		RTE_LOG(DEBUG, USER1, "Initializing slave %d TX queue 0...\n",
		    slave);

		rte_eth_dev_info_get(slave, &dev_info);
		txconf = &dev_info.default_txconf;

		/* Enable VLAN offloading */
		txconf->txq_flags &= ~ETH_TXQ_FLAGS_NOVLANOFFL;
		ret = rte_eth_tx_queue_setup(
		    slave,
		    0,
		    cfg.nic_tx_ring_size,
		    socket,
		    txconf);

		if (ret < 0) {
			rte_panic("Cannot init TX queue 0 on slave %d (%d)\n",
			    slave, ret);
		}
		/* Start the port */
		ret = rte_eth_dev_start(slave);
		if (ret < 0) {
			rte_panic("Cannot start slave %d (%d)\n", slave, ret);
		}
		rte_eth_macaddr_get(slave, &cfg.ifaces[slave].hwaddr);
	}

	return 1;
}

static void
init_ifaces(void)
{
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	uint32_t lcore;
	unsigned socket;
	int ret;
	uint16_t queue, n_rx_queues;
	uint8_t port;

	/* Init NIC ports and queues, then start the ports */
	for (port = 0; port < MAX_NIC_PORTS; port++) {
		struct rte_mempool *pool;

		n_rx_queues = cfg_nic_rx_queues_per_port(port);
		if ((n_rx_queues == 0 &&
		    !(cfg.ifaces[port].flags & NIC_FLAG_TX_ON)) ||
		    (cfg.ifaces[port].flags & NIC_FLAG_BOND_SLAVE)) {
			continue;
		}
		if (cfg.ifaces[port].flags & NIC_FLAG_BOND_IFACE) {
			char name[MAX_NIC_LEN];
			int r;

			snprintf(name, sizeof(name), "bond%d", port);
			r = rte_eth_bond_create(
			    name,
			    BONDING_MODE_8023AD,
			    0);

			if (r != port) {
				rte_panic("bond id != port. Deal with this.\n");
			}
			if (!init_bond_slaves(port)) {
				rte_panic("Could not init bond slaves for %d.\n",
				    port);
			}
		}
		/* Init port */
		RTE_LOG(DEBUG, USER1, "Initializing NIC port %d...\n", port);
		ret = rte_eth_dev_configure(
		    port,
		    n_rx_queues,
		    1,
		    &port_conf);

		if (ret < 0) {
			rte_panic("Cannot init NIC port %d (%d)\n", port, ret);
		}
		/* Init RX queues */
		for (queue = 0; queue < MAX_RX_QUEUES_PER_NIC_PORT; queue++) {
			if (cfg.ifaces[port].rx_queues[queue] == 0) {
				continue;
			}
			cfg_lcore_for_nic_rx(port, queue, &lcore);
			socket = rte_lcore_to_socket_id(lcore);
			pool = cfg.lcores[lcore].pool;

			RTE_LOG(DEBUG, USER1,
			    "Initializing NIC port %d RX queue %d ...\n",
			    port, queue);
			ret = rte_eth_rx_queue_setup(
			    port,
			    queue,
			    cfg.nic_rx_ring_size,
			    socket,
			    NULL,
			    pool);
			if (ret < 0) {
				rte_panic(
				    "Cannot init RX queue %d on port %d (%d)\n",
				    queue, port, ret);
			}
		}

		/* Init TX queues */
		rte_eth_dev_info_get(port, &dev_info);
		txconf = &dev_info.default_txconf;

		/* Enable VLAN offloading */
		txconf->txq_flags &= ~ETH_TXQ_FLAGS_NOVLANOFFL;

		if (cfg.ifaces[port].flags & NIC_FLAG_TX_ON) {
			cfg_lcore_for_nic_tx(port, &lcore);
			socket = rte_lcore_to_socket_id(lcore);
			RTE_LOG(DEBUG, USER1,
			    "Initializing NIC port %u TX queue 0...\n",
			    (unsigned)port);
			ret = rte_eth_tx_queue_setup(
			    port,
			    0,
			    (uint16_t)cfg.nic_tx_ring_size,
			    socket,
			    txconf);
			if (ret < 0) {
				rte_panic(
				    "Cannot init TX queue 0 on port %d (%d)\n",
				    port, ret);
			}
		}
		/* Add slave interfaces to bond */
		if (cfg.ifaces[port].flags & NIC_FLAG_BOND_IFACE) {
			int i;

			for (i = 0; i < cfg.ifaces[port].n_slaves; i++) {
				int r;
				RTE_LOG(DEBUG, USER1,
				    "Adding port %d to bond %d.\n",
				    i, port);
				r = rte_eth_bond_slave_add(
				    port,
				    cfg.ifaces[port].slaves[i]);
				if (r == -1) {
					rte_panic("Could not add slave %d.\n",
					    i);
				}
			}
			//rte_eth_promiscuous_enable(port);
		}
		/* Start port */
		ret = rte_eth_dev_start(port);
		if (ret < 0) {
			rte_panic("Cannot start port %d (%d)\n", port, ret);
		}
		rte_eth_macaddr_get(port, &cfg.ifaces[port].hwaddr);
		//rte_eth_promiscuous_enable(port);
	}

	check_all_ports_link_status(MAX_NIC_PORTS, (~0x0));
}

static void
init_tap(void)
{
#ifndef IFNAMSIZ
#define IFNAMSIZ 32
#endif
	char tapname[IFNAMSIZ];
	struct lc_cfg *lcp;
	uint8_t lcore, tap;

	for (lcore = 0; lcore < MAX_LCORES; lcore++) {
		struct tap_lc_cfg *taplcp;

		lcp = &cfg.lcores[lcore];
		if (lcp->type != LCORE_TYPE_WORKER ||
		    lcp->worker.type != WORKER_TYPE_CTRL_TAP) {
			continue;
		}
		taplcp = &lcp->worker.tap;

		for (tap = 0; tap < taplcp->n_taps; tap++) {
			int8_t port;
			int tapfd, i;

			if ((port = taplcp->tap_to_port[tap]) == -1) {
				continue;
			}
			snprintf(tapname, sizeof(tapname), "mitra%u", tap);
			tapfd = tap_create(tapname, &cfg.ifaces[port]);
			if (tapfd < 0) {
				rte_panic("Could not create interface: %s.\n",
				    tapname);
			}
			taplcp->taps[tap] = tapfd;

			for (i = 0; taplcp->port_to_tap[i] >= 0; i++) {
				taplcp->port_to_tap[i] =
				    taplcp->taps[taplcp->port_to_tap[i]];
			}
		}
	}
}

static void
init_kni(void)
{
	struct lc_cfg *lcp;
	struct rte_kni *kni;
	uint8_t lcore, i;

	if (cfg.n_kni_ports == 0) {
		RTE_LOG(DEBUG, USER1,
		    "No KNI ports configured. Skipping KNI init.\n");
		return;
	}
	rte_kni_init(cfg.n_kni_ports);
	for (lcore = 0; lcore < MAX_LCORES; lcore++) {
		struct kni_lc_cfg *knilcp;

		lcp = &cfg.lcores[lcore];
		if (lcp->type != LCORE_TYPE_WORKER ||
		    lcp->worker.type != WORKER_TYPE_CTRL_KNI) {
			continue;
		}
		knilcp = &lcp->worker.kni;
		for (i = 0; i < knilcp->n_kni; i++) {
			int8_t port;

			if ((port = knilcp->kni_to_port[i]) == -1) {
				continue;
			}
			kni = kni_alloc_port(port, lcp);
			if (kni == NULL) {
				rte_exit(EXIT_FAILURE,
				    "Error creating KNI for port: %d\n", port);
			}
			knilcp->kni[i] = kni;
		}
	}
}

static void
init_fw(void)
{
	if (fw_init() != 0) {
		rte_exit(EXIT_FAILURE,
		    "Could not initialize firewall workers.\n");
	}
}

static void
init_offload(void)
{

}

void
init_app(void)
{
	init_mbuf_pools();
	init_ol_mbuf_pools();
	init_rings_rx();
	init_rings_tx();
	init_rings_ctrl();
	init_rings_offload();
	init_ifaces();
	init_tap();
	init_kni();
	init_fw();
	init_offload();

	RTE_LOG(DEBUG, USER1, "Initialization complete.\n");
}
