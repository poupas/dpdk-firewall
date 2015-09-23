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

#ifndef _MAIN_H_
#define _MAIN_H_

#include <stdint.h>
#include <netinet/in.h>

#include <rte_memory.h>
#include <rte_config.h>
#include <rte_ether.h>
#include <rte_mempool.h>

/* Processor sockets */
#ifndef MAX_SOCKETS
#define MAX_SOCKETS 2
#endif

/* Logical cores */
#ifndef MAX_LCORES
#define MAX_LCORES RTE_MAX_LCORE
#endif

/* Network interfaces (ports) */
#ifndef MAX_NIC_PORTS
#define MAX_NIC_PORTS RTE_MAX_ETHPORTS
#endif

#ifndef MAX_VLANS
#define MAX_VLANS 4096
#endif

/* Must be a power of 2 */
#ifndef MAX_GWS
#define MAX_GWS 8
#endif

#ifndef MAX_RX_QUEUES_PER_NIC_PORT
#define MAX_RX_QUEUES_PER_NIC_PORT 16
#endif

#ifndef MAX_TX_QUEUES_PER_NIC_PORT
#define MAX_TX_QUEUES_PER_NIC_PORT 16
#endif

#ifndef MAX_IO_LCORES
#define MAX_IO_LCORES 16
#endif
#if (MAX_IO_LCORES > MAX_LCORES)
#error "MAX_IO_LCORES is too big"
#endif

#ifndef MAX_NIC_RX_QUEUES_PER_IO_LCORE
#define MAX_NIC_RX_QUEUES_PER_IO_LCORE 16
#endif

#ifndef MAX_NIC_TX_PORTS_PER_IO_LCORE
#define MAX_NIC_TX_PORTS_PER_IO_LCORE 6
#endif
#if (MAX_NIC_TX_PORTS_PER_IO_LCORE > MAX_NIC_PORTS)
#error "MAX_NIC_TX_PORTS_PER_IO_LCORE too big"
#endif


#ifndef MAX_NIC_LEN
#define MAX_NIC_LEN 16
#endif

#ifndef MAX_WORKER_LCORES
#define MAX_WORKER_LCORES 16
#endif
#if (MAX_WORKER_LCORES > MAX_LCORES)
#error "MAX_WORKER_LCORES is too big"
#endif

#ifndef MAX_CTRL_LCORES
#define MAX_CTRL_LCORES 2
#endif

#ifndef MAX_FW_LCORES
#define MAX_FW_LCORES 2
#endif

#ifndef MAX_OL_LCORES
#define MAX_OL_LCORES 2
#endif

/* Mempools */
#define BUF_SIZE 2048
#ifndef MBUF_SIZE
#define MBUF_SIZE (BUF_SIZE + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#endif

/*
 * TODO: set sensible sizes here
 */
#ifndef MEMPOOL_BUFFERS
#define MEMPOOL_BUFFERS 8192 * 4
#endif

#ifndef MEMPOOL_CACHE_SIZE
#define MEMPOOL_CACHE_SIZE 256
#endif

/* NIC RX */
#ifndef NIC_RX_RING_SIZE
#define NIC_RX_RING_SIZE 256
#endif

/* NIC TX */
#ifndef NIC_TX_RING_SIZE
#define NIC_TX_RING_SIZE 512
#endif

/* Software Rings */
#ifndef RING_RX_SIZE
#define RING_RX_SIZE 512
#endif

#ifndef RING_TX_SIZE
#define RING_TX_SIZE 512
#endif

/* Bursts */
#ifndef MBUF_ARRAY_SIZE
#define MBUF_ARRAY_SIZE 512
#endif

#ifndef BURST_SIZE_IO_RX_READ
#define BURST_SIZE_IO_RX_READ 32
#endif
#if (BURST_SIZE_IO_RX_READ > MBUF_ARRAY_SIZE)
#error "BURST_SIZE_IO_RX_READ is too big"
#endif

#ifndef BURST_SIZE_IO_RX_WRITE
#define BURST_SIZE_IO_RX_WRITE 32
#endif
#if (BURST_SIZE_IO_RX_WRITE > MBUF_ARRAY_SIZE)
#error "BURST_SIZE_IO_RX_WRITE is too big"
#endif

#ifndef BURST_SIZE_IO_TX_READ
#define BURST_SIZE_IO_TX_READ 32
#endif
#if (BURST_SIZE_IO_TX_READ > MBUF_ARRAY_SIZE)
#error "BURST_SIZE_IO_TX_READ is too big"
#endif

#ifndef BURST_SIZE_IO_TX_WRITE
#define BURST_SIZE_IO_TX_WRITE 32
#endif
#if (BURST_SIZE_IO_TX_WRITE > MBUF_ARRAY_SIZE)
#error "BURST_SIZE_IO_TX_WRITE is too big"
#endif

#ifndef BURST_SIZE_WORKER_READ
#define BURST_SIZE_WORKER_READ 32
#endif
#if ((2 * BURST_SIZE_WORKER_READ) > MBUF_ARRAY_SIZE)
#error "BURST_SIZE_WORKER_READ is too big"
#endif

#ifndef BURST_SIZE_WORKER_WRITE
#define BURST_SIZE_WORKER_WRITE 32
#endif
#if (BURST_SIZE_WORKER_WRITE > MBUF_ARRAY_SIZE)
#error "BURST_SIZE_WORKER_WRITE is too big"
#endif

#ifndef BATCH_SIZE_ACL
#define BATCH_SIZE_ACL BURST_SIZE_WORKER_READ
#endif
#if ((2 * BATCH_SIZE_ACL) > MBUF_ARRAY_SIZE)
#error "BATCH_SIZE_ACL is too big"
#endif

#if (BATCH_SIZE_ACL % 2 != 0)
#error "BATCH_SIZE_ACL must be a power of two"
#endif

#define MAX_ZONE_LEN		32
#define MAX_ZONES		2
#define MAX_NAT_ENTRIES		1024
#define MAX_ACL_COUNTERS	16
#define MAX_FILE_PATH		256
#define CONF_PATH		"etc"
#define ZONE_PATH		CONF_PATH"/zones"
#define RULE_PATH		ZONE_PATH"/rules"


#define OL_MEMPOOL_SIZE		8192
#define MAX_FRAG_NUM		RTE_LIBRTE_IP_FRAG_MAX_FRAG
#define FRAG_TABLE_BUCKETS	16

#define NIC_FLAG_REVERSE	1 << 0
#define NIC_FLAG_BOND_IFACE	1 << 1
#define NIC_FLAG_BOND_SLAVE	1 << 2
#define NIC_FLAG_TX_ON		1 << 3

struct mbuf_array {
	struct rte_mbuf *array[MBUF_ARRAY_SIZE];
	uint32_t n_mbufs;
};

enum lc_type {
	LCORE_TYPE_NONE = 0,
	LCORE_TYPE_IO,
	LCORE_TYPE_WORKER,
};

enum worker_type {
	WORKER_TYPE_FW = 0,
	WORKER_TYPE_NAT,
	WORKER_TYPE_CTRL_KNI,
	WORKER_TYPE_CTRL_TAP
};

enum worker_ol_type {
	WORKER_OL_OFF = 0,
	WORKER_OL_CLNT,
	WORKER_OL_PROV,
	WORKER_OL_NUM
};

struct nic_cfg {
	char zone[MAX_ZONE_LEN];
	struct ether_addr hwaddr;
	uint8_t slaves[MAX_NIC_PORTS];
	uint8_t n_slaves;
	uint8_t rx_queues[MAX_RX_QUEUES_PER_NIC_PORT];

	uint8_t flags;

	volatile uint8_t lacp;
};

struct io_lc_cfg {
	/* I/O RX */
	struct {
		/* NIC */
		struct {
			uint8_t port;
			uint8_t queue;
		}      nic_queues[MAX_RX_QUEUES_PER_NIC_PORT];
		uint32_t n_nic_queues;

		/* Rings */
		struct rte_ring *rings[MAX_WORKER_LCORES];
		uint32_t n_rings;

		/* Internal buffers */
		struct mbuf_array ibuf;
		struct mbuf_array obuf[MAX_WORKER_LCORES];
		uint8_t obuf_flush[MAX_WORKER_LCORES];

		/* Connected workers */
		uint32_t workers_mask;

		/* Stats */
		uint64_t nic_q_pkts[MAX_NIC_RX_QUEUES_PER_IO_LCORE];
		uint64_t rings_pkts[MAX_WORKER_LCORES];
	}      rx;

	/* I/O TX */
	struct {
		/* Rings */
		struct rte_ring *rings[MAX_NIC_PORTS][MAX_WORKER_LCORES];

		/* NIC */
		uint8_t nic_ports[MAX_NIC_TX_PORTS_PER_IO_LCORE];
		uint32_t n_nic_ports;
		uint32_t workers_mask;

		/* Internal buffers */
		struct mbuf_array obuf[MAX_NIC_TX_PORTS_PER_IO_LCORE];
		uint8_t obuf_flush[MAX_NIC_TX_PORTS_PER_IO_LCORE];

		/* Stats */
		uint64_t rings_pkts[MAX_WORKER_LCORES];
		uint64_t nic_pkts[MAX_NIC_TX_PORTS_PER_IO_LCORE];
	}      tx;

	uint64_t stats_tsc;
	uint8_t pending;
};

struct wrk_ring {
	struct rte_ring *ring;
	struct mbuf_array obuf;
	uint8_t obuf_flush;
};

struct fw_ctx;

struct fw_lc_cfg {
	struct fw_ctx *ctx;
};

struct kni_lc_cfg {
	struct rte_kni *kni[MAX_NIC_PORTS];
	int8_t port_to_kni[MAX_NIC_PORTS];
	int8_t kni_to_port[MAX_NIC_PORTS];
	uint32_t n_kni;
	uint8_t is_master;
};

struct tap_lc_cfg {
	int taps[MAX_NIC_PORTS];
	int port_to_tap[MAX_NIC_PORTS];
	int8_t tap_to_port[MAX_NIC_PORTS];
	uint32_t n_taps;
};

struct rt_ctx {
	struct ether_addr ogws[MAX_GWS];
	struct ether_addr igws[MAX_GWS];
	uint64_t gws_ts;
	uint8_t n_igws;
	uint8_t n_ogws;
	uint8_t ovlan;
	uint8_t reassembly;
};

struct worker_lc_cfg {
	union {
		struct fw_lc_cfg fw;
		struct kni_lc_cfg kni;
		struct tap_lc_cfg tap;
	};

	/* Rings */
	struct rte_ring *irings[MAX_LCORES];
	uint16_t n_irings;
	struct rte_ring *orings[MAX_NIC_PORTS];

	/* Internal buffers */
	struct mbuf_array ibuf;
	struct mbuf_array obuf[MAX_NIC_PORTS];
	uint8_t obuf_flush[MAX_NIC_PORTS];

	/* Stats */
	uint64_t irings_pkts[MAX_LCORES];
	uint64_t orings_pkts[MAX_NIC_PORTS];
	uint64_t crings_pkts[MAX_CTRL_LCORES];

	/* Control path lcores */
	struct wrk_ring crings[MAX_CTRL_LCORES];
	uint32_t n_crings;

	/* Routing */
	struct rt_ctx rt;

	/* Offloaders (fragment reassembly, syn flood handlers, etc.) */
	struct wrk_ring ol_rings[MAX_OL_LCORES];
	uint32_t n_ol_rings;

	enum worker_type type;
	enum worker_ol_type ol;
	uint8_t pending;
	uint8_t ctrlplane;
	uint8_t id;
};

struct lc_cfg {
	union {
		struct io_lc_cfg io;
		struct worker_lc_cfg worker;
	};
	enum lc_type type;
	struct rte_mempool *pool;
}      __rte_cache_aligned;

union in6_xmm_addr {
	struct in6_addr addr;
	__m128i xmm;
};

struct vlan_info {
	struct in_addr ip;
	struct in_addr ip_net;
	struct in_addr ip_mask;
	union in6_xmm_addr ip6;
	union in6_xmm_addr ip6_net;
	union in6_xmm_addr ip6_mask;
};

struct gw_addr {
	struct in_addr ip;
	struct ether_addr mac;
	uint16_t vlan;
	uint64_t update_ts;
	uint64_t probe_ts;
	uint64_t probes;
};

struct app_cfg {
	/* lcore */
	struct lc_cfg lcores[MAX_LCORES];

	/* Network interfaces */
	struct nic_cfg ifaces[MAX_NIC_PORTS];

	/* Network gateways */
	struct gw_addr igws[MAX_GWS];
	struct gw_addr ogws[MAX_GWS];
	volatile uint16_t ivlan;
	volatile uint16_t ovlan;
	volatile uint8_t n_igws;
	volatile uint8_t n_ogws;
	volatile uint64_t gws_ts;

	/* Local IP addresses */
	struct vlan_info vlans[MAX_VLANS];
	volatile uint64_t vlans_ts;

	/* Main mbuf pools */
	struct rte_mempool *pools[MAX_SOCKETS];

	/* Offload memory pools */
	struct rte_mempool *ol_pools[MAX_SOCKETS];

	/* Rings */
	uint16_t nic_rx_ring_size;
	uint16_t nic_tx_ring_size;
	uint16_t ring_rx_size;
	uint16_t ring_tx_size;

	/* Burst sizes */
	uint16_t io_rx_read_burst_size;
	uint16_t io_rx_write_burst_size;
	uint16_t io_tx_read_burst_size;
	uint16_t io_tx_write_burst_size;
	uint16_t worker_read_burst_size;
	uint16_t worker_write_burst_size;

	/* KNI ports */
	uint16_t n_kni_ports;

	/* Fragmentation options */
	uint16_t frag_max_flow_num;
	uint16_t frag_max_flow_ttl;

}       __rte_cache_aligned;

extern struct app_cfg cfg;
extern struct rte_eth_conf port_conf;
extern volatile uint8_t reload_fw;
extern volatile uint8_t dump_fw_counters;

void cfg_print_settings(void);
int cfg_parse_file(const char *);
int cfg_lcore_for_nic_rx(uint32_t, uint32_t, uint32_t *);
int cfg_lcore_for_nic_tx(uint32_t, uint32_t *);
int cfg_is_socket_used(uint32_t);
uint16_t cfg_nic_rx_queues_per_port(uint32_t);
uint32_t cfg_lcores_io_rx(void);
uint32_t cfg_lcores_worker(void);

void init_app(void);
int lcore_main_loop(void *);

int kni_change_mtu(uint8_t, unsigned int);
int kni_config_network_if(uint8_t, uint8_t);
struct rte_kni *kni_alloc_port(uint8_t, struct lc_cfg *);

int tap_create(const char *, struct nic_cfg *);
int fw_init(void);
void fw_reload(void);
void fw_dump_counters(void);
#endif	/* _MAIN_H_ */
