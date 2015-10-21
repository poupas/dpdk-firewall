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

#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <assert.h>

#include <libconfig.h>

#include <rte_memory.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_debug.h>
#include <rte_common.h>
#include <rte_log.h>

#include "main.h"
#include "util.h"

struct app_cfg cfg;
volatile uint8_t reload_fw;
volatile uint8_t dump_fw_counters;

static int parse_worker_lcores(config_setting_t *);
static int parse_io_lcores(config_setting_t *);
static int parse_rx_lcore(config_setting_t *, uint32_t);
static int parse_tx_lcore(config_setting_t *, uint32_t);
static int parse_fw_lcore(config_setting_t *, uint32_t);
static int parse_kni_lcore(config_setting_t *, uint32_t);
static int parse_tap_lcore(config_setting_t *, uint32_t);
static int parse_ifaces(config_setting_t *);
static int parse_routing(config_setting_t *);
static int check_every_rx_port_is_tx_enabled(void);

static int
parse_worker_lcores(config_setting_t * w_lcores)
{
	int ret;
	uint32_t i, count;

	ret = -1;
	count = config_setting_length(w_lcores);
	for (i = 0; i < count; i++) {
		const char *type;
		config_setting_t *wlcp = config_setting_get_elem(w_lcores, i);
		config_setting_lookup_string(wlcp, "type", &type);
		if (strcmp(type, "fw") == 0) {
			ret = parse_fw_lcore(wlcp, i);
		} else if (strcmp(type, "control") == 0) {
			const char *ktype;
			config_setting_lookup_string(wlcp, "kni_type", &ktype);
			if (strcmp(ktype, "kni") == 0) {
				ret = parse_kni_lcore(wlcp, i);
			} else if (strcmp(ktype, "tap") == 0) {
				ret = parse_tap_lcore(wlcp, i);
			} else {
				RTE_LOG(DEBUG, USER1,
				    "Unknown control worker type.\n");
			}
		} else {
			RTE_LOG(DEBUG, USER1, "Unknown worker lcore type.\n");
		}
	}

	if (ret != 0) {
		RTE_LOG(ERR, USER1,
		    "Could not parse worker lcores. Error: %d.\n", ret);
	}
	return ret;
}

static int
parse_io_lcores(config_setting_t * io_lcores)
{
	uint32_t i, count;

	count = config_setting_length(io_lcores);
	for (i = 0; i < count; i++) {
		const char *type;
		config_setting_t *iolcp = config_setting_get_elem(io_lcores, i);
		config_setting_lookup_string(iolcp, "type", &type);
		if (strcmp(type, "rx") == 0) {
			parse_rx_lcore(iolcp, i);
		} else if (strcmp(type, "tx") == 0) {
			parse_tx_lcore(iolcp, i);
		} else {
			RTE_LOG(DEBUG, USER1, "Uknown IO lcore type.\n");
			return -1;
		}
	}

	return 0;
}

static int
parse_rx_lcore(config_setting_t * rxst, uint32_t id)
{
	struct lc_cfg *lcp;
	config_setting_t *setting;
	unsigned int lcore, count, i;

	config_setting_lookup_int(rxst, "lcore", (int *)&lcore);
	setting = config_setting_get_member(rxst, "queues");
	count = config_setting_length(setting);

	if (count > MAX_NIC_RX_QUEUES_PER_IO_LCORE) {
		RTE_LOG(ERR, USER1, "Core %u has %u rx queues defined. "
		    "Limit is %u. Sorry.\n", lcore, count,
		    MAX_NIC_RX_QUEUES_PER_IO_LCORE);
		return -1;
	}
	if (rte_lcore_is_enabled(lcore) == 0) {
		return -2;
	}
	if (lcore >= MAX_LCORES || id >= MAX_IO_LCORES) {
		return -3;
	}
	/* IO cores cannot have worker roles */
	lcp = &cfg.lcores[lcore];
	if (lcp->type != LCORE_TYPE_IO && lcp->type != LCORE_TYPE_NONE) {
		return -4;
	}
	lcp->type = LCORE_TYPE_IO;

	for (i = 0; i < count; i++) {
		unsigned int port, queue;

		config_setting_t *qs = config_setting_get_elem(setting, i);
		config_setting_lookup_int(qs, "port", (int *)&port);
		config_setting_lookup_int(qs, "queue", (int *)&queue);

		/* Enable port and queue for later initialization */
		if (port >= MAX_NIC_PORTS ||
		    queue >= MAX_RX_QUEUES_PER_NIC_PORT) {
			return -4;
		}
		/* Ensure that this queue is consumed by only one core */
		if (cfg.ifaces[port].rx_queues[queue] != 0) {
			return -5;
		}
		cfg.ifaces[port].rx_queues[queue] = 1;

		for (i = 0; i < lcp->io.rx.n_nic_queues; i++) {
			if ((lcp->io.rx.nic_queues[i].port == port) &&
			    (lcp->io.rx.nic_queues[i].queue == queue)) {
				/* (port,queue) tuple already configured */
				return -6;
			}
		}
		if (lcp->io.rx.n_nic_queues >= MAX_NIC_RX_QUEUES_PER_IO_LCORE) {
			return -7;
		}
		lcp->io.rx.nic_queues[lcp->io.rx.n_nic_queues].port =
		    (uint8_t)port;
		lcp->io.rx.nic_queues[lcp->io.rx.n_nic_queues].queue =
		    (uint8_t)queue;
		lcp->io.rx.n_nic_queues++;
	}

	setting = config_setting_get_member(rxst, "workers");
	count = config_setting_length(setting);

	if (!is_power_of_two(count)) {
		RTE_LOG(DEBUG, USER1, "Workers must be a power of two.\n");
		return -7;
	}
	for (i = 0; i < count; i++) {
		int worker = config_setting_get_int_elem(setting, i);
		/* TODO: sanitize 'worker' value */
		assert(worker >= 0 && worker < MAX_WORKER_LCORES);
		lcp->io.rx.workers_mask |= (1 << worker);
	}

	return 0;
}

static int
parse_tx_lcore(config_setting_t * txst, uint32_t id)
{
	struct lc_cfg *lcp;
	config_setting_t *setting;
	unsigned int i, count, lcore, port;

	config_setting_lookup_int(txst, "lcore", (int *)&lcore);
	setting = config_setting_get_member(txst, "ports");
	count = config_setting_length(setting);

	if (count > MAX_NIC_TX_PORTS_PER_IO_LCORE) {
		RTE_LOG(ERR, USER1, "Core %u has %u tx ports defined. "
		    "Limit is %u. Sorry.\n", lcore, count,
		    MAX_NIC_TX_PORTS_PER_IO_LCORE);
		return -1;
	}
	if (rte_lcore_is_enabled(lcore) == 0) {
		return -2;
	}
	if (lcore >= MAX_LCORES || id >= MAX_IO_LCORES) {
		return -3;
	}
	lcp = &cfg.lcores[lcore];
	if (lcp->type != LCORE_TYPE_IO && lcp->type != LCORE_TYPE_NONE) {
		/* IO cores must perform IO-only functions */
		return -4;
	}
	lcp->type = LCORE_TYPE_IO;

	for (i = 0; i < count; i++) {
		port = config_setting_get_int_elem(setting, i);

		/* Enable port and queue for later initialization */
		if (port >= MAX_NIC_PORTS) {
			return -5;
		}
		if (cfg.ifaces[port].flags & NIC_FLAG_TX_ON) {
			return -6;
		}
		cfg.ifaces[port].flags |= NIC_FLAG_TX_ON;

		/* Ensure that the port is enabled only once */
		for (i = 0; i < lcp->io.tx.n_nic_ports; i++) {
			if (lcp->io.tx.nic_ports[i] == port) {
				return -7;
			}
		}

		lcp->io.tx.nic_ports[lcp->io.tx.n_nic_ports] = (uint8_t)port;
		lcp->io.tx.n_nic_ports++;
	}

	return 0;
}

static int
parse_fw_lcore(config_setting_t * fwst, uint32_t id)
{
	struct lc_cfg *lcp;
	unsigned int lcore, offload;
	int bool;

	config_setting_lookup_int(fwst, "lcore", (int *)&lcore);
	if (rte_lcore_is_enabled(lcore) == 0) {
		return -1;
	}
	if (lcore >= MAX_LCORES || id >= MAX_WORKER_LCORES) {
		return -2;
	}
	lcp = &cfg.lcores[lcore];
	if (lcp->type != LCORE_TYPE_NONE) {
		return -3;
	}
	config_setting_lookup_int(fwst, "offload_type", (int *)&offload);
	if (offload >= WORKER_OL_NUM) {
		return -4;
	}
	lcp->type = LCORE_TYPE_WORKER;
	lcp->worker.id = id;
	lcp->worker.type = WORKER_TYPE_FW;
	lcp->worker.ol = offload;

	config_setting_lookup_bool(fwst, "kni", &bool);
	lcp->worker.ctrlplane = bool;

	return 0;
}

static int
parse_kni_lcore(config_setting_t * knist, uint32_t id)
{
	struct lc_cfg *lcp;
	config_setting_t *setting;
	unsigned int lcore, i, count;
	int bool;

	config_setting_lookup_int(knist, "lcore", (int *)&lcore);
	if (rte_lcore_is_enabled(lcore) == 0) {
		return -1;
	}
	if (lcore >= MAX_LCORES) {
		return -2;
	}
	lcp = &cfg.lcores[lcore];
	if (lcp->type != LCORE_TYPE_NONE) {
		return -3;
	}
	lcp->type = LCORE_TYPE_WORKER;
	lcp->worker.id = id;
	lcp->worker.type = WORKER_TYPE_CTRL_KNI;

	config_setting_lookup_bool(knist, "master", &bool);
	lcp->worker.kni.is_master = bool;

	setting = config_setting_get_member(knist, "ports");
	count = config_setting_length(setting);

	for (i = 0; i < RTE_DIM(lcp->worker.kni.port_to_kni); i++) {
		lcp->worker.kni.port_to_kni[i] = -1;
		lcp->worker.kni.kni_to_port[i] = -1;
	}

	for (i = 0; i < count; i++) {
		struct nic_cfg *nic;
		int port, j;

		port = config_setting_get_int_elem(setting, i);
		assert(port >= 0 && port < MAX_NIC_PORTS);
		lcp->worker.kni.port_to_kni[port] = i;
		lcp->worker.kni.kni_to_port[i] = port;
		lcp->worker.kni.n_kni++;
		cfg.n_kni_ports++;

		/* If interface is bonded, connect KNI to slave nics */
		nic = &cfg.ifaces[port];
		for (j = 0; j < nic->n_slaves; j++) {
			uint32_t slave = nic->slaves[j];
			lcp->worker.kni.port_to_kni[slave] = i;
		}
	}

	return 0;
}

static int
parse_tap_lcore(config_setting_t * knist, uint32_t id)
{
	struct lc_cfg *lcp;
	config_setting_t *setting;
	unsigned int lcore, i, count;

	config_setting_lookup_int(knist, "lcore", (int *)&lcore);
	if (rte_lcore_is_enabled(lcore) == 0) {
		return -1;
	}
	if (lcore >= MAX_LCORES) {
		return -2;
	}
	lcp = &cfg.lcores[lcore];
	if (lcp->type != LCORE_TYPE_NONE) {
		return -3;
	}
	lcp->type = LCORE_TYPE_WORKER;
	lcp->worker.id = id;
	lcp->worker.type = WORKER_TYPE_CTRL_TAP;

	setting = config_setting_get_member(knist, "ports");
	count = config_setting_length(setting);

	for (i = 0; i < RTE_DIM(lcp->worker.tap.port_to_tap); i++) {
		lcp->worker.tap.port_to_tap[i] = -1;
		lcp->worker.tap.tap_to_port[i] = -1;
	}

	for (i = 0; i < count; i++) {
		struct nic_cfg *nic;
		int port, j;

		port = config_setting_get_int_elem(setting, i);
		assert(port >= 0 && port < MAX_NIC_PORTS);
		lcp->worker.tap.port_to_tap[port] = i;
		lcp->worker.tap.tap_to_port[i] = port;
		lcp->worker.tap.n_taps++;

		/* If interface is bonded, connect TAP to slave nics */
		nic = &cfg.ifaces[port];
		for (j = 0; j < nic->n_slaves; j++) {
			uint32_t slave = nic->slaves[j];
			lcp->worker.tap.port_to_tap[slave] = i;
		}
	}

	return 0;
}

static int
check_every_rx_port_is_tx_enabled(void)
{
	uint32_t port;

	for (port = 0; port < MAX_NIC_PORTS; port++) {
		if (cfg_nic_rx_queues_per_port(port) > 0 &&
		    (cfg.ifaces[port].flags & NIC_FLAG_TX_ON) == 0) {
			return -1;
		}
	}

	return 0;
}

uint16_t
cfg_nic_rx_queues_per_port(uint32_t port)
{
	uint32_t i, count;

	if (port >= MAX_NIC_PORTS) {
		return 0;
	}
	count = 0;
	for (i = 0; i < MAX_RX_QUEUES_PER_NIC_PORT; i++) {
		if (cfg.ifaces[port].rx_queues[i] == 1) {
			count++;
		}
	}

	return count;
}

int
cfg_lcore_for_nic_rx(uint32_t port, uint32_t queue, uint32_t *lcore_out)
{
	uint32_t lcore;

	for (lcore = 0; lcore < MAX_LCORES; lcore++) {
		struct lc_cfg *lp = &cfg.lcores[lcore];
		uint32_t i;

		if (cfg.lcores[lcore].type != LCORE_TYPE_IO) {
			continue;
		}
		for (i = 0; i < lp->io.rx.n_nic_queues; i++) {
			if (lp->io.rx.nic_queues[i].port == port &&
			    lp->io.rx.nic_queues[i].queue == queue) {
				*lcore_out = lcore;
				return 0;
			}
		}
	}

	return -1;
}

int
cfg_lcore_for_nic_tx(uint32_t port, uint32_t *lcore_out)
{
	uint32_t lcore;

	for (lcore = 0; lcore < MAX_LCORES; lcore++) {
		struct lc_cfg *lp = &cfg.lcores[lcore];
		uint32_t i;

		if (cfg.lcores[lcore].type != LCORE_TYPE_IO) {
			continue;
		}
		for (i = 0; i < lp->io.tx.n_nic_ports; i++) {
			if (lp->io.tx.nic_ports[i] == port) {
				*lcore_out = lcore;
				return 0;
			}
		}
	}

	return -1;
}

int
cfg_is_socket_used(uint32_t socket)
{
	uint32_t lcore;

	for (lcore = 0; lcore < MAX_LCORES; lcore++) {
		if (cfg.lcores[lcore].type != LCORE_TYPE_NONE) {
			if (socket == rte_lcore_to_socket_id(lcore)) {
				return 1;
			}
		}
	}

	return 0;
}

uint32_t
cfg_lcores_io_rx(void)
{
	uint32_t lcore, count;

	count = 0;
	for (lcore = 0; lcore < MAX_LCORES; lcore++) {
		struct lc_cfg *lcp = &cfg.lcores[lcore];

		if (cfg.lcores[lcore].type != LCORE_TYPE_IO ||
		    lcp->io.rx.n_nic_queues == 0) {
			continue;
		}
		count++;
	}

	return count;
}

uint32_t
cfg_lcores_worker(void)
{
	uint32_t lcore, count;

	count = 0;
	for (lcore = 0; lcore < MAX_LCORES; lcore++) {
		if (cfg.lcores[lcore].type == LCORE_TYPE_WORKER) {
			count++;
		}
	}
	if (count > MAX_WORKER_LCORES) {
		rte_panic("Config error: too many worker lcores.\n");
		return 0;
	}
	return count;
}

static int
parse_bond(int port, config_setting_t * slaves)
{
	int i, count;

	count = config_setting_length(slaves);
	if (count < 1 || count > MAX_NIC_PORTS - 1) {
		return -1;
	}
	for (i = 0; i < count; i++) {
		int slave;

		slave = config_setting_get_int_elem(slaves, i);
		if (slave < 0 || slave > MAX_NIC_PORTS - 1) {
			return -1;
		}
		cfg.ifaces[port].slaves[i] = slave;
		cfg.ifaces[slave].flags |= NIC_FLAG_BOND_SLAVE;
	}
	cfg.ifaces[port].n_slaves = count;
	cfg.ifaces[port].flags |= NIC_FLAG_BOND_IFACE;

	return port;
}

static int
parse_ifaces(config_setting_t * ifaces)
{
	int i, count;
	if (ifaces == NULL) {
		RTE_LOG(DEBUG, USER1, "Could not find any configured NIC.\n");
		return -1;
	}
	count = config_setting_length(ifaces);
	if (count < 1) {
		RTE_LOG(DEBUG, USER1, "No NICS configured.\n");
		return -2;
	}
	for (i = 0; i < count; i++) {
		config_setting_t *nic, *bond;
		/* TODO: config validation and error handling */
		int port;
		const char *zone;
		int reverse;

		nic = config_setting_get_elem(ifaces, i);
		port = -1;
		config_setting_lookup_int(nic, "port", &port);
		if (port < 0 || port >= MAX_NIC_PORTS) {
			return -3;
		}
		bond = config_setting_get_member(nic, "bond");
		if (bond && !parse_bond(port, bond)) {
			return -4;
		}
		config_setting_lookup_string(nic, "zone", &zone);
		config_setting_lookup_bool(nic, "reverse", &reverse);

		if (reverse) {
			cfg.ifaces[port].flags |= NIC_FLAG_REVERSE;
		}
		snprintf(cfg.ifaces[port].zone, sizeof(cfg.ifaces[port].zone),
		    "%s%s", zone, reverse ? "_rev" : "");
	}

	return 0;
};

static int
parse_gateways(config_setting_t * set, volatile struct gw_addr *gws,
    volatile uint8_t *n_gws, uint16_t vlan)
{
	struct in_addr in;
	const char *str;
	int i, count;

	count = config_setting_length(set);
	if (count < 1) {
		RTE_LOG(ERR, USER1, "No gateways provided.\n");
		return -1;
	}
	count = RTE_MIN(count, MAX_GWS);
	for (i = 0; i < count; i++) {
		if ((str = config_setting_get_string_elem(set, i)) == NULL) {
			RTE_LOG(ERR, USER1, "Error fetching gateway\n.");
			return -1;
		}
		if (!inet_pton(AF_INET, str, &in.s_addr)) {
			RTE_LOG(ERR, USER1, "Found invalid gateway: %s\n",
			    str);
			return -1;
		}
		gws[i].ip = in;
		gws[i].vlan = vlan;
	}

	*n_gws = count;

	return 0;
}

static int
parse_routing(config_setting_t * rt)
{
	config_setting_t *gws;
	uint16_t vlan;

	if (rt == NULL) {
		RTE_LOG(ERR, USER1, "Could not find gateways.\n");
		return -1;
	}
	/* Internal gateways */
	if (config_setting_lookup_int(rt, "inside_vlan", (int *)&vlan) !=
	    CONFIG_TRUE) {
		RTE_LOG(ERR, USER1, "Could not find inside vlan.\n");
		return -2;
	}
	if ((gws = config_setting_get_member(rt, "inside_gws")) == NULL) {
		RTE_LOG(ERR, USER1, "Could not find inside gateways.\n");
		return -3;
	}
	if (parse_gateways(gws, cfg.igws, &cfg.n_igws, vlan) < 0) {
		RTE_LOG(ERR, USER1, "Could not parse inside gateways\n.");
		return -4;
	}
	cfg.ivlan = vlan;

	/* External gateways */
	if (config_setting_lookup_int(rt, "outside_vlan", (int *)&vlan) !=
	    CONFIG_TRUE) {
		RTE_LOG(ERR, USER1, "Could not find outside vlan.\n");
		return -2;
	}
	if ((gws = config_setting_get_member(rt, "outside_gws")) == NULL) {
		RTE_LOG(ERR, USER1, "Could not find outside gateways.\n");
		return -6;
	}
	if (parse_gateways(gws, cfg.ogws, &cfg.n_ogws, vlan) < 0) {
		RTE_LOG(ERR, USER1, "Could not parse outside gateways\n.");
		return -7;
	}
	cfg.ovlan = vlan;

	config_setting_lookup_int(
	    rt, "frag_max_flow_num", (int *)&cfg.frag_max_flow_num);

	config_setting_lookup_int(
	    rt, "frag_max_flow_ttl", (int *)&cfg.frag_max_flow_ttl);

	return 0;
};

int
cfg_parse_file(const char *path)
{
	config_t _cfg;
	config_setting_t *setting;
	int result;

	result = -1;
	config_init(&_cfg);
	if (!config_read_file(&_cfg, path)) {
		RTE_LOG(DEBUG, USER1, "%s:%d - %s\n", config_error_file(&_cfg),
		    config_error_line(&_cfg), config_error_text(&_cfg));
		goto done;
	}
	setting = config_lookup(&_cfg, "ifaces");
	if ((result = parse_ifaces(setting)) != 0) {
		goto done;
	}
	setting = config_lookup(&_cfg, "routing");
	if ((result = parse_routing(setting)) != 0) {
		goto done;
	}
	setting = config_lookup(&_cfg, "io_lcores");
	if ((result = parse_io_lcores(setting)) != 0) {
		goto done;
	}
	setting = config_lookup(&_cfg, "worker_lcores");
	if ((result = parse_worker_lcores(setting)) != 0) {
		goto done;
	}
	if ((result = check_every_rx_port_is_tx_enabled()) != 0) {
		RTE_LOG(ERR, USER1, "RX and TX ports do not match. "
		    "Check your configuration file.\n");
		goto done;
	}
	cfg.nic_rx_ring_size = NIC_RX_RING_SIZE;
	cfg.nic_tx_ring_size = NIC_TX_RING_SIZE;
	cfg.ring_rx_size = RING_RX_SIZE;
	cfg.ring_tx_size = RING_TX_SIZE;

	cfg.io_rx_read_burst_size = BURST_SIZE_IO_RX_READ;
	cfg.io_rx_write_burst_size = BURST_SIZE_IO_RX_WRITE;
	cfg.io_tx_read_burst_size = BURST_SIZE_IO_TX_READ;
	cfg.io_tx_write_burst_size = BURST_SIZE_IO_TX_WRITE;
	cfg.worker_read_burst_size = BURST_SIZE_WORKER_READ;
	cfg.worker_write_burst_size = BURST_SIZE_WORKER_WRITE;

done:
	config_destroy(&_cfg);
	return result;
}

void
cfg_print_settings(void)
{
	uint32_t port, queue, lcore, i, j;

	/* Print NIC RX configuration */
	RTE_LOG(DEBUG, USER1, "NIC RX ports: ");
	for (port = 0; port < MAX_NIC_PORTS; port++) {
		uint16_t n_rx_queues = cfg_nic_rx_queues_per_port(port);

		if (n_rx_queues == 0) {
			continue;
		}
		printf("%u (", port);
		for (queue = 0; queue < MAX_RX_QUEUES_PER_NIC_PORT; queue++) {
			if (cfg.ifaces[port].rx_queues[queue] == 1) {
				printf("%u ", queue);
			}
		}
		printf(")  ");
	}
	RTE_LOG(DEBUG, USER1, ";\n");

	/* Print IO lcore RX cfg */
	for (lcore = 0; lcore < MAX_LCORES; lcore++) {
		struct lc_cfg *lcp = &cfg.lcores[lcore];

		if (cfg.lcores[lcore].type != LCORE_TYPE_IO ||
		    lcp->io.rx.n_nic_queues == 0) {
			continue;
		}
		RTE_LOG(DEBUG, USER1, "IO lcore %u (socket %u): ",
		    lcore, rte_lcore_to_socket_id(lcore));

		RTE_LOG(DEBUG, USER1, "RX ports  ");
		for (i = 0; i < lcp->io.rx.n_nic_queues; i++) {
			printf("(%u, %u)  ",
			    (unsigned)lcp->io.rx.nic_queues[i].port,
			    (unsigned)lcp->io.rx.nic_queues[i].queue);
		}
		RTE_LOG(DEBUG, USER1, "; ");

		RTE_LOG(DEBUG, USER1, "Output rings  ");
		for (i = 0; i < lcp->io.rx.n_rings; i++) {
			printf("%p  ", lcp->io.rx.rings[i]);
		}
		RTE_LOG(DEBUG, USER1, ";\n");
	}

	/* Print worker lcore RX configuration */
	for (lcore = 0; lcore < MAX_LCORES; lcore++) {
		struct lc_cfg *lcp = &cfg.lcores[lcore];

		if (cfg.lcores[lcore].type != LCORE_TYPE_WORKER) {
			continue;
		}
		RTE_LOG(DEBUG, USER1, "Worker lcore %u (socket %u) ID %u: ",
		    lcore,
		    rte_lcore_to_socket_id(lcore),
		    (unsigned)lcp->worker.id);

		RTE_LOG(DEBUG, USER1, "Input rings  ");
		for (i = 0; i < lcp->worker.n_irings; i++) {
			printf("%p  ", lcp->worker.irings[i]);
		}

		RTE_LOG(DEBUG, USER1, ";\n");
	}

	/* Print NIC TX configuration */
	RTE_LOG(DEBUG, USER1, "NIC TX ports:  ");
	for (port = 0; port < MAX_NIC_PORTS; port++) {
		if (cfg.ifaces[port].flags & NIC_FLAG_TX_ON) {
			printf("%u  ", port);
		}
	}
	RTE_LOG(DEBUG, USER1, ";\n");

	/* Print IO TX lcore configuration */
	for (lcore = 0; lcore < MAX_LCORES; lcore++) {
		struct lc_cfg *lcp = &cfg.lcores[lcore];
		uint32_t n_workers = cfg_lcores_worker();

		if (cfg.lcores[lcore].type != LCORE_TYPE_IO ||
		    lcp->io.tx.n_nic_ports == 0) {
			continue;
		}
		RTE_LOG(DEBUG, USER1, "IO lcore %u (socket %u): ",
		    lcore, rte_lcore_to_socket_id(lcore));

		RTE_LOG(DEBUG, USER1, "Input rings per TX port  ");
		for (i = 0; i < lcp->io.tx.n_nic_ports; i++) {
			port = lcp->io.tx.nic_ports[i];

			printf("%u (", port);
			for (j = 0; j < n_workers; j++) {
				printf("%p  ", lcp->io.tx.rings[port][j]);
			}
			printf(")  ");

		}

		RTE_LOG(DEBUG, USER1, ";\n");
	}

	/* Print worker lcore TX cfg */
	for (lcore = 0; lcore < MAX_LCORES; lcore++) {
		struct lc_cfg *lcp = &cfg.lcores[lcore];

		if (cfg.lcores[lcore].type != LCORE_TYPE_WORKER) {
			continue;
		}
		RTE_LOG(DEBUG, USER1, "Worker lcore %u (socket %u) ID %u: \n",
		    lcore,
		    rte_lcore_to_socket_id(lcore),
		    (unsigned)lcp->worker.id);

		RTE_LOG(DEBUG, USER1, "Output rings per TX port  ");
		for (port = 0; port < MAX_NIC_PORTS; port++) {
			if (lcp->worker.orings[port] != NULL) {
				printf("%u (%p)  ",
				    port, lcp->worker.orings[port]);
			}
		}

		RTE_LOG(DEBUG, USER1, ";\n");
	}

	/* Rings */
	RTE_LOG(DEBUG, USER1, "Ring sizes: NIC RX = %u; Worker in = %u; "
	    "Worker out = %u; NIC TX = %u;\n",
	    (unsigned)cfg.nic_rx_ring_size,
	    (unsigned)cfg.ring_rx_size,
	    (unsigned)cfg.ring_tx_size,
	    (unsigned)cfg.nic_tx_ring_size);

	/* Bursts */
	RTE_LOG(DEBUG, USER1, "Burst sizes: IO RX (rd = %u, wr = %u); Worker "
	    "(rd = %u, wr = %u); IO TX (rd = %u, wr = %u)\n",
	    (unsigned)cfg.io_rx_read_burst_size,
	    (unsigned)cfg.io_rx_write_burst_size,
	    (unsigned)cfg.worker_read_burst_size,
	    (unsigned)cfg.worker_write_burst_size,
	    (unsigned)cfg.io_tx_read_burst_size,
	    (unsigned)cfg.io_tx_write_burst_size);
}
