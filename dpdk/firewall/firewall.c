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

#include <inttypes.h>

#include <rte_memory.h>
#include <rte_common.h>
#include <rte_lcore.h>
#include <rte_ip_frag.h>

#include "main.h"
#include "runtime.h"
#include "packet.h"
#include "acl.h"
#include "forward.h"
#include "zone.h"
#include "nat.h"
#include "ip6.h"
#include "frag.h"

/*
 * BATCH_SIZE must be a power of 2.
 * Do note that currently we assume that this is value is 4.
 * If you decide to change this remember, to also change the functions:
 * fwd_pkts, nat_ip_4pkts
 */
#define BATCH_SIZE 4

#define ETH_HEAD_OFF (sizeof(struct ether_hdr))
#define IP_OFF2PROTO (offsetof(struct ipv4_hdr, next_proto_id))
#define IP_DATA_2PROTO(data) (data + ETH_HEAD_OFF + IP_OFF2PROTO)
#define IP6_OFF2PROTO (offsetof(struct ipv6_hdr, proto))
#define IP6_DATA_2PROTO(data) (data + ETH_HEAD_OFF + IP6_OFF2PROTO)

#define PORT2ZONE(port) (nic_zone[(port)]->id)
#define PKT2ZONE(pkt, ctx)					\
	(PKT_VLANID((pkt)->vlan_tci) == ctx->cfg->rt.ovlan ?	\
	    PORT2ZONE((pkt)->port) : 				\
	    MAX_ZONES)

struct fw_ctx {
	struct acl_ctx acl;
	struct acl_counter counters[MAX_ZONES][MAX_ACL_COUNTERS];
	struct frag_ctx frag;

	struct worker_lc_cfg *cfg;

	/* Used by the control core(s) to request action by this core */
	volatile uint32_t ctrl_request;

}      __rte_cache_aligned;

struct fw_cron {
	uint64_t flush;
	uint64_t tasks;
	uint64_t stats;

	uint64_t last_stats;
};

static struct fw_ctx *workers[MAX_FW_LCORES];
rte_atomic16_t n_workers;

static struct zone_cfg zones[MAX_ZONES];
static uint32_t n_zones;
static struct zone_cfg tmp_zone;

static struct zone_cfg *nic_zone[MAX_NIC_PORTS];

static struct zone_cfg *
get_zone_cfg(const char *name)
{
	struct zone_cfg *zp;
	uint32_t i;

	zp = NULL;
	for (i = 0; i < MAX_ZONES; i++) {
		if (strncmp(name, zones[i].name, sizeof(zones[i].name) - 1)
		    == 0) {
			zp = &zones[i];
			break;
		}
	}

	return zp;
}

static inline void
reset_ctx_counters(struct fw_ctx *ctx)
{
	if (ctx != NULL &&
	    unlikely(ctx->ctrl_request & WORKER_REQ_RESET_CNT)) {
		RTE_LOG(INFO, USER1, "Resetting ACL rule counters...\n");
		memset(ctx->counters, 0, sizeof(ctx->counters));
		ctx->ctrl_request &= ~WORKER_REQ_RESET_CNT;
	}
}

static void
update_zone(struct zone_cfg *zp, struct zone_cfg *tmp)
{
	uint32_t i, wrk_cnt;

	for (i = 0; i < MAX_SOCKETS; i++) {

		printf("old acl_ctx: %p, new acl_ctx: %p\n", zp->ip_acl[i],
		    tmp->ip_acl[i]);

		tmp->ip_acl[i] =
		    rcu_xchg_pointer(&zp->ip_acl[i], tmp->ip_acl[i]);
		tmp->ip6_acl[i] =
		    rcu_xchg_pointer(&zp->ip6_acl[i], tmp->ip6_acl[i]);
		/*
		 * tmp->ip_nat_k[i] = rcu_xchg_pointer(&zp->ip_nat_k[i],
		 * tmp->ip_nat_k[i]); tmp->ip_nat_v[i] =
		 * rcu_xchg_pointer(&zp->ip_nat_v[i], tmp->ip_nat_v[i]);
		 */
	}

	zp->version = tmp->version + 1;
	zp->n_rules = tmp->n_rules;
	rte_memcpy(zp->rules, tmp->rules, sizeof(tmp->rules));

	wrk_cnt = rte_atomic16_read(&n_workers);
	for (i = 0; i < wrk_cnt; i++) {
		struct fw_ctx *ctx = workers[i];
		if (ctx != NULL) {
			ctx->ctrl_request |= WORKER_REQ_RESET_CNT;
		}
	}

	synchronize_rcu();
}

/*
 * Deprecated:
 * The forwarding code will check the timestamp for every pkt.
 */
static inline void
refresh_routes(struct fw_ctx *ctx)
{
	if (likely(ctx->cfg->rt.gws_ts == cfg.gws_ts)) {
		return;
	}

	rt_refresh_gws(&ctx->cfg->rt);
}

static inline void
refresh_settings(struct fw_ctx *ctx)
{
	if (likely(ctx != NULL && ctx->ctrl_request == 0)) {
		return;
	}
	reset_ctx_counters(ctx);
}

static void
dump_zone_counters(struct zone_cfg *zone)
{
	char buffer[MAX_ACL_STR_SIZE];
	int16_t wrk, wrk_cnt;
	uint8_t rule;

	wrk_cnt = rte_atomic16_read(&n_workers);

	snprintf(buffer, sizeof(buffer), "Stats for zone: %s\n", zone->name);
	RTE_LOG(INFO, USER1, "%s", buffer);

	for (rule = 0; rule < zone->n_rules; rule++) {
		uint64_t packets = 0, bytes = 0;

		for (wrk = 0; wrk < wrk_cnt; wrk++) {
			struct acl_counter *acl_cnt;
			if (workers[wrk] == NULL) {
				continue;
			}
			acl_cnt = workers[wrk]->counters[zone->id];
			packets += acl_cnt[rule].packets;
			bytes += acl_cnt[rule].bytes;
		}
		snprintf(buffer, sizeof(buffer),
		    "%spackets %" PRIu64 " bytes %" PRIu64 "\n",
		    zone->rules[rule], packets, bytes);
		RTE_LOG(INFO, USER1, "%s", buffer);
	}
}

static int
reload_zone(struct zone_cfg *zone)
{
	struct zone_cfg *tmp;
	int ret;

	/* Zone not initialized */
	if (strlen(zone->name) == 0) {
		return 0;
	}
	RTE_LOG(INFO, USER1, "(Re)Loading firewall zone config: %s...\n",
	    zone->name);

	tmp = &tmp_zone;
	memset(tmp, 0, sizeof(struct zone_cfg));
	strlcpy(tmp->name, zone->name, sizeof(tmp->name));
	tmp->id = zone->id;
	tmp->reverse = zone->reverse;
	tmp->version = zone->version;

	if ((ret = acl_parse_rules(tmp)) != 0) {
		RTE_LOG(WARNING, USER1, "Could not parse ACLs for zone %s!\n",
		    zone->name);
		goto cleanup;
	}
	/*
	 * if ((ret = nat_parse_rules(tmp)) != 0) { RTE_LOG(WARNING, USER1,
	 * "Could not parse NAT for zone %s!\n", zone->name); goto cleanup; }
	 */

	update_zone(zone, tmp);
	ret = 0;

	RTE_LOG(INFO, USER1, "Firewall zone %s (re)loaded successfully!\n",
	    zone->name);
cleanup:
	acl_free_rules(tmp);
	nat_free_rules(tmp);

	return ret;
}

void
fw_dump_counters(void)
{
	uint32_t i;

	for (i = 0; i < MAX_ZONES; i++) {
		dump_zone_counters(&zones[i]);
	}
}

void
fw_reload(void)
{
	uint32_t i;

	for (i = 0; i < MAX_ZONES; i++) {
		reload_zone(&zones[i]);
	}
}

int
fw_init(void)
{
	int ret;
	uint32_t port;

	rte_atomic16_init(&n_workers);

	for (port = 0; port < MAX_NIC_PORTS; port++) {
		struct zone_cfg *zp;
		char *zone;

		zone = cfg.ifaces[port].zone;

		/* No zone defined */
		if (zone[0] == 0) {
			continue;
		}

		zp = get_zone_cfg(zone);
		if (zp == NULL) {
			strlcpy(zones[n_zones].name, zone,
			    sizeof(zones[n_zones].name));
			zp = &zones[n_zones];
			zp->reverse = cfg.ifaces[port].flags & NIC_FLAG_REVERSE;
			zp->id = n_zones;
			if ((ret = reload_zone(zp)) != 0) {
				return ret;
			}
			n_zones++;
		}
		nic_zone[port] = zp;
	}

	return 0;
}

static inline struct rte_mbuf *
handle_ip_frag(struct ipv4_hdr *hdr, struct rte_mbuf *pkt)
{

	if (!hdr || !pkt) {
		return NULL;
	}
	return NULL;
}

static inline uint8_t *
setup_ip_acl_data(struct rte_mbuf *pkt, uint8_t reassembly, struct fw_ctx *ctx)
{
	struct ipv4_hdr *ip_hdr;
	uint8_t *ehp;

	ehp = rte_pktmbuf_mtod(pkt, uint8_t *);
	ip_hdr = (struct ipv4_hdr *)(ehp + sizeof(struct ether_hdr));

	/* Accept IPv4 packets with no extra options */
	if (unlikely(PKT_IP_HDR_LEN(ip_hdr) != IP_HDR_LEN)) {
		return NULL;
	}

	/* Check for fragments */
	if (unlikely(rte_ipv4_frag_pkt_is_fragmented(ip_hdr) && reassembly)) {
		switch (ctx->cfg->ol) {
		case WORKER_OL_PROV:
			pkt->udata64 |= PKT_META_OL;
			if (frag_ip_reass(&ctx->frag, ip_hdr, pkt) == NULL) {
				return NULL;
			}
			break;
		case WORKER_OL_CLNT:
			pkt->udata64 |= PKT_META_OL;
			/* Offload fragment to offloader cores */
			fwd_ol_pkt(pkt, ctx->cfg);
			return NULL;
		default:
			break;
		}

		/* XXX: ehp must be updated here */
	}
	return IP_DATA_2PROTO(ehp);
}

static inline uint8_t *
build_alt_ip6_hdr(struct rte_mbuf *pkt, uint32_t exthdrs, uint8_t *l4hdr,
    uint16_t l4proto)
{
	uint8_t *hdr, *althdr;

	hdr = rte_pktmbuf_mtod(pkt, uint8_t *);
	althdr = hdr + pkt->data_len;
	hdr += ETH_HEAD_OFF;

	if (l4hdr != NULL) {
		rte_memcpy(althdr, hdr, sizeof(struct ipv6_hdr));
		rte_memcpy(althdr + sizeof(struct ipv6_hdr), l4hdr, L4_HDR_LEN);
		((struct ipv6_hdr *)althdr)->proto = l4proto;
	} else if (exthdrs & IP6_EH_FRAGMENT) {
		rte_memcpy(althdr, hdr, sizeof(struct ipv6_hdr));
		((struct ipv6_hdr *)althdr)->proto = IPPROTO_FRAGMENT;
	} else if ((exthdrs & IP6_EH_INVALID) == 0) {	/* Ext header found */
		althdr = hdr;
	} else {
		althdr = NULL;
	}

	return althdr;
}

static inline uint8_t *
setup_ip6_acl_data(struct rte_mbuf *pkt)
{
	uint8_t *l4hdr;
	uint16_t l4proto;
	uint32_t exthdrs;

	l4hdr = NULL;
	exthdrs = ip6_parse_hdrs(pkt, &l4hdr, &l4proto);
	if (likely(exthdrs == 0 && l4hdr != NULL)) {
		return IP6_DATA_2PROTO(rte_pktmbuf_mtod(pkt, uint8_t *));
	} else {
		uint8_t *hdr;
		hdr = build_alt_ip6_hdr(pkt, exthdrs, l4hdr, l4proto);
		return hdr ? hdr + IP6_OFF2PROTO : NULL;
	}
}

/*
 * Make sure that the ACL mbuf array is contiguous.
 */
static inline void
compact_ip_acl(struct acl_ctx *acl)
{
	uint32_t i, next;

	next = 0;
	for (i = 0; i < acl->n_ip; i++) {
		if (acl->ip_m[i] != NULL && next == i) {
			next++;
		} else if (acl->ip_m[i] != NULL) {
			acl->ip_m[next] = acl->ip_m[i];
			acl->ip_m[i] = NULL;
			acl->n_ip--;
			next++;
		}
	}
}

static inline void
setup_pkt_acl(struct rte_mbuf *pkt, struct fw_ctx *ctx)
{
	struct acl_ctx *acl;
	uint8_t *data;
	uint32_t ptype;

	acl = &ctx->acl;
	ptype = PKT_TYPE(pkt);

	if (ptype & RTE_PTYPE_L3_IPV4) {
		data = setup_ip_acl_data(pkt, ctx->cfg->rt.reassembly, ctx);
		if (unlikely(data == NULL)) {
			if (pkt->udata64 & PKT_META_OL) {
				RTE_LOG(DEBUG, ACL, "reassembling packet");
			} else {
				pkt_dump(pkt, "dropping packet: ");
				rte_pktmbuf_free(pkt);
			}
			return;
		}
		acl->ip_data[acl->n_ip] = data;
		acl->ip_m[acl->n_ip] = pkt;
		acl->n_ip++;

	} else if (ptype & RTE_PTYPE_L3_IPV6) {
		/* Header processing */
		data = setup_ip6_acl_data(pkt);
		if (unlikely(data == NULL)) {
			rte_pktmbuf_free(pkt);
			return;
		}
		acl->ip6_data[acl->n_ip6] = data;
		acl->ip6_m[acl->n_ip6] = pkt;
		acl->n_ip6++;
	} else {
		/* We only filter IPv4 and IPv6 for now. */
		fwd_ctrl_pkt(pkt, ctx->cfg);
	}
}

static inline unsigned
__attribute__((always_inline))
setup_acl_search(struct rte_mbuf **pkts, uint32_t offset, struct fw_ctx *ctx,
    uint32_t n, uint8_t *zid)
{
	unsigned i, nbatch;
	uint8_t zone;

	zone = PKT2ZONE(pkts[offset], ctx);
	*zid = zone;
	ctx->acl.n_ip = 0;
	ctx->acl.n_ip6 = 0;

	/* Prefetch first packets */
	for (i = offset; i < BATCH_SIZE && i < n; i++) {
		rte_prefetch0(rte_pktmbuf_mtod(pkts[i], void *));
	}

	nbatch = RTE_ALIGN_FLOOR(n, BATCH_SIZE);
	for (i = offset; i < nbatch; i += BATCH_SIZE) {
		if (unlikely(PKT2ZONE(pkts[i], ctx) != zone)) {
			return i;
		}
		setup_pkt_acl(pkts[i], ctx);

		if (unlikely(PKT2ZONE(pkts[i + 1], ctx) != zone)) {
			return i + 1;
		}
		setup_pkt_acl(pkts[i + 1], ctx);

		if (unlikely(PKT2ZONE(pkts[i + 2], ctx) != zone)) {
			return i + 2;
		}
		setup_pkt_acl(pkts[i + 2], ctx);

		if (unlikely(PKT2ZONE(pkts[i + 3], ctx) != zone)) {
			return i + 3;
		}
		setup_pkt_acl(pkts[i + 3], ctx);
	}

	/* Process remaining packets */
	for (; i < n; i++) {
		if (unlikely(PKT2ZONE(pkts[i], ctx) != zone)) {
			return i;
		}
		setup_pkt_acl(pkts[i], ctx);
	}

	return i;
}

static inline void
nat_ip_pkts(struct rte_hash *ht, uint32_t *ips, struct rte_mbuf **pkts,
    uint32_t *res, uint32_t n_pkts)
{
	uint32_t i, nbatch, natmask;

	natmask = ACL_ACTION_SNAT | ACL_ACTION_DNAT;
	nbatch = RTE_ALIGN_FLOOR(n_pkts, BATCH_SIZE);
	for (i = 0; i < nbatch; i += BATCH_SIZE) {
		uint32_t nat = 0;

		nat = (res[i] & natmask) && (res[i + 1] & natmask) &&
		    (res[i + 2] & natmask) && (res[i + 3] & natmask);

		if (nat) {	/* NAT BATCH_SIZE packets at once */
			nat_ip_4pkts(&pkts[i], ht, ips, res);
		} else {	/* (Possibly) NAT each packet individually */
			nat_ip_pkt(pkts[i], ht, ips, res[i]);
			nat_ip_pkt(pkts[i + 1], ht, ips, res[i + 1]);
			nat_ip_pkt(pkts[i + 2], ht, ips, res[i + 2]);
			nat_ip_pkt(pkts[i + 3], ht, ips, res[i + 3]);
		}
	}

	/* Process remaining packets */
	for (; i < n_pkts; i++) {
		nat_ip_pkt(pkts[i], ht, ips, res[i]);
	}
}

static inline void
fwd_acl_pkt(struct worker_lc_cfg *lp, struct rte_mbuf *pkt, uint32_t res)
{
	if (unlikely(res & ACL_ACTION_COUNT)) {
		uint8_t id = ACL_COUNT_ID(res);
		uint8_t zone = PORT2ZONE(pkt->port);
		lp->fw.ctx->counters[zone][id].packets++;
		lp->fw.ctx->counters[zone][id].bytes += pkt->data_len;
	}
	if (unlikely(res & ACL_ACTION_MONIT)) {
		struct rte_mbuf *clone;
		clone = rte_pktmbuf_clone(pkt, cfg.pools[rte_socket_id()]);
		fwd_ctrl_pkt(clone, lp);
	}
	if (likely(res & ACL_ACTION_ACCEPT)) {
		if (likely(!rt_is_local(pkt))) {
			fwd_nic_pkt(pkt, lp);
		} else {
			pkt->udata64 |= PKT_META_LOCAL;
			fwd_ctrl_pkt(pkt, lp);
		}
	} else {
		pkt_dump(pkt, "dropping packet: ");
		rte_pktmbuf_free(pkt);
	}
}

static inline void
fwd_pkt(struct worker_lc_cfg *lp, struct rte_mbuf *pkt)
{
	if (likely(!rt_is_local(pkt))) {
		fwd_nic_pkt(pkt, lp);
	} else {
		pkt->udata64 |= PKT_META_LOCAL;
		fwd_ctrl_pkt(pkt, lp);
	}
}

static inline void
fwd_acl_pkts(struct worker_lc_cfg *lp, struct rte_mbuf **pkts, uint32_t *res,
    uint32_t n_pkts)
{
	uint32_t i, nbatch;

	nbatch = RTE_ALIGN_FLOOR(n_pkts, BATCH_SIZE);
	for (i = 0; i < nbatch; i += BATCH_SIZE) {
		fwd_acl_pkt(lp, pkts[i], res[i]);
		fwd_acl_pkt(lp, pkts[i + 1], res[i + 1]);
		fwd_acl_pkt(lp, pkts[i + 2], res[i + 2]);
		fwd_acl_pkt(lp, pkts[i + 3], res[i + 3]);
	}

	for (; i < n_pkts; i++) {
		fwd_acl_pkt(lp, pkts[i], res[i]);
	}
}

static inline void
__attribute__((always_inline))
fwd_pkts(struct worker_lc_cfg *lp, struct rte_mbuf **pkts, uint32_t n_pkts)
{
	uint32_t i, nbatch;

	nbatch = RTE_ALIGN_FLOOR(n_pkts, BATCH_SIZE);
	for (i = 0; i < nbatch; i += BATCH_SIZE) {
		fwd_pkt(lp, pkts[i]);
		fwd_pkt(lp, pkts[i + 1]);
		fwd_pkt(lp, pkts[i + 2]);
		fwd_pkt(lp, pkts[i + 3]);
	}

	for (; i < n_pkts; i++) {
		fwd_pkt(lp, pkts[i]);
	}

}


static inline uint32_t
__attribute__((always_inline))
check_pkts(struct fw_ctx *ctx, uint32_t burst, uint32_t ring_n)
{
	struct rte_mbuf **pktbuf;
	struct rte_ring *ring;
	struct acl_ctx *acl;
	struct rte_acl_ctx *acl_ctx;
	unsigned n_rx, offset;
	unsigned sockid;

	acl = &ctx->acl;
	pktbuf = ctx->cfg->ibuf.array;
	ring = ctx->cfg->irings[ring_n];

	n_rx = rte_ring_sc_dequeue_burst(ring, (void **)pktbuf, burst);
	if (unlikely(n_rx > burst)) {
		RTE_LOG(CRIT, USER1, "FW: error receiving from ring!\n");
		return 0;
	}
	if (unlikely(n_rx == 0)) {
		return 0;
	}

#ifdef APP_STATS
	ctx->cfg->irings_pkts[ring_n] += n_rx;
#endif

	sockid = rte_socket_id();
	offset = 0;
	rcu_read_lock();

	while (offset < n_rx) {
		unsigned n_left;
		uint8_t zid;

		n_left = n_rx - offset;
		offset = setup_acl_search(pktbuf, offset, ctx, n_left, &zid);

		/* IPv4 */
		if (likely(acl->n_ip)) {

			/* Apply ACLs if required */
			if (zid < MAX_ZONES && (acl_ctx =
			    rcu_dereference(zones[zid].ip_acl[sockid]))) {
				rte_acl_classify(
				    acl_ctx,
				    acl->ip_data,
				    acl->ip_res,
				    acl->n_ip,
				    MAX_ACL_CATEGORIES);

				fwd_acl_pkts(
				    ctx->cfg,
				    acl->ip_m,
				    acl->ip_res,
				    acl->n_ip);

				/* Forward packets without filtering */
			} else {
				fwd_pkts(ctx->cfg, acl->ip_m, acl->n_ip);
			}
		}

		/* IPv6 */
		if (likely(acl->n_ip6)) {
			/* Apply ACLs if required */
			if (zid < MAX_ZONES && (acl_ctx =
			    rcu_dereference(zones[zid].ip6_acl[sockid]))) {
				rte_acl_classify(
				    acl_ctx,
				    acl->ip6_data,
				    acl->ip6_res,
				    acl->n_ip6,
				    MAX_ACL_CATEGORIES);

				fwd_acl_pkts(
				    ctx->cfg,
				    acl->ip6_m,
				    acl->ip6_res,
				    acl->n_ip6);

				/* Forward packets without filtering */
			} else {
				fwd_pkts(ctx->cfg, acl->ip6_m, acl->n_ip6);
			}
		}
	}
	rcu_read_unlock();

	return n_rx;
}

static inline uint32_t
offload_pkts(struct fw_ctx *ctx, uint32_t burst, uint32_t ring_n)
{
	return check_pkts(ctx, burst, ring_n);
}

static inline void
__attribute__((always_inline))
cron_cnt(struct fw_ctx *ctx, struct fw_cron *cron)
{

	if (LCORE_WORKER_FLUSH &&
	    (unlikely(cron->flush == LCORE_WORKER_FLUSH))) {
		cron->flush = 0;
		if (ctx->cfg->pending) {
			flush_nic_buffers(ctx->cfg);
			flush_ctrl_buffers(ctx->cfg);
			flush_ol_buffers(ctx->cfg);
			ctx->cfg->pending = 0;
		}
	}
	if (LCORE_WORKER_TASKS &&
	    (unlikely(cron->tasks == LCORE_WORKER_TASKS))) {
		rcu_quiescent_state();
		refresh_settings(ctx);
		cron->tasks = 0;
	}

	if (APP_STATS &&
	    (unlikely(cron->stats == APP_STATS))) {
		uint64_t elapsed_us = TSC2US(now_tsc - cron->last_stats);
		if (elapsed_us > 5 * US_PER_S) {
			wrk_pkt_stats(ctx->cfg, &cron->last_stats);
		}
		cron->stats = 0;
	}

	cron->flush++;
	cron->tasks++;
	cron->stats++;
}

static inline void
cron_tsc(struct fw_ctx *ctx, struct fw_cron *cron)
{
	uint64_t now = now_tsc;

	if (unlikely(now > cron->flush)) {
		if (ctx->cfg->pending) {
			flush_nic_buffers(ctx->cfg);
			flush_ctrl_buffers(ctx->cfg);
			flush_ol_buffers(ctx->cfg);
			ctx->cfg->pending = 0;
		}
		cron->flush = now + US2TSC(LCORE_WORKER_FLUSH_US);
	}
	if (unlikely(now > cron->tasks)) {
		rcu_quiescent_state();
		refresh_settings(ctx);
		cron->tasks = now + US2TSC(LCORE_WORKER_TASKS_US);
	}
}

static struct fw_ctx *
init_ctx(struct worker_lc_cfg *lp)
{
	struct fw_ctx *ctx;
	char name[64];
	size_t size;
	int16_t n;

	snprintf(name, sizeof(name), "fw_wrk_%u", lp->id);
	size = RTE_CACHE_LINE_ROUNDUP(sizeof(struct fw_ctx));
	ctx = rte_zmalloc(name, size, RTE_CACHE_LINE_SIZE);
	if (ctx == NULL) {
		rte_panic("Error creating firewall context for worker %u.\n",
		    lp->id);
	}
	ctx->cfg = lp;
	lp->fw.ctx = ctx;
	lp->rt.ovlan = cfg.ovlan;

	n = rte_atomic16_add_return(&n_workers, 1) - 1;
	workers[n] = ctx;

	return ctx;
}


void
fw_lcore_main_loop_cnt(struct worker_lc_cfg *lp)
{
	struct fw_cron cron = {0};
	struct fw_ctx *ctx;
	uint32_t ring, n_rings, burst;
	uint32_t idle;

	burst = cfg.worker_read_burst_size;
	n_rings = lp->n_irings;
	ctx = init_ctx(lp);
	idle = 0;

	for (;;) {
		cron_cnt(ctx, &cron);
		for (ring = 0; ring < n_rings; ring++) {
			if (check_pkts(ctx, burst, ring)) {
				idle = 0;
			}
		}

		idle_heuristic(idle);
		if (lp->pending == 0) {
			idle++;
		} else {
			idle = 0;
		}
	}
}

void
fw_lcore_main_loop_tsc(struct worker_lc_cfg *lp)
{
	struct fw_cron cron = {0};
	struct fw_ctx *ctx;
	uint32_t ring, n_rings, burst;
	uint32_t idle;

	burst = cfg.worker_read_burst_size;
	n_rings = lp->n_irings;
	ctx = init_ctx(lp);
	idle = 0;

	for (;;) {
		cron_tsc(ctx, &cron);
		for (ring = 0; ring < n_rings; ring++) {
			if (check_pkts(ctx, burst, ring)) {
				idle = 0;
			}
		}

		idle_heuristic(idle);
		if (lp->pending == 0) {
			idle++;
		} else {
			idle = 0;
		}
	}
}
