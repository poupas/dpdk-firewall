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
#include "synauth.h"

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
	struct synauth_ctx sauth;

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
static struct fw_ctx *offldrs[MAX_OL_LCORES];
rte_atomic16_t n_workers;
rte_atomic16_t n_offldrs;

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
 * The forwarding code will check the gateway timestamp for every pkt.
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
	rte_atomic16_init(&n_offldrs);

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

static inline uint8_t *
setup_ip_acl_data(struct rte_mbuf **mr, struct fw_ctx *ctx)
{
	struct rte_mbuf *m;
	struct ipv4_hdr *ih;
	uint8_t *ehp;

	m = *mr;
	ehp = rte_pktmbuf_mtod(m, uint8_t *);
	ih = (struct ipv4_hdr *)(ehp + sizeof(struct ether_hdr));

	/*
	 * Accept only IPv4 packets with no extra options.
	 *
	 * It is assumed that the size of an IPv4 header is 20 bytes.
	 * This check ensures that assumption is valid.
	 * Stuff will break otherwise (see ip_l4_hdr in packet.h).
	 */
	if (PKT_IP_HDR_LEN(ih) != IP_HDR_LEN) {
		return NULL;
	}

	/* Check for fragments */
	if (rte_ipv4_frag_pkt_is_fragmented(ih) && ctx->cfg->rt.reassembly) {
		uint64_t udata64;

		ehp = NULL;

		switch (ctx->cfg->ol) {
		case WORKER_OL_PROV:
			m->udata64 |= PKT_META_OL_IP;
			udata64 = m->udata64;

			if ((m = frag_ip_reass(&ctx->frag, ih, m)) == NULL) {
				break;
			}
			ehp = rte_pktmbuf_mtod(m, uint8_t *);
			*mr = m;
			m->udata64 = udata64;
			break;

		case WORKER_OL_CLNT:
			m->udata64 |= PKT_META_OL_IP;
			/* Offload fragment to offloader cores */
			fwd_ol_pkt(m, ctx->cfg);
			break;

		default:
			RTE_LOG(WARNING, USER1, "Unknown offload type!\n");
			break;
		}
	}

	return ehp ? IP_DATA_2PROTO(ehp) : NULL;
}

static inline uint8_t *
build_alt_ip6_hdr(struct rte_mbuf *m, uint32_t exthdrs, uint8_t *l4hdr,
    uint16_t l4proto)
{
	struct mbuf_extra *extra;
	uint8_t *althdr, *hdr;

	hdr = rte_pktmbuf_mtod(m, uint8_t *);
	althdr = NULL;
	extra = (struct mbuf_extra *)(hdr + m->data_len);

	hdr += ETH_HEAD_OFF;

	if (l4hdr != NULL) {
		m->udata64 |= PKT_META_ALT_HDR;
		extra->l4hdr = l4hdr;
		althdr = extra->hdrs;
		rte_memcpy(althdr, hdr, sizeof(struct ipv6_hdr));
		rte_memcpy(althdr + sizeof(struct ipv6_hdr), l4hdr, L4_HDR_LEN);
		((struct ipv6_hdr *)althdr)->proto = l4proto;

	} else if (exthdrs & IP6_EH_FRAGMENT) {
		m->udata64 |= PKT_META_ALT_HDR;
		extra->l4hdr = NULL;
		althdr = extra->hdrs;
		rte_memcpy(althdr, hdr, sizeof(struct ipv6_hdr));
		((struct ipv6_hdr *)althdr)->proto = IPPROTO_FRAGMENT;

	} else if ((exthdrs & IP6_EH_INVALID) == 0) {	/* Ext header found */
		althdr = hdr;
	}

	return althdr;
}

static inline uint8_t *
setup_ip6_acl_data(struct rte_mbuf **mr, struct fw_ctx *ctx)
{
	struct rte_mbuf *m;
	uint8_t *l4hdr;
	uint32_t exthdrs;
	uint16_t l4proto;

	m = *mr;
	l4hdr = NULL;
	exthdrs = ip6_parse_hdrs(m, &l4hdr, &l4proto);

	/* No extra headers */
	if (exthdrs == 0 && l4hdr != NULL) {
		return IP6_DATA_2PROTO(rte_pktmbuf_mtod(m, uint8_t *));
	}
	/* Extra headers but not a fragment */
	if (!(exthdrs & IP6_EH_FRAGMENT)) {
		uint8_t *ih = build_alt_ip6_hdr(m, exthdrs, l4hdr, l4proto);
		return ih ? ih + IP6_OFF2PROTO : NULL;
	}
	/* Fragment */
	if (!ctx->cfg->rt.reassembly) {
		/* XXX: use fake header to filter fragment? */
		return NULL;
	}

	switch (ctx->cfg->ol) {
	uint64_t udata64;

	case WORKER_OL_PROV:
		m->udata64 |= PKT_META_OL_IP6;
		udata64 = m->udata64;

		if ((m = frag_ip6_reass(&ctx->frag, m)) == NULL) {
			return NULL;
		}
		*mr = m;
		m->udata64 = udata64;

		return setup_ip6_acl_data(mr, ctx);
		break;

	case WORKER_OL_CLNT:
		m->udata64 |= PKT_META_OL_IP6;
		/* Offload fragment to offloader cores */
		fwd_ol_pkt(m, ctx->cfg);
		break;

	default:
		RTE_LOG(WARNING, USER1, "Unknown offload type!\n");
		break;
	}

	return NULL;
}

static inline uint32_t
compact_pkt_array(struct rte_mbuf **pkts, uint32_t n_pkts)
{
	uint32_t i, next;

	next = 0;
	for (i = 0; i < n_pkts; i++) {
		if (pkts[i] != NULL && next == i) {
			next++;
		} else if (pkts[i] != NULL) {
			pkts[next] = pkts[i];
			pkts[i] = NULL;
			next++;
		}
	}

	return next;
}

static inline void
setup_pkt_acl(struct rte_mbuf *m, struct fw_ctx *ctx)
{
	struct acl_ctx *acl;
	uint8_t *data;
	uint32_t ptype;

	acl = &ctx->acl;
	ptype = PKT_TYPE(m);

	if (ptype & RTE_PTYPE_L3_IPV4) {
		data = setup_ip_acl_data(&m, ctx);
		if (unlikely(data == NULL)) {
			if (m->udata64 & PKT_META_OL) {
				RTE_LOG(DEBUG, ACL, "reassembling packet");
			} else {
				pkt_dump(m, "dropping packet: ");
				rte_pktmbuf_free(m);
			}
			return;
		}
		acl->ip_data[acl->n_ip] = data;
		acl->ip_m[acl->n_ip] = m;
		acl->n_ip++;
		m->udata64 |= PKT_META_PARSED;

	} else if (ptype & RTE_PTYPE_L3_IPV6) {
		/* Header processing */
		data = setup_ip6_acl_data(&m, ctx);
		if (unlikely(data == NULL)) {
			if (m->udata64 & PKT_META_OL) {
				RTE_LOG(DEBUG, ACL, "reassembling packet");
			} else {
				pkt_dump(m, "dropping packet: ");
				rte_pktmbuf_free(m);
			}
			return;
		}
		acl->ip6_data[acl->n_ip6] = data;
		acl->ip6_m[acl->n_ip6] = m;
		acl->n_ip6++;
		m->udata64 |= PKT_META_PARSED;

	} else {
		/* We only filter IPv4 and IPv6 for now. */
		fwd_ctrl_pkt(m, ctx->cfg);
	}
}

static inline unsigned
__attribute__((always_inline))
setup_acl_search(struct rte_mbuf **pkts, struct fw_ctx *ctx, uint32_t n,
    uint8_t *zid)
{
	unsigned i, nbatch;
	uint8_t zone;

	zone = PKT2ZONE(pkts[0], ctx);
	*zid = zone;
	ctx->acl.n_ip = 0;
	ctx->acl.n_ip6 = 0;

	/* Prefetch first packets */
	for (i = 0; i < BATCH_SIZE && i < n; i++) {
		rte_prefetch0(rte_pktmbuf_mtod(pkts[i], void *));
	}

	nbatch = RTE_ALIGN_FLOOR(n, BATCH_SIZE);
	for (i = 0; i < nbatch; i += BATCH_SIZE) {
		if (PKT2ZONE(pkts[i], ctx) != zone) {
			return i;
		}
		setup_pkt_acl(pkts[i], ctx);

		if (PKT2ZONE(pkts[i + 1], ctx) != zone) {
			return i + 1;
		}
		setup_pkt_acl(pkts[i + 1], ctx);

		if (PKT2ZONE(pkts[i + 2], ctx) != zone) {
			return i + 2;
		}
		setup_pkt_acl(pkts[i + 2], ctx);

		if (PKT2ZONE(pkts[i + 3], ctx) != zone) {
			return i + 3;
		}
		setup_pkt_acl(pkts[i + 3], ctx);
	}

	/* Process remaining packets */
	for (; i < n; i++) {
		if (PKT2ZONE(pkts[i], ctx) != zone) {
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

static inline int
test_synauth(struct rte_mbuf *m, struct synauth_ctx *ctx)
{
	struct tcp_hdr *th;
	uint32_t ptype;
	int r;

	ptype = PKT_TYPE(m);
	if (ptype == RTE_PTYPE_L3_IPV4) {
		th = ip_l4_hdr(m);
		r = (th->tcp_flags & (TH_SYN|TH_RST)) ?
		    synauth_test_ip(ctx, m) : 1;
	} else if (ptype == RTE_PTYPE_L3_IPV6) {
		th = ip6_l4_hdr(m);
		r = (th->tcp_flags & (TH_SYN|TH_RST)) ?
		    synauth_test_ip6(ctx, m) : 1;
	} else {
		RTE_LOG(WARNING, USER1,
		    "Unknown packet type %u in syn check\n.",
		    ptype);
		r = SYNAUTH_ERROR;
	}

	return r;
}

static unsigned
synauth_ol(struct fw_ctx *ctx, struct rte_mbuf **pkts, uint32_t n_pkts)
{
	struct worker_lc_cfg *lp;
	struct synauth_ctx *sactx;
	struct tcp_hdr *th;
	unsigned i, n_sa, action;
	int sares;

#define _ACT_IGNORE	0
#define _ACT_FORWARD	1
#define _ACT_DROP	2

	lp = ctx->cfg;
	sactx = &ctx->sauth;
	n_sa = 0;

	for (i = 0; i < n_pkts; i++) {
		action = _ACT_IGNORE;

		if (pkts[i]->udata64 & PKT_META_SYNAUTH_IP) {
			th = ip_l4_hdr(pkts[i]);
			n_sa++;

			sares = synauth_test_ip(sactx, pkts[i]);
			if (sares == SYNAUTH_OK) {
				action = _ACT_FORWARD;
			} else if (th->tcp_flags & TH_SYN) {
				synauth_auth_ip(sactx, pkts[i]);
				action = _ACT_FORWARD;
			} else if (th->tcp_flags & TH_RST) {
				sares = synauth_vrfy_ip(sactx, pkts[i]);
				action = sares == SYNAUTH_OK ?
				    _ACT_FORWARD : _ACT_DROP;
			}

		} else if (pkts[i]->udata64 & PKT_META_SYNAUTH_IP6) {
			th = ip6_l4_hdr(pkts[i]);
			n_sa++;

			sares = synauth_test_ip6(sactx, pkts[i]);
			if (sares == SYNAUTH_OK) {
				action = _ACT_FORWARD;
			} else if (th->tcp_flags & TH_SYN) {
				synauth_auth_ip6(sactx, pkts[i]);
				action = _ACT_FORWARD;
			} else if (th->tcp_flags & TH_RST) {
				sares = synauth_vrfy_ip6(sactx, pkts[i]);
				action = sares == SYNAUTH_OK ?
				    _ACT_FORWARD : _ACT_DROP;
			}
		}

		if (action == _ACT_FORWARD) {
			fwd_nic_pkt(pkts[i], lp);
			pkts[i] = NULL;

		} else if (action == _ACT_DROP) {
			rte_pktmbuf_free(pkts[i]);
			pkts[i] = NULL;
		}
	}

#undef _ACT_IGNORE
#undef _ACT_FORWARD
#undef _ACT_DROP

	return n_sa;
}

static inline void
handle_synauth_ol(struct worker_lc_cfg *lp, struct rte_mbuf *m)
{
	int sa;

	sa = test_synauth(m, &lp->fw.ctx->sauth);
	if (sa == SYNAUTH_OK) {
		fwd_nic_pkt(m, lp);
	} else if (sa == SYNAUTH_IP_AUTH){
		m->udata64 |= PKT_META_SYNAUTH_IP;
		synauth_ol(lp->fw.ctx, &m, 1);
	} else if (sa == SYNAUTH_IP6_AUTH){
		m->udata64 |= PKT_META_SYNAUTH_IP6;
		synauth_ol(lp->fw.ctx, &m, 1);
	} else {
		rte_pktmbuf_free(m);
	}
}

static inline void
handle_synauth_acl(struct worker_lc_cfg *lp, struct rte_mbuf *m)
{
	/* Offloader core */
	if (lp->ol == WORKER_OL_PROV) {
		handle_synauth_ol(lp, m);
		return;
	}

	/* Main core */
	switch (PKT_TYPE(m)) {
	struct tcp_hdr *th;

	case RTE_PTYPE_L3_IPV4:
		th = ip_l4_hdr(m);
		if (th->tcp_flags & (TH_SYN|TH_RST)) {
			m->udata64 |= PKT_META_SYNAUTH_IP;
			fwd_ol_pkt(m, lp);
			return;
		}
		break;
	case RTE_PTYPE_L3_IPV6:
		th = ip6_l4_hdr(m);
		if (th->tcp_flags & (TH_SYN|TH_RST)) {
			m->udata64 |= PKT_META_SYNAUTH_IP6;
			fwd_ol_pkt(m, lp);
			return;
		}
		break;
	}

	fwd_nic_pkt(m, lp);
}

static inline void
fwd_acl_pkt(struct worker_lc_cfg *lp, struct rte_mbuf *m, uint32_t res)
{
	if (unlikely(res & ACL_ACTION_COUNT)) {
		uint8_t id = ACL_COUNT_ID(res);
		uint8_t zone = PORT2ZONE(m->port);
		lp->fw.ctx->counters[zone][id].packets++;
		lp->fw.ctx->counters[zone][id].bytes += m->data_len;
	}
	if (unlikely(res & ACL_ACTION_MONIT)) {
		struct rte_mbuf *clone;
		clone = rte_pktmbuf_clone(m, cfg.pools[rte_socket_id()]);
		fwd_ctrl_pkt(clone, lp);
	}
	if (res & ACL_ACTION_ACCEPT) {
		if (unlikely(rt_is_local(m))) {
			m->udata64 |= PKT_META_LOCAL;
			fwd_ctrl_pkt(m, lp);
		} else {
			if (res & ACL_ACTION_SYNAUTH) {
				handle_synauth_acl(lp, m);
			} else {
				fwd_nic_pkt(m, lp);
			}
		}
	} else {
		pkt_dump(m, "dropping packet: ");
		rte_pktmbuf_free(m);
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


static inline void
__attribute__((always_inline))
test_pkts(struct fw_ctx *ctx, struct rte_mbuf **pkts, uint32_t n_pkts)
{
	struct acl_ctx *acl;
	struct rte_acl_ctx *acl_ctx;
	unsigned sockid, offset;

	acl = &ctx->acl;
	sockid = rte_socket_id();
	offset = 0;

	rcu_read_lock();
	while (offset < n_pkts) {
		uint8_t zid;

		offset +=
		    setup_acl_search(pkts + offset, ctx, n_pkts - offset, &zid);

		/* IPv4 */
		if (acl->n_ip) {
			/* Apply ACLs if required */
			if (zid < MAX_ZONES && (acl_ctx =
			    rcu_dereference(zones[zid].ip_acl[sockid]))) {
				rte_acl_classify(acl_ctx, acl->ip_data,
				    acl->ip_res, acl->n_ip, MAX_ACL_CATEGORIES);

				fwd_acl_pkts(ctx->cfg, acl->ip_m, acl->ip_res,
				    acl->n_ip);

			} else {
				/* Forward packets without filtering */
				fwd_pkts(ctx->cfg, acl->ip_m, acl->n_ip);
			}
		}

		/* IPv6 */
		if (acl->n_ip6) {
			/* Apply ACLs if required */
			if (zid < MAX_ZONES && (acl_ctx =
			    rcu_dereference(zones[zid].ip6_acl[sockid]))) {
				rte_acl_classify(acl_ctx, acl->ip6_data,
				    acl->ip6_res, acl->n_ip6,
				    MAX_ACL_CATEGORIES);

				fwd_acl_pkts(ctx->cfg, acl->ip6_m, acl->ip6_res,
				    acl->n_ip6);

			} else {
				/* Forward packets without filtering */
				fwd_pkts(ctx->cfg, acl->ip6_m, acl->n_ip6);
			}
		}
	}
	rcu_read_unlock();
}

static inline uint32_t
__attribute__((always_inline))
input(struct fw_ctx *ctx, uint32_t burst, uint32_t ring_n)
{
	struct rte_mbuf **pkts;
	struct rte_ring *ring;
	unsigned n_rx;

	pkts = ctx->cfg->ibuf.array;
	ring = ctx->cfg->irings[ring_n];

	n_rx = rte_ring_sc_dequeue_burst(ring, (void **)pkts, burst);
	if (unlikely(n_rx > burst)) {
		RTE_LOG(CRIT, USER1, "FW: error receiving from ring!\n");
		return 0;
	}

	test_pkts(ctx, pkts, n_rx);

#ifdef APP_STATS
		ctx->cfg->irings_pkts[ring_n] += n_rx;
#endif

	return n_rx;
}

static inline uint32_t
input_ol(struct fw_ctx *ctx, uint32_t burst, uint32_t ring_n)
{
	struct rte_mbuf **pkts;
	struct rte_ring *ring;
	unsigned n_rx, n_sa;

	pkts = ctx->cfg->ibuf.array;
	ring = ctx->cfg->irings[ring_n];

	n_rx = rte_ring_sc_dequeue_burst(ring, (void **)pkts, burst);
	if (unlikely(n_rx > burst)) {
		RTE_LOG(CRIT, USER1, "FW: error receiving from ring!\n");
		return 0;
	}
	if (n_rx == 0) {
		return 0;
	}
#ifdef APP_STATS
	ctx->cfg->irings_pkts[ring_n] += n_rx;
#endif

	/* Handle SYN authentication requests */
	n_sa = synauth_ol(ctx, pkts, n_rx);
	if (n_sa == n_rx) {
		return n_rx;
	} else if (n_sa < n_rx) {
		n_rx = compact_pkt_array(pkts, n_rx);
	}

	test_pkts(ctx, pkts, n_rx);

	return n_rx;
}

static inline void
__attribute__((always_inline))
cron_cnt(struct fw_ctx *ctx, struct fw_cron *cron)
{

	if (LCORE_WORKER_FLUSH &&
	    (unlikely(cron->flush == LCORE_WORKER_FLUSH))) {
		cron->flush = 0;
		if (ctx->cfg->pending) {
			ctx->cfg->pending = 0;
			flush_nic_buffers(ctx->cfg);
			flush_ctrl_buffers(ctx->cfg);
			flush_ol_buffers(ctx->cfg);
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
			/* Pending may be reset by the flush handler */
			ctx->cfg->pending = 0;
			flush_nic_buffers(ctx->cfg);
			flush_ctrl_buffers(ctx->cfg);
			flush_ol_buffers(ctx->cfg);
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
	unsigned int socket;
	char name[64];
	size_t size;
	int16_t n;

	socket = rte_lcore_id();
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

	/* Allocate required structures for offload providers */
	if (lp->ol == WORKER_OL_PROV) {
		if (frag_init(&ctx->frag, cfg.ol_pools[socket],
		    cfg.frag_max_flow_num, cfg.frag_max_flow_ttl) != 0) {
			rte_panic("Could initialize fragmentation context. "
			    "Shutting down...\n");
		}

		if (synauth_init(&ctx->sauth) != 0) {
			rte_panic("Could not initialize syn authentication "
			    "context. Shutting down...");
		}

		n = rte_atomic16_add_return(&n_offldrs, 1) - 1;
		offldrs[n] = ctx;
	}

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

	RTE_LOG(DEBUG, USER1, "Worker %u checking in: lcore: %u, ol: %u.\n",
	    lp->id, rte_lcore_id(), lp->ol);

	for (;;) {
		cron_cnt(ctx, &cron);
		for (ring = 0; ring < n_rings; ring++) {
			if (input(ctx, burst, ring)) {
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

	RTE_LOG(DEBUG, USER1, "Worker %u checking in: lcore: %u, ol: %u.\n",
	    lp->id, rte_lcore_id(), lp->ol);

	for (;;) {
		cron_tsc(ctx, &cron);
		for (ring = 0; ring < n_rings; ring++) {
			if (input_ol(ctx, burst, ring)) {
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
