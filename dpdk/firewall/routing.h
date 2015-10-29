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

#ifndef ROUTING_H_
#define ROUTING_H_

#include <errno.h>

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

#include "main.h"
#include "util.h"
#include "packet.h"

static struct ether_addr nullea;

static inline int
__attribute__((always_inline))
rt_is_local(struct rte_mbuf *m)
{
	uint8_t *data;
	uint16_t vlan;
	int is_local;

	data = rte_pktmbuf_mtod(m, uint8_t *);
	vlan = PKT_VLANID(m->vlan_tci);
	is_local = 0;

	if (m->packet_type & RTE_PTYPE_L3_IPV4) {
		struct ipv4_hdr *ih;

		ih = (struct ipv4_hdr *)(data + sizeof(struct ether_hdr));
		is_local = (ih->dst_addr & cfg.vlans[vlan].ip_mask.s_addr) ==
		    cfg.vlans[vlan].ip_net.s_addr;
	} else if (m->packet_type & RTE_PTYPE_L3_IPV6) {
		struct ipv6_hdr *ih;
		__m128i addr, net;

		ih = (struct ipv6_hdr *)(data + sizeof(struct ether_hdr));
		addr = _mm_loadu_si128((__m128i *) & ih->dst_addr);
		net = _mm_and_si128(addr, cfg.vlans[vlan].ip6_mask.xmm);
		is_local = is_equal128(net, cfg.vlans[vlan].ip6_net.xmm);
	} else {
		is_local = 1;
	}

	/*
	 * TODO: handle broadcast and multicast packets
	 */
	return is_local;
}

#define FLOW_VLAN_OUT	0
#define FLOW_VLAN_IN	1

static inline void
rt_refresh_gws(struct rt_ctx *ctx)
{
	struct ether_addr *macs;
	uint16_t n_gws;
	int i;

	macs = ctx->igws;
	n_gws = 0;
	for (i = 0; i < cfg.n_igws; i++) {
		if (memcmp(&cfg.igws[i].mac, &macs[i],
		    sizeof(struct ether_addr))) {
			ether_addr_copy(&cfg.igws[i].mac, &macs[i]);
		}
		if (memcmp(&macs[i], &nullea, sizeof(nullea)) != 0) {
			n_gws++;
		}
	}
	ctx->n_igws = n_gws;

	macs = ctx->ogws;
	n_gws = 0;
	for (i = 0; i < cfg.n_ogws; i++) {
		if (memcmp(&cfg.ogws[i].mac, &macs[i],
		    sizeof(struct ether_addr))) {
			ether_addr_copy(&cfg.ogws[i].mac, &macs[i]);
		}
		if (memcmp(&macs[i], &nullea, sizeof(nullea)) != 0) {
			n_gws++;
		}
	}
	ctx->n_ogws = n_gws;

	LOG(DEBUG, USER1, "Updating gateway mac addresses.\n");
	ctx->ovlan = cfg.ovlan;
	ctx->gws_ts = cfg.gws_ts;
}

static inline
__attribute__((always_inline))
	uint64_t
	         hash_pkt(struct rte_mbuf *m, struct ether_hdr *eh, uint8_t flow)
{
	if (likely(PKT_TYPE(m) == RTE_PTYPE_L3_IPV4)) {
		struct ipv4_hdr *iph = (struct ipv4_hdr *)(eh + 1);

		if (flow == FLOW_VLAN_OUT) {
			return rte_hash_crc_4byte(iph->src_addr, 0);
		} else {
			return rte_hash_crc_4byte(iph->dst_addr, 0);
		}
	} else {
		struct ipv6_hdr *iph = (struct ipv6_hdr *)(eh + 1);
		uint64_t *r;

		if (flow == FLOW_VLAN_OUT) {
			r = (uint64_t *)(&(iph->src_addr) + 8);
			return rte_hash_crc_8byte(*r, 0);
		} else {
			r = (uint64_t *)(&(iph->dst_addr) + 8);
			return rte_hash_crc_8byte(*r, 8);
		}
	}
}

static inline
__attribute__((always_inline))
	struct ether_addr *
	           rt_select_gw(struct rte_mbuf *m, struct ether_hdr *eh,
               struct rt_ctx *ctx)
{
	if (PKT_VLANID(m->vlan_tci) == ctx->ovlan) {
		uint64_t slot = hash_pkt(m, eh, FLOW_VLAN_OUT);
		if (unlikely(ctx->n_ogws == 0)) {
			/* No gateways available yet. Drop the packet... */
			rte_pktmbuf_free(m);
			return NULL;
		}

		slot %= ctx->n_ogws;
		return &ctx->ogws[slot];

	} else {
		uint64_t slot = hash_pkt(m, eh, FLOW_VLAN_IN);
		if (unlikely(ctx->n_igws == 0)) {
			/* No gateways available yet. Drop the packet... */
			rte_pktmbuf_free(m);
			return NULL;
		}

		slot %= ctx->n_igws;
		return &ctx->igws[slot];
	}
}

#endif	/* ROUTING_H_ */
