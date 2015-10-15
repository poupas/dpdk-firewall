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

#include <stdlib.h>

#include "main.h"
#include "util.h"
#include "runtime.h"
#include "packet.h"
#include "forward.h"

#define ARP_UPDATE_US		30 * US_PER_S
#define ARP_PROBE_US		 1 * US_PER_S
#define ARP_PROBE_RETRY_US	30 * US_PER_S
#define ARP_MAX_PROBES		10

static struct gw_addr *
gw_info(uint16_t vlan_tci, in_addr_t addr)
{
	int i;

	if (PKT_VLANID(vlan_tci) == cfg.ovlan) {
		for (i = 0; i < cfg.n_ogws; i++) {
			if (addr == cfg.ogws[i].ip.s_addr) {
				return &cfg.ogws[i];
			}
		}
		return NULL;
	}
	for (i = 0; i < cfg.n_igws; i++) {
		if (addr == cfg.igws[i].ip.s_addr) {
			return &cfg.igws[i];
		}
	}

	return NULL;
}

static inline void
print_mac_addr(const uint8_t *addr, struct in_addr ip, uint8_t port)
{
	char a, b, c, d;
	uint32_to_char(ip.s_addr, &a, &b, &c, &d);
	LOG(DEBUG, USER1, "%4s updating table. Port %u, "
	    "%hhu.%hhu.%hhu.%hhu -> %02x:%02x:%02x:%02x:%02x:%02x.\n",
	    "ARP", port, d, c, b, a,
	    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

static struct gw_addr *
update_from_arp(const struct rte_mbuf *m, const uint8_t *data, uint64_t now)
{
	const struct ether_arp *ea;
	struct gw_addr *gwa;
	in_addr_t *ip;

	if ((ea = pkt_ether_arp_hdr(m, data)) == NULL) {
		RTE_LOG(DEBUG, USER1, "WRK: Not a valid ARP packet.\n");
		return NULL;
	}
	if ((_ntohs(ea->arp_op) & (ARPOP_REQUEST | ARPOP_REPLY)) == 0) {
		RTE_LOG(DEBUG, USER1, "WRK: Not an ARP request or reply.\n");
		return NULL;
	}
	/* Check if the ARP packet is from a gateway */
	ip = (in_addr_t *)&ea->arp_spa;
	if ((gwa = gw_info(m->vlan_tci, *ip)) == NULL) {
		char a, b, c, d;
		uint32_to_char(_htonl(*ip), &a, &b, &c, &d);
		if (*ip != cfg.vlans[PKT_VLANID(m->vlan_tci)].ip.s_addr) {
			RTE_LOG(DEBUG, USER1, "Ignoring ARP. "
			    "srcip: %hhu.%hhu.%hhu.%hhu, vlan: %u, port: %u\n",
			    a, b, c, d, PKT_VLANID(m->vlan_tci), m->port);
		}
		return NULL;
	}
	if (likely(memcmp(&ea->arp_sha, &gwa->mac, ETHER_ADDR_LEN) == 0)) {
		//RTE_LOG(DEBUG, USER1, "Already have latest mac address. "
		    // "Ignoring...\n");
		gwa->update_ts = now;
		return NULL;
	}
	ether_addr_copy(&ea->arp_sha, &gwa->mac);
	print_mac_addr((uint8_t *)&gwa->mac, gwa->ip, m->port);

	return gwa;
}

static struct gw_addr *
update_from_ip(const struct rte_mbuf *m, const uint8_t *data, uint64_t now)
{
	const struct ether_hdr *eh;
	const struct ipv4_hdr *ih;
	struct gw_addr *gwa;

	eh = (const struct ether_hdr *)data;
	ih = (const struct ipv4_hdr *)(data + sizeof(struct ether_hdr));

	/* Check if the ARP packet is from a gateway */
	if ((gwa = gw_info(m->vlan_tci, ih->src_addr)) == NULL) {
		//LOG(DEBUG, USER1, "%4s packet not from known gateway.\n",
		    //"ARP");
		return NULL;
	}
	if (likely(memcmp(&eh->s_addr, &gwa->mac, ETHER_ADDR_LEN) == 0)) {
		//LOG(DEBUG, USER1, "%4s already have latest mac address. "
		    // "Ignoring...\n", "ARP");
		gwa->update_ts = now;
		return NULL;
	}
	ether_addr_copy(&eh->s_addr, &gwa->mac);
	print_mac_addr((uint8_t *)&gwa->mac, gwa->ip, m->port);

	return gwa;
}

static struct rte_mbuf *
create_request(in_addr_t ip, uint16_t vlan)
{
	struct rte_mbuf *m;
	struct rte_mempool *pool;
	struct ether_hdr *eh;
	struct ether_arp *ah;
	uint8_t *data;
	static struct ether_addr brd = {
		.addr_bytes = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	};

	pool = cfg.pools[rte_socket_id()];
	m = rte_pktmbuf_alloc(pool);
	if (m == NULL) {
		return NULL;
	}
	data = rte_pktmbuf_mtod(m, uint8_t *);
	eh = (struct ether_hdr *)data;
	ah = (struct ether_arp *)(data + sizeof(struct ether_hdr));

	/* Ethernet header */
	ether_addr_copy(&cfg.ifaces[0].hwaddr, &eh->s_addr);
	ether_addr_copy(&brd, &eh->d_addr);
	eh->ether_type = _htons(ETHER_TYPE_ARP);

	/* ARP header */
	ah->ea_hdr.ar_hrd = _htons(ARPHRD_ETHER);
	ah->ea_hdr.ar_pro = _htons(ETHER_TYPE_IPv4);
	ah->ea_hdr.ar_hln = ETHER_ADDR_LEN;
	ah->ea_hdr.ar_pln = sizeof(struct in_addr);
	ah->ea_hdr.ar_op = _htons(ARPOP_REQUEST);

	rte_memcpy(&ah->arp_spa, &cfg.vlans[vlan].ip, sizeof(ah->arp_spa));
	rte_memcpy(&ah->arp_tpa, &ip, sizeof(ah->arp_tpa));
	rte_memcpy(&ah->arp_sha, &cfg.ifaces[0].hwaddr, sizeof(ah->arp_sha));
	rte_memcpy(&ah->arp_tha, &brd, sizeof(ah->arp_tha));

	m->pkt_len = sizeof(struct ether_hdr) + sizeof(struct ether_arp);
	m->data_len = sizeof(struct ether_hdr) + sizeof(struct ether_arp);
	m->nb_segs = 1;
	m->next = NULL;
	m->vlan_tci = vlan;

	/* TODO: choose port randomly? */
	m->port = 4;

	/* Let the forwarding code know that no routing decision is required */
	m->udata64 = PKT_META_ROUTED;

	return m;
}

struct gw_addr *
arp_chk_gw_pkt(struct rte_mbuf *m, uint64_t now)
{
	if (PKT_TYPE(m) == RTE_PTYPE_L2_ETHER_ARP) {
		return update_from_arp(m, rte_pktmbuf_mtod(m, uint8_t *), now);
	}
	if ((m->udata64 & PKT_META_LOCAL) && PKT_TYPE(m) == RTE_PTYPE_L3_IPV4) {
		return update_from_ip(m, rte_pktmbuf_mtod(m, uint8_t *), now);
	}
	return NULL;
}

void
arp_send_probes(struct worker_lc_cfg *lp, struct gw_addr *gws,
    uint32_t n_gws, uint64_t tsc_per_us)
{
	uint32_t i;

	for (i = 0; i < n_gws; i++) {
		struct rte_mbuf *m;

		/* Entry is up to date or being throttled */
		if (now_tsc - gws[i].update_ts < US2TSC(ARP_UPDATE_US) ||
		    now_tsc - gws[i].probe_ts < US2TSC(ARP_PROBE_US)) {
			continue;
		}
		if (gws[i].probes > ARP_MAX_PROBES) {
			/* Not yet ready to start sending ARP probes */
			if (now_tsc -
			    gws[i].probe_ts < US2TSC(ARP_PROBE_RETRY_US)) {
				continue;
			}
			/* Start probing again */
			gws[i].probes = 0;
		}
		/* Ensure that we have a configured address for the vlan */
		if (unlikely(cfg.vlans[gws[i].vlan].ip.s_addr == 0)) {
			continue;
		}
		char a, b, c, d;
		uint32_to_char(gws[i].ip.s_addr, &d, &c, &b, &a);
		//LOG(DEBUG, USER1, "%4s sending probe for: "
		    // "%hhu.%hhu.%hhu.%hhu vlan: %" PRIu16 "\n",
		    //"ARP", a, b, c, d, gws[i].vlan);
		m = create_request(gws[i].ip.s_addr, gws[i].vlan);
		if (m == NULL) {
			/* TODO: log error */
			continue;
		}
		gws[i].probes++;
		gws[i].probe_ts = now_tsc;

		fwd_nic_pkt(m, lp);
	}
}
