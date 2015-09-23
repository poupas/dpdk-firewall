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

#include <netinet/in.h>

#include <rte_mbuf.h>

#include "main.h"
#include "runtime.h"
#include "packet.h"

inline uint32_t
pkt_type(struct rte_mbuf *m)
{
	const uint8_t *payload;
	const struct ether_hdr *eth_hdr;
	uint16_t etype;
	uint8_t i;

	payload = rte_pktmbuf_mtod(m, uint8_t *);
	if (unlikely(payload == NULL)) {
		return 0;
	}
	eth_hdr = (const struct ether_hdr *)payload;
	etype = _ntohs(eth_hdr->ether_type);
	for (i = 0; i < 2; i++) {
		switch (etype) {
		case ETHER_TYPE_IPv4:
			m->packet_type |= RTE_PTYPE_L3_IPV4;
			return m->packet_type;
		case ETHER_TYPE_IPv6:
			m->packet_type |= RTE_PTYPE_L3_IPV6;
			return m->packet_type;
		case ETHER_TYPE_ARP:
			m->packet_type |= RTE_PTYPE_L2_ETHER_ARP;
			return m->packet_type;
		case ETHER_TYPE_RARP:
			m->packet_type |= RTE_PTYPE_L2_ETHER_ARP;
			return m->packet_type;
		case ETHER_TYPE_VLAN:
			RTE_LOG(
			    WARNING,
			    USER1,
			    "Found a tagged frame. Ensure that vlan offloading "
			    "is enabled.\n");

			/* Skip over the VLAN tag */
			etype = _ntohs(*(&eth_hdr->ether_type + 2));
			break;
		default:
			// RTE_LOG(WARNING, USER1, "Unknown: 0x%.4x\n", etype);
			return m->packet_type;
		}
	}

	RTE_LOG(WARNING, USER1, "Error determining packet type.\n");
	return m->packet_type;
}

const struct ether_arp *
pkt_ether_arp_hdr(const struct rte_mbuf *m, const uint8_t *data)
{
	const struct arphdr *ar;
	size_t hlen, dlen;

	/* Ensure that both ethernet and ARP headers exist */
	dlen = rte_pktmbuf_data_len(m);
	hlen = sizeof(struct ether_hdr) + sizeof(struct arphdr);
	if (dlen < hlen || !rte_pktmbuf_is_contiguous(m)) {
		return NULL;
	}
	ar = (const struct arphdr *)(data + sizeof(struct ether_hdr));
	if (_ntohs(ar->ar_hrd) != ARPHRD_ETHER) {
		return NULL;
	}
	/* Rest of ARP packet: hardware and protocol addresses */
	/*
	 * XXX: does a buffer overflow exist here? we are trusting user
	 * input. Later we cast the data buffer to an ether arp struct
	 */
	hlen += 2 * (ar->ar_hln + ar->ar_pln);
	if (dlen < hlen || _ntohs(ar->ar_pro) != ETHER_TYPE_IPv4) {
		return NULL;
	}
	return (const struct ether_arp *)ar;
}

/*
 * This function trusts the input parameters, i.e., the packet has a valid
 * IPv4 header.
 * This should not be a problem. We check the NIC's offload flags, and its value
 * should be trustworthy.
 *
 * TODO: check that the assumptions are valid.
 *
 * On 10Gbps NICs this might be true. It does not seem so on 1Gbps NICs.
 *
 */
const struct ipv4_hdr *
pkt_ip_hdr(struct rte_mbuf *m, const uint8_t *data)
{
	if (unlikely(PKT_TYPE(m) != RTE_PTYPE_L3_IPV4)) {
		return NULL;
	}
	return (const struct ipv4_hdr *)(data + sizeof(struct ether_hdr));
}

static void
mac_to_str(uint8_t *mac, char *dst, size_t dsiz)
{
	snprintf(dst, dsiz, "%02x:%02x:%02x:%02x:%02x:%02x",
	    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void
pkt_dump(const struct rte_mbuf *m, const char *prefix)
{
	struct ether_hdr *eh;
	uint8_t *data, proto;
	char saddr[INET6_ADDRSTRLEN], daddr[INET6_ADDRSTRLEN];
	char smac[20], dmac[20];

	data = rte_pktmbuf_mtod(m, uint8_t *);
	eh = (struct ether_hdr *)data;

	if (likely(m->packet_type & RTE_PTYPE_L3_IPV4)) {
		struct ipv4_hdr *ip;
		ip = (struct ipv4_hdr *)(data + sizeof(struct ether_hdr));
		inet_ntop(AF_INET, &ip->src_addr, saddr, sizeof(saddr));
		inet_ntop(AF_INET, &ip->dst_addr, daddr, sizeof(daddr));
		proto = ip->next_proto_id;
	} else {
		struct ipv6_hdr *ip;
		ip = (struct ipv6_hdr *)(data + sizeof(struct ether_hdr));
		inet_ntop(AF_INET6, &ip->src_addr, saddr, sizeof(saddr));
		inet_ntop(AF_INET6, &ip->dst_addr, daddr, sizeof(daddr));
		proto = ip->proto;
	}
	mac_to_str((uint8_t *)&eh->s_addr, smac, sizeof(smac));
	mac_to_str((uint8_t *)&eh->d_addr, dmac, sizeof(dmac));

	RTE_LOG(DEBUG, USER1,
	    "%s iface: %d. vlan: %u, etype: 0x%02x%02x, "
	    "smac: %s, dmac: %s, saddr: %s, "
	    "daddr: %s, protocol: 0x%02x\n",
	    prefix, m->port, m->vlan_tci,
	    ((uint8_t *)&eh->ether_type)[0],
	    ((uint8_t *)&eh->ether_type)[1],
	    smac, dmac, saddr, daddr,
	    proto);
}

size_t
pkt_add_vlan_hdr(struct rte_mbuf *m)
{
	size_t size;
	uint8_t *data;

	data = rte_pktmbuf_mtod(m, uint8_t *);
	size = rte_pktmbuf_data_len(m);

	if (likely(PKT_VLANID(m->vlan_tci) != 0)) {
		struct ether_hdr *eh;
		struct vlan_hdr *vh;
		uint8_t *hole;
		size_t dlen;

		/* Make room for the vlan tag */
		hole = data + sizeof(struct ether_hdr);
		dlen = size - sizeof(struct ether_hdr);
		memmove(hole + sizeof(struct vlan_hdr), hole, dlen);

		/* Place the tag */
		eh = (struct ether_hdr *)data;
		vh = (struct vlan_hdr *)hole;
		vh->eth_proto = eh->ether_type;
		eh->ether_type = _htons(ETHER_TYPE_VLAN);
		vh->vlan_tci = _htons(m->vlan_tci);

		m->data_len += sizeof(struct vlan_hdr);
		m->pkt_len += sizeof(struct vlan_hdr);
		size += sizeof(struct vlan_hdr);
	}

	return size;
}
