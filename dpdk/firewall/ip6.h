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

#ifndef IP6_H_
#define IP6_H_

#include "packet.h"

/*
 * IPv6 extension headers.
 *
 * The extension header are filtered only for presence using a bit
 * vector with a flag for each header.
 */
#define IP6_EH_FRAGMENT	(1 << 0)
#define IP6_EH_HOPOPTS	(1 << 1)
#define IP6_EH_ROUTING	(1 << 2)
#define IP6_EH_AH	(1 << 3)
#define IP6_EH_ESP	(1 << 4)
#define IP6_EH_DSTOPTS	(1 << 5)
#define IP6_EH_RTHDR0	(1 << 6)
#define IP6_EH_RTHDR2	(1 << 7)
#define IP6_EH_UNKNOWN	(1 << 8)
#define IP6_EH_INVALID	(1 << 9)

/*
 * This code is derived from FreeBSD: <url>
 */
static inline uint32_t
ip6_parse_hdrs(struct rte_mbuf *m, uint8_t **l4hdr, uint16_t *l4proto)
{
	struct ipv6_hdr *iphdr;
	void *ulp;
	uint32_t exthdrs, hlen;
	uint8_t proto;

/*
 * PULLUP_TO(len, p, T) sets p to point at the offset "len" in the mbuf.
 * WARNING: the pointer might become stale after other pullups
 * (but we never use it this way).
 */
#define PULLUP_TO(_len, p, T)	PULLUP_LEN(_len, p, sizeof(T))
#define PULLUP_LEN(_len, p, T)					\
do {								\
	uint16_t x = (_len) + T;				\
	if ((m)->data_len < x) {				\
		p = NULL;					\
		goto fail;					\
	}							\
	p = (rte_pktmbuf_mtod(m, uint8_t *)) + (_len);		\
} while (0)

	*l4hdr = NULL;
	*l4proto = 0;
	exthdrs = 0;
	hlen = sizeof(struct ether_hdr) + sizeof(struct ipv6_hdr);
	ulp = NULL;
	iphdr = (struct ipv6_hdr *)(rte_pktmbuf_mtod(m, uint8_t *)+
	    sizeof(struct ether_hdr));
	proto = iphdr->proto;

	while (ulp == NULL) {
		switch (proto) {
		case IPPROTO_ICMPV6:
			PULLUP_TO(hlen, ulp, struct icmp6_hdr);
			*l4hdr = ulp;
			*l4proto = proto;
			break;

		case IPPROTO_TCP:
			PULLUP_TO(hlen, ulp, struct tcphdr);
			*l4hdr = ulp;
			*l4proto = proto;
			break;

		case IPPROTO_SCTP:
			PULLUP_TO(hlen, ulp, struct sctphdr);
			*l4hdr = ulp;
			*l4proto = proto;
			break;

		case IPPROTO_UDP:
			PULLUP_TO(hlen, ulp, struct udphdr);
			*l4hdr = ulp;
			*l4proto = proto;
			break;

		case IPPROTO_HOPOPTS:	/* RFC 2460 */
			PULLUP_TO(hlen, ulp, struct ip6_hbh);
			exthdrs |= IP6_EH_HOPOPTS;
			hlen += (((struct ip6_hbh *)ulp)->ip6h_len + 1) << 3;
			proto = ((struct ip6_hbh *)ulp)->ip6h_nxt;
			ulp = NULL;
			break;

		case IPPROTO_ROUTING:	/* RFC 2460 */
			PULLUP_TO(hlen, ulp, struct ip6_rthdr);
			exthdrs |= IP6_EH_ROUTING;
			hlen += (((struct ip6_rthdr *)ulp)->ip6r_len + 1) << 3;
			proto = ((struct ip6_rthdr *)ulp)->ip6r_nxt;
			ulp = NULL;
			break;

		case IPPROTO_FRAGMENT:	/* RFC 2460 */
			PULLUP_TO(hlen, ulp, struct ip6_frag);
			exthdrs |= IP6_EH_FRAGMENT;
			hlen += sizeof(struct ip6_frag);
			proto = ((struct ip6_frag *)ulp)->ip6f_nxt;
			ulp = NULL;
			break;

		case IPPROTO_DSTOPTS:	/* RFC 2460 */
			PULLUP_TO(hlen, ulp, struct ip6_hbh);
			exthdrs |= IP6_EH_DSTOPTS;
			hlen += (((struct ip6_hbh *)ulp)->ip6h_len + 1) << 3;
			proto = ((struct ip6_hbh *)ulp)->ip6h_nxt;
			ulp = NULL;
			break;

		case IPPROTO_AH:	/* RFC 2402 */
			PULLUP_TO(hlen, ulp, struct ip6_ext);
			exthdrs |= IP6_EH_AH;
			hlen += (((struct ip6_ext *)ulp)->ip6e_len + 2) << 2;
			proto = ((struct ip6_ext *)ulp)->ip6e_nxt;
			ulp = NULL;
			break;

		case IPPROTO_ESP:	/* RFC 2406 */
			PULLUP_TO(hlen, ulp, uint32_t);	/* SPI, Seq# */
			/*
			 * Anything past Seq# is variable length and data
			 * past this ext. header is encrypted.
			 */
			exthdrs |= IP6_EH_ESP;
			break;

		case IPPROTO_NONE:	/* RFC 2460 */
			/*
			 * Packet ends here, and IPv6 header has already been
			 * pulled up. If ip6e_len != 0 then octets must be
			 * ignored.
			 */
			goto done;

		case IPPROTO_OSPFIGP:
			/* XXX OSPF header check? */
			PULLUP_TO(hlen, ulp, struct ip6_ext);
			break;

		case IPPROTO_PIM:
			/* XXX PIM header check? */
			PULLUP_TO(hlen, ulp, struct pim);
			break;

		case IPPROTO_IPV6:	/* RFC 2893 */
			PULLUP_TO(hlen, ulp, struct ipv6_hdr);
			break;

		case IPPROTO_IPV4:	/* RFC 2893 */
			PULLUP_TO(hlen, ulp, struct ipv4_hdr);
			break;

		default:
			RTE_LOG(WARNING, ACL, "parse_ip6_hdrs: unknown header "
			    "type: %x\n", proto);
			exthdrs |= IP6_EH_UNKNOWN;
			PULLUP_TO(hlen, ulp, struct ip6_ext);
			break;
		}
	}

#undef PULLUP_TO
#undef PULLUP_LEN

done:
	return exthdrs;

fail:
	*l4hdr = NULL;
	exthdrs = IP6_EH_INVALID;

	return exthdrs;
}

#endif	/* IP6_H_ */
