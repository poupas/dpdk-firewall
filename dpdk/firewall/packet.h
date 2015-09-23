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

/*
 * Copyright (c) 1986, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)if_arp.h    8.1 (Berkeley) 6/10/93
 */

#ifndef _PACKET_H_
#define _PACKET_H_

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>

#include <rte_byteorder.h>
#include <rte_ip.h>
#include <rte_ether.h>
#include <rte_hash_crc.h>

/*
 * Address Resolution Protocol.
 *
 * See RFC 826 for protocol description.  ARP packets are variable
 * in size; the arp_hdr structure defines the fixed-length portion.
 * Protocol type values are the same as those for 10 Mb/s Ethernet.
 * It is followed by the variable-sized fields ar_sha, arp_spa,
 * arp_tha and arp_tpa in that order, according to the lengths
 * specified.  Field names used correspond to RFC 826.
 */
struct arphdr {
	uint16_t ar_hrd;	/* format of hardware address */
#define ARPHRD_ETHER	1	/* ethernet hardware format */
#define ARPHRD_IEEE802	6	/* IEEE 802 hardware format */
#define ARPHRD_FRELAY	15	/* frame relay hardware format */
#define ARPHRD_IEEE1394	24	/* IEEE 1394 (FireWire) hardware format */
	uint16_t ar_pro;	/* format of protocol address */
	uint8_t ar_hln;	/* length of hardware address */
	uint8_t ar_pln;	/* length of protocol address */
	uint16_t ar_op;	/* one of: */
#define ARPOP_REQUEST	1	/* request to resolve address */
#define ARPOP_REPLY	2	/* response to previous request */
#define ARPOP_REVREQUEST 3	/* request protocol address given hardware */
#define ARPOP_REVREPLY	4	/* response giving protocol address */
#define ARPOP_INVREQUEST 8	/* request to identify peer */
#define ARPOP_INVREPLY	9	/* response identifying peer */
/*
 * The remaining fields are variable in size,
 * according to the sizes above.
 */
#ifdef COMMENT_ONLY
	uint8_t ar_sha[];	/* sender hardware address */
	uint8_t ar_spa[];	/* sender protocol address */
	uint8_t ar_tha[];	/* target hardware address */
	uint8_t ar_tpa[];	/* target protocol address */
#endif
}      __attribute__((__packed__));


/*
 * Ethernet Address Resolution Protocol.
 *
 * See RFC 826 for protocol description.  Structure below is adapted
 * to resolving internet addresses.  Field names used correspond to
 * RFC 826.
 */
struct ether_arp {
	struct arphdr ea_hdr;	/* fixed-size header */
	struct ether_addr arp_sha;	/* sender hardware address */
	uint8_t arp_spa[4];	/* sender protocol address */
	struct ether_addr arp_tha;	/* target hardware address */
	uint8_t arp_tpa[4];	/* target protocol address */
}         __attribute__((__packed__));

#define arp_hrd ea_hdr.ar_hrd
#define arp_pro ea_hdr.ar_pro
#define arp_hln ea_hdr.ar_hln
#define arp_pln ea_hdr.ar_pln
#define arp_op  ea_hdr.ar_op


/*
 * RTE packet type identifiers
 */
#define PKT_RX_IP_HDR (PKT_RX_IPV4_HDR | PKT_RX_IPV6_HDR)

/*
 * Packet metadata
 */
#define PKT_META_OL		(1 << 1)
#define PKT_META_ROUTED		(1 << 2)
#define PKT_META_LOCAL		(1 << 3)
#define PKT_META_VLAN_TAG	(1 << 4)

/*
 * SCTP
 */
struct sctphdr {
	uint16_t src_port;	/* source port */
	uint16_t dest_port;	/* destination port */
	uint32_t v_tag;	/* verification tag of packet */
	uint32_t checksum;	/* Adler32 C-Sum */
	/* chunks follow... */
}       __attribute__((__packed__));


/*
 * PIM
 */
struct pim {
#ifdef __PIM_VT
	uint8_t pim_vt;	/* PIM version and message type */
#else	/* ! _PIM_VT   */
#if __BYTE_ORDER == __BIG_ENDIAN
	u_int pim_vers:4,	/* PIM protocol version         */
	      pim_type:4;	/* PIM message type             */
#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int pim_type:4,	/* PIM message type             */
	      pim_vers:4;	/* PIM protocol version         */
#endif
#endif	/* ! _PIM_VT  */
	uint8_t pim_reserved;	/* Reserved                     */
	uint16_t pim_cksum;	/* IP-style checksum            */
};

/* VLAN header */
struct vlan_ethhdr {
	struct ether_addr d_addr;
	struct ether_addr s_addr;
	uint16_t vlan_proto;
	uint16_t vlan_tci;
	uint16_t enc_etype;
}	__attribute__((__packed__));

#define L4_HDR_LEN 20

#define _ntohs rte_bswap16
#define _htons rte_bswap16
#define _ntohl rte_bswap32
#define _htonl rte_bswap32

#define IP_HDR_LEN 20
#define IP_PKT_MIN_LEN ETHER_HDR_LEN + IP_HDR_LEN + L4_HDR_LEN

#ifndef IPPROTO_OSPFIGP
#define IPPROTO_OSPFIGP	89
#endif

#ifndef IPPROTO_IPV4
#define IPPROTO_IPV4 4
#endif

#define PKT_IP_HDR(m, hdr)					\
	do {							\
		(hdr) = (struct ipv4_hdr *)			\
		    (rte_pktmbuf_mtod((m), uint8_t *) + 	\
		    sizeof(struct ether_hdr));			\
	} while (0)

#define PKT_IP_TX_OFFLOAD(m)					\
	do {							\
		uint8_t *data;					\
		data = rte_pktmbuf_mtod(m, uint8_t *);		\
		data += sizeof(struct ether_hdr);		\
		((struct ipv4_hdr *)data)->hdr_checksum = 0;	\
		m->ol_flags |= PKT_TX_IP_CKSUM;			\
		m->ol_flags |= PKT_TX_IPV4;			\
		m->l2_len = sizeof(struct ether_hdr);		\
		m->l3_len = sizeof(struct ipv4_hdr);		\
	} while (0)

#define PKT_TYPE(m) 						\
	((m) ?							\
		(m)->packet_type ? 				\
			(m)->packet_type			\
		:						\
			pkt_type(m)				\
	:							\
		0)						\

/*
 * We only need this if the NIC does not set the packet type.
 * This is the case with e1000 cards.
 */
#define PKT_INIT(m)						\
	do {							\
		(m)->packet_type = 0;				\
		(m)->udata64 = 0;				\
	} while (0)

#define PKT_FREE(m)						\
	do {							\
		(m)->packet_type = 0;				\
		(m)->udata64 = 0;				\
		rte_pktmbuf_free((m));				\
	} while (0)

#define PKT_VLANID(vlan_tci) (vlan_tci & 0x0fff)

#define PKT_IP_HDR_LEN(hdr) (((hdr)->version_ihl & 0x0f) << 2)

static inline uint32_t
ip_hash_crc(const void *data, __rte_unused uint32_t datalen, uint32_t initval)
{
	const uint32_t *ip;

	ip = data;

#ifdef RTE_MACHINE_CPUFLAG_SSE4_2
	initval = rte_hash_crc_4byte(*ip, initval);
#else	/* RTE_MACHINE_CPUFLAG_SSE4_2 */
	initval = rte_jhash_1word(*ip, initval);
#endif	/* RTE_MACHINE_CPUFLAG_SSE4_2 */

	return initval;
}

inline uint32_t pkt_type(struct rte_mbuf *m);
const struct ether_arp *
          pkt_ether_arp_hdr(const struct rte_mbuf *, const uint8_t *);
const struct ipv4_hdr *pkt_ip_hdr(struct rte_mbuf *, const uint8_t *);
void pkt_dump(const struct rte_mbuf *, const char *);
size_t pkt_add_vlan_hdr(struct rte_mbuf *);

#endif	/* PACKET_H_ */
