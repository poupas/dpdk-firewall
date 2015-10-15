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

#ifndef NAT_H_
#define NAT_H_

#include <rte_hash.h>

#include "main.h"
#include "zone.h"
#include "acl.h"

static inline uint32_t *
get_ip_addr(struct ipv4_hdr *hdr, uint32_t type)
{
	if (type & ACL_ACTION_SNAT) {
		return &hdr->src_addr;
	} else if (type & ACL_ACTION_DNAT) {
		return &hdr->dst_addr;
	} else {
		return NULL;
	}
}

static inline
void
nat_ip_addr(uint32_t *addr, int32_t ret, uint32_t *ipaddrs)
{
	if (unlikely(ret == -1)) {
		return;
	}
	*addr = ipaddrs[ret];
}

static inline
void
nat_ip_pkt(struct rte_mbuf *m, struct rte_hash *ht, uint32_t *ipaddrs,
    uint32_t type)
{
	struct ipv4_hdr *hdr;
	uint32_t *addr;
	int32_t ret;

	PKT_IP_HDR(m, hdr);
	addr = get_ip_addr(hdr, type);
	if (unlikely(addr == NULL)) {
		return;
	}
	ret = rte_hash_lookup(ht, addr);
	nat_ip_addr(addr, ret, ipaddrs);
	PKT_IP_TX_OFFLOAD(m);
}

static inline
void
nat_ip_4pkts(struct rte_mbuf *m[4], struct rte_hash *ht, uint32_t *ipaddrs,
    uint32_t type[4])
{
	struct ipv4_hdr *hdrs[4];
	uint32_t *addrs[4];
	int32_t ret[4];

	PKT_IP_HDR(m[0], hdrs[0]);
	PKT_IP_HDR(m[1], hdrs[1]);
	PKT_IP_HDR(m[2], hdrs[2]);
	PKT_IP_HDR(m[3], hdrs[3]);

	addrs[0] = get_ip_addr(hdrs[0], type[0]);
	addrs[1] = get_ip_addr(hdrs[1], type[1]);
	addrs[2] = get_ip_addr(hdrs[2], type[2]);
	addrs[3] = get_ip_addr(hdrs[3], type[3]);

	rte_hash_lookup_multi(ht, (const void **)&addrs[0], 4, ret);

	nat_ip_addr(addrs[0], ret[0], ipaddrs);
	nat_ip_addr(addrs[1], ret[1], ipaddrs);
	nat_ip_addr(addrs[2], ret[2], ipaddrs);
	nat_ip_addr(addrs[3], ret[3], ipaddrs);

	PKT_IP_TX_OFFLOAD(m[0]);
	PKT_IP_TX_OFFLOAD(m[1]);
	PKT_IP_TX_OFFLOAD(m[2]);
	PKT_IP_TX_OFFLOAD(m[3]);
}

int nat_parse_rules(struct zone_cfg *);
void nat_free_rules(struct zone_cfg *);

#endif	/* NAT_H_ */
