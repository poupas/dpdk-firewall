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

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>

#include <rte_mbuf.h>
#include <stdint.h>
#include <rte_log.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_eth_ctrl.h>
#include <rte_ethdev.h>
#include <rte_common.h>

#include "main.h"
#include "util.h"
#include "runtime.h"
#include "packet.h"


int
scan_vlans(void)
{
	struct ifaddrs *ifaddr, *ifa;
	uint16_t vlan;
	int family, n, changed;

	if (getifaddrs(&ifaddr) == -1) {
		RTE_LOG(DEBUG, USER1, "getifaddrs: %d\n", errno);
		return -1;
	}
	changed = 0;
	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}
		/* Only interested in vlan interfaces */
		if (sscanf(ifa->ifa_name, "vlan%" SCNu16, &vlan) != 1) {
			continue;
		}
		family = ifa->ifa_addr->sa_family;
		if (family == AF_INET) {
			struct sockaddr_in *sa, *sm;
			in_addr_t addr, mask, net;

			sa = (struct sockaddr_in *)ifa->ifa_addr;
			sm = (struct sockaddr_in *)ifa->ifa_netmask;

			addr = sa->sin_addr.s_addr;
			mask = sm->sin_addr.s_addr;
			net = addr & mask;

			if (addr != cfg.vlans[vlan].ip.s_addr) {
				cfg.vlans[vlan].ip.s_addr = addr;
			}
			if (net != cfg.vlans[vlan].ip_net.s_addr) {
				changed = 1;
				cfg.vlans[vlan].ip_net.s_addr = net;
				cfg.vlans[vlan].ip_mask.s_addr = mask;
			}
		} else if (family == AF_INET6) {
			struct sockaddr_in6 *sa, *sm;
			__m128i addr, mask, net;

			sa = (struct sockaddr_in6 *)ifa->ifa_addr;
			sm = (struct sockaddr_in6 *)ifa->ifa_netmask;

			addr = _mm_loadu_si128((__m128i *) & sa->sin6_addr);
			mask = _mm_loadu_si128((__m128i *) & sm->sin6_addr);
			net = _mm_and_si128(addr, mask);

			if (!is_equal128(addr, cfg.vlans[vlan].ip6.xmm)) {
				_mm_store_si128(&cfg.vlans[vlan].ip6.xmm, addr);
			}
			if (!is_equal128(net, cfg.vlans[vlan].ip6_net.xmm)) {
				changed = 1;
				_mm_store_si128(&cfg.vlans[vlan].ip6_net.xmm,
				    net);
				_mm_store_si128(&cfg.vlans[vlan].ip6_mask.xmm,
				    mask);
			}
		}
	}
	freeifaddrs(ifaddr);

	return changed;
}
