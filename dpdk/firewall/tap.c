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

/*
 * Create a tap network interface, or use existing one with same name.
 * If name[0]='\0' then a name is automatically assigned and returned in name.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include <netinet/in.h>
#include <linux/if_tun.h>
#include <linux/if.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>

#include <rte_log.h>

#include "main.h"
#include "packet.h"
#include "runtime.h"
#include "forward.h"

int
tap_create(const char *name, struct nic_cfg *nic)
{
	struct ifreq ifr;
	int fd, ret, sock, flags;

	sock = -1;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
		ret = fd;
		goto done;
	}
	flags = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	memset(&ifr, 0, sizeof(ifr));

	/* TAP device without packet information */
	flags = IFF_TAP | IFF_NO_PI;
	ifr.ifr_flags = flags;

	/* Set the interface name */
	if (name && *name) {
		strlcpy(ifr.ifr_name, name, IFNAMSIZ);
	}
	if ((ret = ioctl(fd, TUNSETIFF, &ifr)) < 0) {
		goto done;
	}
	/* Set the mac address of the tap interface */
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	ether_addr_copy(&nic->hwaddr,
	    (struct ether_addr *)&ifr.ifr_hwaddr.sa_data);
	if ((ret = ioctl(fd, SIOCSIFHWADDR, &ifr) < 0)) {
		goto done;
	}
	/* Make room for the vlan tag */
	if ((ret = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
		goto done;
	}
	sock = ret;

	ifr.ifr_mtu = 1504;
	if ((ret = ioctl(sock, SIOCSIFMTU, &ifr)) < 0) {
		goto done;
	}
	/* Bring the interface up */
	ifr.ifr_flags = flags | IFF_UP;
	if ((ret = ioctl(sock, SIOCSIFFLAGS, &ifr)) < 0) {
		goto done;
	}
done:
	if (sock >= 0) {
		close(sock);
	}
	if (ret < 0 && fd >= 0) {
		close(fd);
		fd = -1;
	}
	return fd;
}

uint32_t
tap_fwd_pkts_to_kernel(struct worker_lc_cfg *lp, uint32_t burst)
{
	uint32_t ring, n_rings, n_pkts;

	n_pkts = 0;
	n_rings = lp->n_irings;

	for (ring = 0; ring < n_rings; ring++) {
		struct rte_ring *iring = lp->irings[ring];
		struct rte_mbuf **ibuf = lp->ibuf.array;
		unsigned int n_rx, i;
		ssize_t ret;
		int fd;

		n_rx = rte_ring_sc_dequeue_burst(iring, (void **)ibuf, burst);
		if (unlikely(n_rx > burst)) {
			RTE_LOG(CRIT, USER1, "TAP: error receiving on ring!\n");
			return n_rx;
		}
		if (unlikely(n_rx == 0)) {
			continue;
		}
		n_pkts += n_rx;

#ifdef APP_STATS
		lp->irings_pkts[ring] += n_rx;
#endif

		for (i = 0; i < n_rx; i++) {
			struct rte_mbuf *m = ibuf[i];
			uint8_t *data;
			uint16_t dlen;

			fd = lp->tap.port_to_tap[m->port];

			/* Try to update the ARP table */
			if (arp_chk_gw_pkt(m, now_tsc)) {
				cfg.gws_ts = now_tsc;
			}
			/*
			 * The pkt_tag_vlan may change the packet by adding a
			 * vlan header
			 */
			data = rte_pktmbuf_mtod(m, uint8_t *);
			dlen = pkt_add_vlan_hdr(m);

			/* TODO: retry on EGAIN/EINTR */
			ret = write(fd, data, dlen);

			rte_pktmbuf_free(m);

			if (ret == -1 && errno != EAGAIN && errno != EINTR) {
				RTE_LOG(CRIT, USER1,
				    "Got unexpected error while writing to the "
				    "tap interface: %u\n", errno);
			}
		}
	}

	return n_pkts;
}

uint32_t
tap_fwd_pkts_to_nic(struct worker_lc_cfg *lp, uint32_t burst)
{
	struct rte_mempool *pool;
	uint32_t tap, n_pkts;

	n_pkts = 0;
	pool = cfg.pools[rte_socket_id()];

	for (tap = 0; tap < lp->tap.n_taps; tap++) {
		struct rte_mbuf *m;
		int ret, fd;
		uint32_t pkt, port;

		fd = lp->tap.taps[tap];
		port = lp->tap.tap_to_port[tap];

		for (pkt = 0; pkt < burst; pkt++) {
			m = rte_pktmbuf_alloc(pool);
			if (m == NULL) {
				RTE_LOG(DEBUG, USER1, "Cannot allocate mbuf.\n");
				continue;
			}
			ret = read(fd, rte_pktmbuf_mtod(m, void *), MBUF_SIZE);
			if (unlikely(ret == -1)) {
				if (errno != EAGAIN && errno != EINTR) {
					RTE_LOG(ERR, USER1,
					    "TAP read error: %u\n", errno);
					break;
				}
				rte_pktmbuf_free(m);
				break;
			}
			m->nb_segs = 1;
			m->next = NULL;
			m->pkt_len = (uint16_t)ret;
			m->data_len = (uint16_t)ret;

			m->port = port;
			m->udata64 |= PKT_META_ROUTED | PKT_META_VLAN_TAG;

			ret = rte_ring_sp_enqueue_burst(
			    lp->orings[port], (void **)&m, 1);
			if (unlikely(ret < 1)) {
				rte_pktmbuf_free(m);
			}
			n_pkts++;
		}
	}

	return n_pkts;
}
