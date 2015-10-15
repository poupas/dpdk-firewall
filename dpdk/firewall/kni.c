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

#include <errno.h>

#include <netinet/in.h>
#include <linux/if_tun.h>
#include <linux/if.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>

#include "main.h"
#include "util.h"
#include "runtime.h"
#include "packet.h"
#include "forward.h"

/* Total octets in ethernet header */
#define KNI_ETHER_HEADER_SIZE 14

/* Total octets in the FCS */
#define KNI_ETHER_FCS_SIZE 4

struct rte_kni *
kni_alloc_port(uint8_t port, struct lc_cfg *lcp)
{
	struct ifreq ifr;
	struct rte_kni_conf conf;
	struct rte_kni *kni;
	struct nic_cfg *nic;
	int ret, sock;

	kni = NULL;
	sock = -1;
	ret = -1;
	nic = &cfg.ifaces[port];
	memset(&conf, 0, sizeof(conf));
	snprintf(conf.name, sizeof(conf.name), "mitra%u", port);
	conf.group_id = port;
	conf.mbuf_size = MBUF_SIZE;

	if (lcp->worker.kni.is_master) {
		struct rte_kni_ops ops;
		struct rte_eth_dev_info dev_info;

		memset(&dev_info, 0, sizeof(dev_info));
		rte_eth_dev_info_get(port, &dev_info);
		conf.addr = dev_info.pci_dev->addr;
		conf.id = dev_info.pci_dev->id;

		memset(&ops, 0, sizeof(ops));
		ops.port_id = port;
		ops.change_mtu = kni_change_mtu;
		ops.config_network_if = kni_config_network_if;

		kni = rte_kni_alloc(lcp->pool, &conf, &ops);
	} else {
		kni = rte_kni_alloc(lcp->pool, &conf, NULL);
	}

	if (kni == NULL) {
		RTE_LOG(ERR, USER1, "Could not allocate KNI for port %u!",
		    port);
		goto done;
	}
	/* Configure KNI interface */
	if ((ret = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
		goto done;
	}
	sock = ret;

	/* Set the mac address */
	strlcpy(ifr.ifr_name, conf.name, IFNAMSIZ);
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	ether_addr_copy(
	    &nic->hwaddr, (struct ether_addr *)&ifr.ifr_hwaddr.sa_data);
	if ((ret = ioctl(sock, SIOCSIFHWADDR, &ifr) < 0)) {
		goto done;
	}
	/* Bring the interface up */
	/*
	 * if ((ret = ioctl(sock, SIOCGIFFLAGS, &ifr)) < 0) { goto done; }
	 * 
	 * ifr.ifr_flags |= IFF_UP; if ((ret = ioctl(sock, SIOCSIFFLAGS, &ifr))
	 * < 0) { goto done; }
	 */
done:
	if (sock >= 0) {
		close(sock);
	}
	if (ret < 0 && kni) {
		rte_kni_release(kni);
		kni = NULL;
	}
	return kni;
}

int
kni_change_mtu(uint8_t port_id, unsigned int new_mtu)
{
	int ret;
	struct rte_eth_conf conf;

	return 0;

	if (port_id >= rte_eth_dev_count()) {
		RTE_LOG(DEBUG, KNI, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}
	RTE_LOG(DEBUG, KNI, "Change MTU of port %d to %u\n", port_id, new_mtu);

	/* Stop specific port */
	rte_eth_dev_stop(port_id);

	rte_memcpy(&conf, &port_conf, sizeof(conf));
	/* Set new MTU */
	if (new_mtu > ETHER_MAX_LEN)
		conf.rxmode.jumbo_frame = 1;
	else
		conf.rxmode.jumbo_frame = 0;

	/* MTU + length of header + length of FCS = max pkt length */
	conf.rxmode.max_rx_pkt_len =
	    new_mtu + KNI_ETHER_HEADER_SIZE + KNI_ETHER_FCS_SIZE;
	ret = rte_eth_dev_configure(port_id, 1, 1, &conf);
	if (ret < 0) {
		RTE_LOG(DEBUG, KNI, "Fail to reconfigure port %d\n", port_id);
		return ret;
	}
	/* Restart specific port */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		RTE_LOG(DEBUG, KNI, "Fail to restart port %d\n", port_id);
		return ret;
	}
	return 0;
}

int
kni_config_network_if(uint8_t port_id, uint8_t if_up)
{
	int ret = 0;

	return 0;

	if (port_id >= rte_eth_dev_count() || port_id >= RTE_MAX_ETHPORTS) {
		RTE_LOG(DEBUG, KNI, "Invalid port id %d\n", port_id);
		return -EINVAL;
	}
	RTE_LOG(DEBUG, KNI, "Configure network interface of %d %s\n",
	    port_id, if_up ? "up" : "down");

	if (if_up != 0) {	/* Configure network interface up */
		rte_eth_dev_stop(port_id);
		ret = rte_eth_dev_start(port_id);
	} else {	/* Configure network interface down */
		rte_eth_dev_stop(port_id);
	}
	if (ret < 0) {
		RTE_LOG(DEBUG, KNI, "Failed to start port %d\n", port_id);
	}
	return ret;
}

uint32_t
kni_fwd_pkts_to_kernel(struct worker_lc_cfg *lp, uint32_t burst)
{
	uint32_t n_rings, r, n_pkts;

	n_pkts = 0;
	n_rings = lp->n_irings;

	for (r = 0; r < n_rings; r++) {
		struct rte_ring *iring = lp->irings[r];
		struct rte_mbuf **ibuf = lp->ibuf.array;
		uint32_t base, cur, n_rx, n_tx, port;

		n_rx = rte_ring_sc_dequeue_burst(iring, (void **)ibuf, burst);
		if (unlikely(n_rx > burst)) {
			RTE_LOG(CRIT, USER1, "KNI: error receiving on ring!\n");
			return n_pkts;
		}
		if (unlikely(n_rx == 0)) {
			continue;
		}
		n_pkts += n_rx;
		base = 0;
		cur = 0;
		port = ibuf[0]->port;
		while (base < n_rx) {
			struct rte_kni *kni;
			size_t len;
			int ret;

			port = ibuf[cur]->port;
			while (cur < n_rx && ibuf[cur]->port == port) {
				if (arp_chk_gw_pkt(ibuf[cur], now_tsc)) {
					cfg.gws_ts = now_tsc;
				}
				/*
				 * The pkt_tag_vlan may change the packet by
				 * adding a vlan header
				 */
				pkt_add_vlan_hdr(ibuf[cur]);

				cur++;
			}

			/* Burst packets to KNI */
			len = cur - base;

			kni = lp->kni.kni[lp->kni.port_to_kni[port]];
			n_tx = rte_kni_tx_burst(kni, ibuf + base, len);
			ret = rte_kni_handle_request(kni);
			if (ret < 0) {
				RTE_LOG(CRIT, USER1,
				    "Error sending packets to kernel.\n");
			}
			if (unlikely(n_tx < len)) {
				util_free_mbufs_burst(
				    &ibuf[base + n_tx], len - n_tx);
			}
			base = cur;
		}
	}

	return n_pkts;
}

uint32_t
kni_fwd_pkts_to_nic(struct worker_lc_cfg *lp, uint32_t burst)
{
	uint32_t r, port, n_kni, n_pkts;

	n_pkts = 0;
	n_kni = lp->kni.n_kni;

	for (r = 0; r < n_kni; r++) {
		struct rte_kni *kni;
		struct rte_mbuf **outbuf;
		unsigned i, n_rx, n_tx;

		kni = lp->kni.kni[r];
		port = lp->kni.kni_to_port[r];
		outbuf = lp->obuf[port].array;

		n_rx = rte_kni_rx_burst(kni, outbuf, burst);
		if (unlikely(n_rx > burst)) {
			RTE_LOG(CRIT, USER1, "KNI: error receiving on ring!\n");
			return n_pkts;
		}
		if (unlikely(n_rx == 0)) {
			continue;
		}
		for (i = 0; i < n_rx; i++) {
			outbuf[i]->port = port;
			outbuf[i]->udata64 |=
			    PKT_META_ROUTED | PKT_META_VLAN_TAG;
		}

		/* Burst packets to IO tx lcore */
		n_tx = rte_ring_sp_enqueue_burst(
		    lp->orings[port], (void **)outbuf, n_rx);

		if (unlikely(n_tx < n_rx)) {
			util_free_mbufs_burst(&outbuf[n_tx], n_rx - n_tx);
		}
		n_pkts += n_rx;
	}

	return n_pkts;
}
