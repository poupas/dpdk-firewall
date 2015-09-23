#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <pcap/pcap.h>
#include <inttypes.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define FILTERSIZE	1024
#define CAPSIZE		1500

struct p_tcphdr {
	struct in_addr srcip;
	struct in_addr dstip;
	uint8_t zeroes;
	uint8_t protocol;
	uint16_t len;
}	__attribute__((__packed__));

uint16_t
in_cksum(void *addr, size_t size, uint16_t init)
{
	uint16_t *buffer;
	uint32_t cksum;

	buffer = addr;
	cksum = init;

	while (size > 1) {
		cksum += *buffer++;
		size -= sizeof(uint16_t);
	}

	if (size)
		cksum += *(uint8_t *)buffer;

	while (cksum >> 16)
		cksum = (cksum >> 16) + (cksum & 0xffff);

	return (uint16_t)(~cksum);
}

static void
hexdump(const void *data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';

	for (i = 0; i < size; i++) {
		printf("%02X ", ((uint8_t*) data)[i]);
		if (((uint8_t *) data)[i] >= ' '&&
		    ((uint8_t *) data)[i] <= '~') {
			ascii[i % 16] = ((uint8_t*) data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i + 1) % 8 == 0 || i + 1 == size) {
			printf(" ");
			if ((i + 1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i + 1 == size) {
				ascii[(i + 1) % 16] = '\0';
				if ((i + 1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i + 1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

static size_t
create_syn_challenge(uint8_t *data, size_t len)
{
	struct ether_addr ea;
	struct in_addr ina;
	struct p_tcphdr pth;
	struct ether_header *eh;
	struct ip *ih;
	struct tcphdr *th;
	size_t iplen;
	uint16_t port, csum;
	static int cnt = 0;
	uint8_t rand[8];
	int fd;

	eh = (struct ether_header *)data;
	ih = (struct ip *)(data + sizeof(struct ether_header));
	th = (struct tcphdr *)
	    (data + sizeof(struct ether_header) + sizeof(struct ip));

	/* Ethernet */
	memcpy(&ea, &eh->ether_shost, sizeof(struct ether_addr));
	memcpy(&eh->ether_shost, &eh->ether_dhost, sizeof(struct ether_addr));
	memcpy(&eh->ether_dhost, &ea, sizeof(struct ether_addr));

	/* IP */
	ina = ih->ip_src;
	ih->ip_src = ih->ip_dst;
	ih->ip_dst = ina;
	ih->ip_sum = 0;
	ih->ip_sum = in_cksum(ih, ih->ip_hl * 4, 0);

	/* TCP */
	port = th->th_sport;
	th->th_sport = th->th_dport;
	th->th_dport = port;
	th->th_sum = 0;

    /* XXX: check open() and read() return values */	
	fd = open("/dev/urandom", O_RDONLY);
	read(fd, &rand, sizeof(rand));
	close(fd);

	/* ACK an out-of-sequence initial sequence number */
	th->th_flags |= TH_ACK;
	if (cnt < 2) {
		th->th_ack = *(uint32_t *)rand;
		fprintf(stderr,
		    "[+] Sending out-of-sequence SYN+ACK reply: "
		    "%" PRIu32 " (should be: %" PRIu32 ")\n",
		    ntohl(th->th_ack), ntohl(th->th_seq) + 1);
		cnt++;
	} else {
		th->th_ack = htonl(ntohl(th->th_seq) + 1);
		fprintf(stderr,
		    "[+] Sending correct SYN+ACK reply: %" PRIu32 "\n",
		    ntohl(th->th_ack));
		cnt = 0;
	}
	th->th_seq = *(uint32_t *) rand + 4;
	
	/* TCP checksum */
	iplen = ntohs(ih->ip_len);
	iplen -= ih->ip_hl * 4;

	pth.srcip = ih->ip_src;
	pth.dstip = ih->ip_dst;
	pth.zeroes = 0;
	pth.protocol = IPPROTO_TCP;
	pth.len = htons(iplen);

	csum = in_cksum(&pth, sizeof(struct p_tcphdr), 0);
	th->th_sum = in_cksum(th, iplen, ~csum);

	return len;
}

static void
handler(uint8_t *addr, const struct pcap_pkthdr *hdr, const uint8_t *data)
{
	uint8_t buffer[CAPSIZE];
	pcap_t *h;
	struct ip *ih;
	struct tcphdr *th;

	/*
	printf("Got this:\n");
	hexdump(data, hdr->len);
	*/

    /* XXX: headers and size sanity checks */

	h = (pcap_t *)addr;
	ih = (struct ip *)(data + sizeof(struct ether_header));
	th = (struct tcphdr *)
	    (data + sizeof(struct ether_header) + sizeof(struct ip));

	if (ih->ip_p != IPPROTO_TCP) {
		fprintf(stderr, "[-] Ignoring non-TCP packet...\n");
		return;
	}

	if (th->th_flags & TH_SYN) {
		size_t len;

		if (th->th_flags & TH_ACK) {
			fprintf(stderr, "[-] Ignoring SYN+ACK reply...\n");
		}

		len = hdr->len;
		fprintf(stderr, "[+] Received SYN packet...\n");
		memcpy(buffer, data, hdr->len);
		if ((len = create_syn_challenge(buffer, len)) == 0) {
			fprintf(stderr, "[!] Could not build packet.\n");
			return;
		}

		if (pcap_inject(h, buffer, len) == -1) {
			fprintf(stderr,
			    "[!] Could not send packet: %s\n", pcap_geterr(h));
		}
	} else if ((th->th_flags & TH_ACK) &&
	    !(th->th_flags & (TH_PUSH|TH_FIN|TH_RST))) {
		fprintf(stderr, "[+] Connection established.\n");
	} else if (th->th_flags & TH_RST) {
		fprintf(stderr, "[-] Connection reset by remote host. "
		    "Sequence number: %" PRIu32 ".\n", ntohl(th->th_seq));
	}
}

int
main(int argc, char *argv[])
{
	char filter[FILTERSIZE];
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program bpf;
	char *dev, *port_str;
	pcap_t *h;
	uint32_t mask, net;
	uint16_t port;

	if (argc < 3) {
		fprintf(stderr, "usage: %s <dev> <port>\n", argv[0]);
		return -1;
	}

	dev = argv[1];
	port_str = argv[2];

	if (sscanf(port_str, "%" SCNu16, &port) != 1) {
		fprintf(stderr, "Invalid port number: %s\n", port_str);
		return -1;
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) != 0) {
		fprintf(stderr,
		    "Could not get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	if ((h = pcap_open_live(dev, CAPSIZE, 0, 1000, errbuf)) == NULL) {
		fprintf(stderr,
		    "Error opening device %s: %s\n", dev, errbuf);
		return -1;
	}

	if (pcap_datalink(h) != DLT_EN10MB) {
		fprintf(stderr,
		    "%s does not support ethernet headers\n", dev);
		return -1;
	}

	snprintf(filter, sizeof(filter), "tcp port %" PRIu16, port);
	if (pcap_compile(h, &bpf, filter, 0, net) != 0) {
		 fprintf(stderr,
		    "Could not parse filter %s: %s\n", filter, pcap_geterr(h));
		 return -1;
	 }

	 if (pcap_setfilter(h, &bpf) != 0) {
		 fprintf(stderr,
		    "Could not install filter %s: %s\n", filter, pcap_geterr(h));
		 return -1;
	 }

	 pcap_loop(h, -1, handler, (uint8_t *)h);

	 pcap_freecode(&bpf);
	 pcap_close(h);

	 return 0;
}
