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

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <rte_hash.h>
#include <rte_fbk_hash.h>
#include <rte_memory.h>
#include <rte_ether.h>

#include "main.h"
#include "util.h"
#include "runtime.h"
#include "packet.h"
#include "synauth.h"

#define MAX_ENTRIES	1 << 21	/* 2 million */
#define KEY_TTL_US	(uint64_t)(5 * 60 * US_PER_S)	/* 5 minutes */

struct _entry {
	uint32_t ttl;
	int32_t score;
};


static inline int
setup_ack(struct tcp_hdr *th, uint32_t seq)
{
	uint16_t port;

	port = th->src_port;
	th->src_port = th->dst_port;
	th->dst_port = port;
	th->cksum = 0;

	/* ACK an out-of-sequence initial sequence number */
	th->tcp_flags |= TH_ACK;
	th->recv_ack = th->sent_seq - 1;
	th->sent_seq = seq;
}

static inline int
test_rst(struct rte_mbuf *m, uint32_t verifier)
{

}

static void
rekey_context(struct synauth_ctx *ctx, uint64_t now)
{
	uint8_t iv[CIPHER_BLOCK_SIZE] = { 0x0 };
	uint64_t ttl;
	int keylen;

	ttl = TSC2US(now) + KEY_TTL_US;
	ttl = US2TSC(ttl);
	ctx->key_ttl = ttl;

	/* TODO: check return codes */
	keylen = sizeof(ctx->key);
	EVP_EncryptUpdate(&ctx->cipher, ctx->key, &keylen, ctx->key, keylen);
	EVP_EncryptInit(&ctx->cipher, CIPHER_ALGO, ctx->key, iv);
}

static inline uint32_t
create_ip_challenge(void *data, int inlen, struct synauth_ctx *ctx)
{
	uint8_t buf[CIPHER_BLOCK_SIZE * 4];
	uint64_t now;
	uint32_t r;
	int outlen, i;

	assert(sizeof(buf) >= inlen + CIPHER_BLOCK_SIZE);

	r = 0;
	now = now_tsc;

	if (unlikely(ctx->key_ttl > now)) {
		rekey_context(ctx, now);
	}

	/* XXX: check if EncryptUpdate handles negative sizes */
	/* XXX: check return codes */
	EVP_EncryptUpdate(&ctx->cipher, buf, &outlen, data, inlen);
	EVP_EncryptFinal(&ctx->cipher, buf + outlen, &outlen);

	r = *(uint32_t *)(&(buf[outlen - sizeof(uint32_t)]));

	return r;
}

int
synauth_init(struct synauth_ctx *ctx)
{
	struct rte_hash *h;
	char name[64];
	uint8_t iv[CIPHER_BLOCK_SIZE];
	int rc;
	unsigned cid, sid;

	rc = -1;
	cid = rte_lcore_id();
	sid = rte_socket_id();

	/* IP white lists */
	struct rte_fbk_hash_params ip_params = {
		.name = NULL,
		.entries = MAX_ENTRIES,
		.hash_func = ip_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = sid
	};
	struct rte_hash_parameters ip6_params = {
		.name = NULL,
		.entries = MAX_ENTRIES,
		.key_len = sizeof(struct in6_addr),
		.hash_func = ip6_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = sid
	};

	if ((rc = rh_fbk_create(&ctx->ip_wlst, &ip_params)) != 0) {
		goto done;
	}
	if ((rc = rh_create(&ctx->ip6_wlst, &ip6_params)) != 0) {
		goto done;
	}

	/* Crypto context */
	if (EVP_CIPHER_CTX_init(&ctx->cipher) != 1 ||
	    EVP_CIPHER_CTX_set_padding(&ctx->cipher, 0) != 1 ||
	    RAND_bytes(ctx->key, sizeof(ctx->key)) != 1 ||
	    RAND_bytes(iv, sizeof(iv)) != 1 ||
	    EVP_EncryptInit(&ctx->cipher, CIPHER_ALGO, ctx->key, iv) != 1) {
		RTE_LOG(ERR, USER1, "Could not initialize cipher context.\n");
		goto done;
	}

	rc = 0;

done:
	return rc;
}

int
synauth_auth_ip(struct rte_mbuf *m, struct synauth_ctx *ctx)
{
	struct ether_hdr *eh;
	struct ipv4_hdr *ih;
	struct tcp_hdr *th;
	uint8_t *data;
	uint32_t aux;

	data = rte_pktmbuf_mtod(m, uint8_t *);
	eh = (struct ether_hdr *) data;
	ih = (struct ipv4_hdr *) (data + sizeof(struct ether_hdr));

	/* XXX: assumes that the IP header has no options */
	th = (struct tcp_hdr *) (data + sizeof(struct ether_hdr) +
	    (sizeof(struct ipv4_hdr)));

	/* Swap source and destination ethernet addresses */
	PKT_ETH_ADDR_SWAP(eh);

	/* IP header */
	aux = ih->src_addr;
	ih->src_addr = ih->dst_addr;
	ih->dst_addr = aux;
	ih->hdr_checksum = 0;

	/* Choose the initial seqno using a cryptographic function */
	aux = create_ip_challenge(ih, ctx);

	setup_ack(th, aux);
}

int
synauth_auth_ip6(struct rte_mbuf *m, struct synauth_ctx *ctx)
{

}

int
synauth_check_ip(struct rte_mbuf *m, struct synauth_ctx *ctx)
{
	struct _entry *e;
	struct ipv4_hdr *ih;

	ih = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *,
	    sizeof(struct ether_hdr));

	if (likely(rh_lookup_data(ctx->ip_wlst, &ih->src_addr, &e) >= 0)) {
		uint32_t now = US2S(TSC2US(now_tsc));
		if (likey(e->ttl < now)) {
			return 1;
		}
	}

	return 0;
}

static inline int
synauth_trust_ip(struct rte_mbuf *m, struct synauth_ctx *ctx)
{

}

int
synauth_check_ip6(struct rte_mbuf *m, struct synauth_ctx *ctx)
{

}

static inline int
synauth_trust_ip6(struct rte_mbuf *m, struct synauth_ctx *ctx)
{

}

