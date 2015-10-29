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
#define KEY_TTL_US	(uint64_t)(1 * 60 * US_PER_S)	/* 1 minutes */
#define IP_TTL_S	(uint32_t)(5 * 60)	/* 5 minutes */

struct _entry {
	uint32_t ttl;
	int32_t score;
};

#define AUTH_PKT(ctx, ih, th, r)					      \
	do {								      \
	(r) = data_hash_crc(&(ih)->src_addr, sizeof((ih)->src_addr) * 2, 0);  \
	(r) = data_hash_crc(&(th)->src_port, sizeof((th)->src_port) * 2, r);  \
	(r) = authenticate(ctx, &(r), sizeof(r));			      \
	} while (0)

static void
rekey_context(struct synauth_ctx *ctx, uint64_t now)
{
	uint64_t ttl;
	int keylen;

	ttl = TSC2US(now) + KEY_TTL_US;
	ttl = US2TSC(ttl);
	ctx->key_ttl = ttl;

	/* TODO: check return codes */
	keylen = sizeof(ctx->key);
	EVP_EncryptUpdate(&ctx->cipher, ctx->key, &keylen, ctx->key, keylen);
	EVP_EncryptInit(&ctx->cipher, CIPHER_ALGO, ctx->key, NULL);
}

static inline uint32_t
authenticate(struct synauth_ctx *ctx, void *data, size_t inlen)
{
	uint8_t buf[CIPHER_BLOCK_SIZE];
	uint64_t now;
	uint32_t r;
	int outlen;

	assert(sizeof(buf) >= inlen);

	memset(buf, 0, sizeof(buf));
	rte_memcpy(buf, data, inlen);
	r = 0;
	now = now_tsc;

	if (unlikely(ctx->key_ttl > now)) {
		rekey_context(ctx, now);
	}
	/* XXX: check if EncryptUpdate handles negative sizes */
	/* XXX: check return codes */
	EVP_EncryptUpdate(&ctx->cipher, buf, &outlen, buf, sizeof(buf));
	EVP_EncryptFinal(&ctx->cipher, buf + outlen, &outlen);

	r = *(uint32_t *)(&(buf[outlen - sizeof(uint32_t)]));

	return r;
}

static int
trust_ip(struct synauth_ctx *ctx, struct ipv4_hdr *ih)
{
	struct _entry e;
	uint64_t now_us;
	uint32_t now_s;

	now_us = TSC2US(now_tsc);
	now_s = US2S(now_us);

	e.score = 0;
	e.ttl = now_s + IP_TTL_S;

	return rh_add_key_data(&ctx->ip_wlst, ih, &e, now_us);
}

static int
trust_ip6(struct synauth_ctx *ctx, struct ipv6_hdr *ih)
{
	struct _entry e;
	uint64_t now_us;
	uint32_t now_s;

	now_us = TSC2US(now_tsc);
	now_s = US2S(now_us);

	e.score = 0;
	e.ttl = now_s + IP_TTL_S;

	return rh_add_key_data(&ctx->ip6_wlst, ih, &e, now_us);
}

static void
setup_ack(struct tcp_hdr *th, uint32_t seq)
{
	uint16_t port;

	port = th->src_port;
	th->src_port = th->dst_port;
	th->dst_port = port;
	th->cksum = 0;

	/* ACK an out-of-sequence initial sequence number */
	th->tcp_flags |= TH_ACK;
	th->recv_ack = th->sent_seq;
	th->sent_seq = seq;
}

int
synauth_vrfy_ip(struct synauth_ctx *ctx, struct rte_mbuf *m)
{
	struct ipv4_hdr *ih;
	struct tcp_hdr *th;
	uint32_t aux;

	ih = rte_pktmbuf_mtod_offset(m, void *, sizeof(struct ether_hdr));
	th = ip_l4_hdr(m);

	/* TCP initial seqno (srcip + dstip + srcport + dstport) */
	AUTH_PKT(ctx, ih, th, aux);

	if (aux == th->recv_ack) {
		trust_ip(ctx, ih);
		return SYNAUTH_OK;
	}

	return SYNAUTH_INVALID;
}

int
synauth_vrfy_ip6(struct synauth_ctx *ctx, struct rte_mbuf *m)
{
	struct ipv6_hdr *ih;
	struct tcp_hdr *th;
	uint32_t aux;

	ih = rte_pktmbuf_mtod_offset(m, void *, sizeof(struct ether_hdr));
	th = ip6_l4_hdr(m);

	/* TCP initial seqno (srcip + dstip + srcport + dstport) */
	AUTH_PKT(ctx, ih, th, aux);

	if (th->recv_ack == aux) {
		trust_ip6(ctx, ih);
		return SYNAUTH_OK;
	}

	return SYNAUTH_INVALID;
}

int
synauth_init(struct synauth_ctx *ctx)
{
	char name[64];
	int rc;
	unsigned cid, sid;

	rc = -1;
	cid = rte_lcore_id();
	sid = rte_socket_id();

	/* IP white lists */
	snprintf(name, sizeof(name), "synwl_ip_c%d_s%d", cid, sid);
	struct rte_hash_parameters ip_params = {
		.name = name,
		.entries = MAX_ENTRIES,
		.key_len = sizeof(struct in_addr),
		.hash_func = ip_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = sid
	};
	if ((rc = rh_create(&ctx->ip_wlst, &ip_params)) != 0) {
		goto done;
	}

	snprintf(name, sizeof(name), "synwl_ip6_c%d_s%d", cid, sid);
	struct rte_hash_parameters ip6_params = {
		.name = name,
		.entries = MAX_ENTRIES,
		.key_len = sizeof(struct in6_addr),
		.hash_func = ip6_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = sid
	};
	if ((rc = rh_create(&ctx->ip6_wlst, &ip6_params)) != 0) {
		goto done;
	}

	/* Crypto context */
	EVP_CIPHER_CTX_init(&ctx->cipher);
	if (EVP_CIPHER_CTX_set_padding(&ctx->cipher, 0) != 1 ||
	    RAND_bytes(ctx->key, sizeof(ctx->key)) != 1 ||
	    EVP_EncryptInit(&ctx->cipher, CIPHER_ALGO, ctx->key, NULL) != 1) {
		RTE_LOG(ERR, USER1, "Could not initialize cipher context.\n");
		goto done;
	}
	rc = 0;

done:
	return rc;
}

int
synauth_auth_ip(struct synauth_ctx *ctx, struct rte_mbuf *m)
{
	struct ether_hdr *eh;
	struct ipv4_hdr *ih;
	struct tcp_hdr *th;
	uint32_t aux;

	eh = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ih = (struct ipv4_hdr *)(eh + 1);
	th = ip_l4_hdr(m);

	/* TCP initial seqno (srcip + dstip + srcport + dstport) */
	AUTH_PKT(ctx, ih, th, aux);
	setup_ack(th, aux);

	/* IP header */
	aux = ih->src_addr;
	ih->src_addr = ih->dst_addr;
	ih->dst_addr = aux;
	ih->hdr_checksum = 0;

	/* Swap source and destination ethernet addresses */
	PKT_ETH_ADDR_SWAP(eh);

	/* Offload checksum calculations */
	PKT_TCP_IP_TX_OFFLOAD(m, th);

	m->udata64 |= PKT_META_ROUTED;

	return 0;
}

int
synauth_auth_ip6(struct synauth_ctx *ctx, struct rte_mbuf *m)
{
	struct ether_hdr *eh;
	struct ipv6_hdr *ih;
	struct tcp_hdr *th;
	struct in6_addr ipa;
	uint32_t aux;

	/* TODO: build a new packet with no header options. */

	eh = rte_pktmbuf_mtod(m, struct ether_hdr *);
	ih = (struct ipv6_hdr *)(eh + 1);
	th = ip6_l4_hdr(m);

	/* TCP initial seqno (srcip + dstip + srcport + dstport) */
	AUTH_PKT(ctx, ih, th, aux);
	setup_ack(th, aux);

	/* IP header */
	rte_memcpy(&ipa.s6_addr, &ih->src_addr, sizeof(struct in6_addr));
	rte_memcpy(&ih->src_addr, &ih->dst_addr, sizeof(struct in6_addr));
	rte_memcpy(&ih->dst_addr, &ipa.s6_addr, sizeof(struct in6_addr));

	/* Swap source and destination ethernet addresses */
	PKT_ETH_ADDR_SWAP(eh);

	m->udata64 |= PKT_META_ROUTED;

	return 0;
}

int
synauth_test_ip(struct synauth_ctx *ctx, struct rte_mbuf *m)
{
	struct _entry *e;
	struct ipv4_hdr *ih;

	ih = rte_pktmbuf_mtod_offset(m, void *, sizeof(struct ether_hdr));

	if (rh_lookup_data(&ctx->ip_wlst, &ih->src_addr, (void **)&e) >= 0) {
		uint32_t now = US2S(TSC2US(now_tsc));
		if (likely(e->ttl < now)) {
			return SYNAUTH_OK;
		}
	}

	return SYNAUTH_IP_AUTH;
}


int
synauth_test_ip6(struct synauth_ctx *ctx, struct rte_mbuf *m)
{
	struct _entry *e;
	struct ipv6_hdr *ih;

	ih = rte_pktmbuf_mtod_offset(m, void *, sizeof(struct ether_hdr));
	if (rh_lookup_data(&ctx->ip6_wlst, &ih->src_addr, (void **)&e) >= 0) {
		uint32_t now = US2S(TSC2US(now_tsc));
		if (likely(e->ttl < now)) {
			return SYNAUTH_OK;
		}
	}

	return SYNAUTH_IP6_AUTH;
}
