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

#ifndef FRAG_H_
#define FRAG_H_

struct frag_ctx {
	struct rte_ip_frag_tbl *tbl;
	struct rte_mempool *pool;
	struct rte_ip_frag_death_row death_row;
};

int frag_init(struct frag_ctx *, struct rte_mempool *, uint16_t, uint16_t);

struct rte_mbuf *
frag_ip_reass(struct frag_ctx *, struct ipv4_hdr *,
    struct rte_mbuf *);

static inline struct rte_mbuf *
frag_ip_reass(struct frag_ctx *ctx, struct ipv4_hdr *ih, struct rte_mbuf *m)
{
	struct rte_mbuf *mo;

	mo = rte_ipv4_frag_reassemble_packet(ctx->tbl, &ctx->death_row, m,
	    now_tsc, ih);

	return mo;
}

static inline struct rte_mbuf *
frag_ip6_reass(struct frag_ctx *ctx, struct rte_mbuf *m)
{
	struct ether_hdr *eh;
	struct ipv6_hdr *ih;
	struct ipv6_extension_fragment *fh;
	struct rte_mbuf *mo;

	eh = rte_pktmbuf_mtod(*m, struct ether_hdr *);
	ih = (struct ipv6_hdr *)(eh + 1);
	fh = rte_ipv6_frag_get_ipv6_fragment_header(ih);

	if (unlikely(fh == NULL)) {
		return NULL;
	}
	mo = rte_ipv6_frag_reassemble_packet(ctx->tbl, &ctx->death_row, m,
	    now_tsc, ih);

	return mo;
}

#endif	/* FRAG_H_ */
