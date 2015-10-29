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

#include "main.h"
#include "packet.h"
#include "runtime.h"
#include "frag.h"

#define	MAX_FLOW_NUM UINT16_MAX
#define	MIN_FLOW_NUM 1
#define	DEF_FLOW_NUM 0x1000

/* TTL numbers are in ms */
#define	MAX_FLOW_TTL (3600 * MS_PER_S)
#define	MIN_FLOW_TTL 1
#define	DEF_FLOW_TTL 5 * MS_PER_S

#define MAX_FRAG_NUM RTE_LIBRTE_IP_FRAG_MAX_FRAG

/* Should be a power of two */
#define	IP_FRAG_TBL_BUCKET_ENTRIES 16

int
frag_init(struct frag_ctx *ctx, struct rte_mempool *pool, uint16_t flows,
    uint16_t ttl)
{
	uint64_t frag_cycles;
	unsigned int socket;

	socket = rte_socket_id();
	frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S * ttl;

	ctx->tbl = rte_ip_frag_table_create(
	    flows,
	    IP_FRAG_TBL_BUCKET_ENTRIES,
	    flows,
	    frag_cycles,
	    socket);
	if (ctx->tbl == NULL) {
		RTE_LOG(ERR, USER1, "Could not create fragment table!\n");
		return -1;
	}
	ctx->pool = pool;

	return 0;
}
