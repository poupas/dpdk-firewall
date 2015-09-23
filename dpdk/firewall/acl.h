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

#ifndef ACL_H_
#define ACL_H_

#include <rte_ip.h>
#include <rte_acl.h>

#include "main.h"
#include "zone.h"

#define MAX_ACL_CATEGORIES 1

/*
 * These flags must be kept in sync with build_rules.py
 *
 * Please note that the last 4 bits are reserved for
 * rule statistics purposes.
 */
#define ACL_ACTION_ACCEPT	1 << 0
#define ACL_ACTION_DROP		1 << 1
#define ACL_ACTION_LOCAL	1 << 2
#define ACL_ACTION_SNAT		1 << 3
#define ACL_ACTION_DNAT		1 << 4
#define ACL_ACTION_COUNT	1 << 5
#define ACL_ACTION_MONIT	1 << 6

#define UDATA_BITS (sizeof(uint32_t) * 8)
#define COUNT_BITS (4)
#define COUNT_SHIFT (UDATA_BITS - COUNT_BITS)

#define ACL_COUNT_ID(udata) ((udata >> COUNT_SHIFT) & 0x0f)

struct acl_counter {
	uint64_t packets;
	uint64_t bytes;
};

struct acl_ctx {
	const uint8_t *ip_data[BATCH_SIZE_ACL];
	struct rte_mbuf *ip_m[BATCH_SIZE_ACL];
	uint32_t ip_res[BATCH_SIZE_ACL];
	uint16_t n_ip;

	const uint8_t *ip6_data[BATCH_SIZE_ACL];
	struct rte_mbuf *ip6_m[BATCH_SIZE_ACL];
	uint32_t ip6_res[BATCH_SIZE_ACL];
	uint16_t n_ip6;
};

int acl_parse_rules(struct zone_cfg *);
void acl_free_rules(struct zone_cfg *);

#endif	/* ACL_H_ */
