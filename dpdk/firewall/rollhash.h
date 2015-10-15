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

#ifndef ROLLHASH_H_
#define ROLLHASH_H_

#include <string.h>
#include <errno.h>

#include <rte_hash.h>
#include <rte_fbk_hash.h>
#include <rte_cycles.h>

#define HASH_TTL_US 60 * US_PER_S

struct transient_hash {
	struct rte_hash *h;
	uint64_t ttl;
};

struct rollhash {
	struct transient_hash cur;
	struct transient_hash old;
};


static inline int
rh_fbk_create(struct rollhash *rh, struct rte_fbk_hash_params *p)
{
	struct rte_hash *tables[2];
	char orig_name, name[64];
	int i, rc;

	rc = -1;
	orig_name = p->name;
	p->name = name;

	/* Ensure the sum of internal entries matches the requested count */
	p->entries /= 2;

	for (i = 0; i < 2; i++) {
		snprintf(name, sizeof(name), "%s_%d", orig_name, i);
		tables[i] = rte_fbk_hash_create(p);
		if (tables[i] == NULL) {
			goto done;
		}
	}

	rc = 0;
	rh->old = tables[0];
	rh->cur = tables[1];

done:
	if (rc < 0) {
		if (tables[0] != NULL)
			rte_fbk_hash_free(tables[0]);
		if (tables[1] != NULL)
			rte_fbk_hash_free(tables[1]);
	}
	return rc;
}

static inline int
rh_create(struct rollhash *rh, struct rte_hash_parameters *p)
{
	struct rte_hash *tables[2];
	char orig_name, name[64];
	int i, rc;

	rc = -1;
	orig_name = p->name;
	p->name = name;

	/* Ensure the sum of internal entries matches the requested count */
	p->entries /= 2;

	for (i = 0; i < 2; i++) {
		snprintf(name, sizeof(name), "%s_%d", orig_name, i);
		tables[i] = rte_hash_create(p);
		if (tables[i] == NULL) {
			goto done;
		}
	}

	rc = 0;
	rh->old = tables[0];
	rh->cur = tables[1];

done:
	if (rc < 0) {
		if (tables[0] != NULL)
			rte_hash_free(tables[0]);
		if (tables[1] != NULL)
			rte_hash_free(tables[1]);
	}
	return rc;
}

static inline int
rh_add_key_data(struct rollhash *rh, const void *key, void *data,
    uint64_t now_us)
{
	struct rte_hash *tmp;
	int32_t rc;

	rc = rte_hash_add_key_data(rh->cur.h, key, data);
	if (likely(rc >= 0)) {
		rh->cur.ttl = now_us + HASH_TTL_US;
		return rc;
	}
	/* Check if previous hash table may still have valid entries */
	if (unlikely(rh->old.ttl < now_us)) {
		return rc;
	}
	/* Roll-over hashtables */
	tmp = rh->cur.h;

	rte_rash_reset(rh->old.h);
	rh->cur.h = rh->old.h;

	rh->old.h = tmp;
	rh->old.ttl = rh->cur.ttl;

	rh->cur.ttl = now_us + HASH_TTL_US;
	rc = rte_hash_add_key_data(rh->cur.h, key, data);

	return rc;
}

static inline int
rh_lookup_data(struct rollhash *rh, const void *key, void **data)
{
	int rc;

	rc = rte_hash_lookup_data(rh->cur.h, key, data);
	if (rc >= 0) {
		return rc;
	}
	return rte_hash_lookup_data(rh->old.h, key, data);
}

#endif	/* ROLLHASH_H_ */
