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

#ifndef UTIL_H_
#define UTIL_H_

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include <rte_ring.h>
#include <rte_lcore.h>
#include <rte_cycles.h>

#include "strutil.h"

#define US2TSC(x) (tsc_per_us * (x))
#define TSC2US(x) ((x) / tsc_per_us)

#define US2S(x) (x / US_PER_S)

#define container_of(ptr, type, member) ({			\
	const typeof(((type *)0)->member) *__mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member));})

void util_free_mbufs_burst(struct rte_mbuf **, unsigned);

static inline int
is_equal128(__m128i a, __m128i b)
{
	__m128i zero = _mm_setzero_si128();
	__m128i c = _mm_xor_si128(a, b);
	return _mm_testc_si128(zero, c);
}

static inline int is_power_of_two(uint32_t a)
{
    return (a != 0) && ((a & (a - 1)) == 0);
}

static inline void
make_ts(char *out, size_t outsiz)
{
	char buf[2048];
	struct timeval tv;
	struct tm *tm;

	gettimeofday(&tv, NULL);
	if ((tm = localtime(&tv.tv_sec)) != NULL) {
		strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S.", tm);
		snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf),
		    "%06ld", tv.tv_usec);
		if (out != NULL) {
			snprintf(out, outsiz, "%s", buf);
		}
	}
}

#define LOG(l, t, ...)							\
	do {								\
		uint32_t len;						\
		char head[128], buf[2048];				\
		make_ts(head, sizeof(head));				\
		snprintf(buf, sizeof(buf), "%s [%u] ",			\
		    head, rte_lcore_id());				\
		len = strlen(buf);					\
		snprintf(buf + len, sizeof(buf) - len, __VA_ARGS__);	\
		rte_log(						\
		    RTE_LOG_ ## l, RTE_LOGTYPE_ ## t, # t ": %s", buf); \
	} while (0)

static inline void
util_flush_sp_ring_buffer(struct rte_ring *ring, struct mbuf_array *buffer)
{
	unsigned n_tx;

	n_tx = rte_ring_sp_enqueue_burst(ring, (void **)buffer->array,
	    buffer->n_mbufs);
	if (unlikely(n_tx < buffer->n_mbufs)) {
		util_free_mbufs_burst(&buffer->array[n_tx],
		    buffer->n_mbufs - n_tx);
	}
	buffer->n_mbufs = 0;
}

static inline void
util_flush_mp_ring_buffer(struct rte_ring *ring, struct mbuf_array *buffer)
{
	unsigned n_tx;

	n_tx = rte_ring_mp_enqueue_burst(ring, (void **)buffer->array,
	    buffer->n_mbufs);
	if (unlikely(n_tx < buffer->n_mbufs)) {
		util_free_mbufs_burst(&buffer->array[n_tx],
		    buffer->n_mbufs - n_tx);
	}
	buffer->n_mbufs = 0;
}

#endif	/* UTIL_H_ */
