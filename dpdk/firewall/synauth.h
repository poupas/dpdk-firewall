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

#ifndef SYNAUTH_H_
#define SYNAUTH_H_

#include <string.h>
#include <errno.h>

#include <openssl/evp.h>

#include "rollhash.h"

#define CIPHER_ALGO		(EVP_aes_128_ecb())
#define CIPHER_KEY_SIZE 	16
#define CIPHER_BLOCK_SIZE	16

struct synauth_ctx {
	struct rollhash ip_wlst;
	struct rollhash ip6_wlst;
	EVP_CIPHER_CTX cipher;
	uint8_t key[CIPHER_KEY_SIZE];
	uint64_t key_ttl;
};

#define SYNAUTH_OK		0
#define SYNAUTH_IP_AUTH		1
#define SYNAUTH_IP6_AUTH	2
#define SYNAUTH_INVALID		3
#define SYNAUTH_ERROR		4

int synauth_init(struct synauth_ctx *);
int synauth_vrfy_ip(struct synauth_ctx *, struct rte_mbuf *);
int synauth_vrfy_ip6(struct synauth_ctx *, struct rte_mbuf *);
int synauth_auth_ip(struct synauth_ctx *, struct rte_mbuf *);
int synauth_auth_ip6(struct synauth_ctx *, struct rte_mbuf *);
int synauth_test_ip(struct synauth_ctx *, struct rte_mbuf *);
int synauth_test_ip6(struct synauth_ctx *, struct rte_mbuf *);

#endif	/* SYNAUTH_H_ */
