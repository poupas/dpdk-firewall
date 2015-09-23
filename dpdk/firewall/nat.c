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

#include <rte_hash.h>
#include <rte_hash_crc.h>

#include "main.h"
#include "packet.h"
#include "acl.h"
#include "nat.h"

#define MAX_LINE 1024
#define COMMENT_CHAR '#'

void
nat_free_rules(struct zone_cfg *zone)
{
	uint32_t i;

	for (i = 0; i < RTE_DIM(zone->ip_nat_k); i++) {
		rte_hash_free(zone->ip_nat_k[i]);
		rte_free(zone->ip_nat_v[i]);
	}
}

static int
init_ip_nat(struct zone_cfg *zone)
{
	uint32_t i;
	int ret;

	struct rte_hash_parameters ip_nat_params = {
		.name = NULL,
		.entries = MAX_NAT_ENTRIES,
		.key_len = sizeof(uint32_t),
		.hash_func = ip_hash_crc,
		.hash_func_init_val = 0,
	};

	ret = -1;
	for (i = 0; i < RTE_DIM(zone->ip_nat_k); i++) {
		char name[64];

		snprintf(name, sizeof(name), "ip_nat_%s_%u_%u", zone->name,
		    zone->version, i);

		RTE_LOG(DEBUG, USER1, "Building hash table: %s\n", name);

		/*
		 * XXX: ensure that both rte_hash_create and
		 * rte_zmalloc_socket create a copy of the "name" string.
		 */
		ip_nat_params.name = name;
		ip_nat_params.socket_id = i;
		zone->ip_nat_k[i] = rte_hash_create(&ip_nat_params);
		if (zone->ip_nat_k[i] == NULL) {
			goto fail;
		}
		if ((zone->ip_nat_v[i] = rte_zmalloc_socket(name,
		    MAX_NAT_ENTRIES * sizeof(uint32_t), 0, i)) == NULL) {
			goto fail;
		}
	}

	return 0;

fail:
	nat_free_rules(zone);

	return ret;

}

static int
parse_ip_nat_rule(char *str, struct zone_cfg *zone)
{
	static const char *dlm = " \t\n";
	char *s, *sp, *sn;
	uint32_t key, value, i;
	int32_t r;

	/* XXX: check inet_pton output */
	s = strtok_r(str, dlm, &sp);

	/* Strip out netmask, if provided */
	if ((sn = strstr(s, "/")) != NULL) {
		*sn = '\0';
	}
	inet_pton(AF_INET, s, &key);

	s = strtok_r(NULL, dlm, &sp);
	if ((sn = strstr(s, "/")) != NULL) {
		*sn = '\0';
	}
	inet_pton(AF_INET, s, &value);

	for (i = 0; i < RTE_DIM(zone->ip_nat_k); i++) {
		struct rte_hash *ht = zone->ip_nat_k[i];
		r = rte_hash_add_key(ht, (void *)&key);
		if (r < 0) {
			return -1;
		}
		zone->ip_nat_v[i][r] = value;
	}

	return 0;
}

static int
line_ignored(const char *buff)
{
	int i = 0;

	/* Comment line */
	if (buff[0] == COMMENT_CHAR) {
		return 1;
	}
	/* Empty line */
	while (buff[i] != '\0') {
		if (!isspace(buff[i])) {
			return 0;
		}
		i++;
	}

	return 1;
}

static int
parse_ip_nat(char *path, struct zone_cfg *zone,
    int (*parser) (char *, struct zone_cfg *))
{
	char buff[MAX_LINE];
	FILE *fp;
	unsigned int i, ret;

	if ((fp = fopen(path, "rb")) == NULL) {
		return -1;
	}
	ret = -1;
	i = 0;
	while (fgets(buff, MAX_LINE, fp) != NULL) {
		i++;
		if (line_ignored(buff)) {
			continue;
		}
		if (parser(buff, zone) < 0) {
			goto done;
		}
	}

	ret = 0;
done:
	fclose(fp);

	return ret;

}

int
nat_parse_rules(struct zone_cfg *zone)
{
	char path[MAX_FILE_PATH];
	int ret;

	if ((ret = init_ip_nat(zone)) != 0) {
		RTE_LOG(DEBUG, USER1,
		    "Could not initialize NAT tables for zone %s.\n",
		    zone->name);
		return ret;
	}
	snprintf(path, sizeof(path), "%s/%s.nat.ip.rules",
	    RULE_PATH, zone->name);
	if ((ret = parse_ip_nat(path, zone, parse_ip_nat_rule)) != 0) {
		RTE_LOG(DEBUG, USER1,
		    "Could not open NAT definitions file for zone %s "
		    "(%s): %s.\n", zone->name, path, strerror(errno));
		return ret;
	}
	return ret;
}
