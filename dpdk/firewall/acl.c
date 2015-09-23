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

#include <errno.h>
#include <string.h>
#include <netdb.h>

#include <rte_acl.h>
#include <rte_log.h>

#include "main.h"
#include "acl.h"

#include "strutil.h"

#define COMMENT_LEAD_CHAR ('#')
#define MAX_LINE 2048
#define MAX_ACL_RULE_NUM 100000


enum {
	PROTO_FIELD_IP,
	SRC_FIELD_IP,
	DST_FIELD_IP,
	SRCP_FIELD_IP,
	DSTP_FIELD_IP,
	NUM_FIELDS_IP
};

static struct rte_acl_field_def ip_fields[NUM_FIELDS_IP] = {
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint8_t),
		.field_index = PROTO_FIELD_IP,
		.input_index = RTE_ACL_IPV4VLAN_PROTO,
		.offset = 0,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC_FIELD_IP,
		.input_index = RTE_ACL_IPV4VLAN_SRC,
		.offset = offsetof(struct ipv4_hdr, src_addr)-
		offsetof(struct ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST_FIELD_IP,
		.input_index = RTE_ACL_IPV4VLAN_DST,
		.offset = offsetof(struct ipv4_hdr, dst_addr)-
		offsetof(struct ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = SRCP_FIELD_IP,
		.input_index = RTE_ACL_IPV4VLAN_PORTS,
		.offset = sizeof(struct ipv4_hdr) -
		offsetof(struct ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = DSTP_FIELD_IP,
		.input_index = RTE_ACL_IPV4VLAN_PORTS,
		.offset = sizeof(struct ipv4_hdr) -
		offsetof(struct ipv4_hdr, next_proto_id)+sizeof(uint16_t),
	},
};

#define	IP6_ADDR_LEN 16
#define	IP6_ADDR_U16 (IP6_ADDR_LEN / sizeof(uint16_t))
#define	IP6_ADDR_U32 (IP6_ADDR_LEN / sizeof(uint32_t))

enum {
	PROTO_FIELD_IP6,
	SRC1_FIELD_IP6,
	SRC2_FIELD_IP6,
	SRC3_FIELD_IP6,
	SRC4_FIELD_IP6,
	DST1_FIELD_IP6,
	DST2_FIELD_IP6,
	DST3_FIELD_IP6,
	DST4_FIELD_IP6,
	SRCP_FIELD_IP6,
	DSTP_FIELD_IP6,
	NUM_FIELDS_IP6
};

static struct rte_acl_field_def ip6_fields[NUM_FIELDS_IP6] = {
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint8_t),
		.field_index = PROTO_FIELD_IP6,
		.input_index = PROTO_FIELD_IP6,
		.offset = 0,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC1_FIELD_IP6,
		.input_index = SRC1_FIELD_IP6,
		.offset = offsetof(struct ipv6_hdr, src_addr)-
		offsetof(struct ipv6_hdr, proto),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC2_FIELD_IP6,
		.input_index = SRC2_FIELD_IP6,
		.offset = offsetof(struct ipv6_hdr, src_addr)-
		offsetof(struct ipv6_hdr, proto)+sizeof(uint32_t),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC3_FIELD_IP6,
		.input_index = SRC3_FIELD_IP6,
		.offset = offsetof(struct ipv6_hdr, src_addr)-
		offsetof(struct ipv6_hdr, proto)+2 * sizeof(uint32_t),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC4_FIELD_IP6,
		.input_index = SRC4_FIELD_IP6,
		.offset = offsetof(struct ipv6_hdr, src_addr)-
		offsetof(struct ipv6_hdr, proto)+3 * sizeof(uint32_t),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST1_FIELD_IP6,
		.input_index = DST1_FIELD_IP6,
		.offset = offsetof(struct ipv6_hdr, dst_addr)
		-offsetof(struct ipv6_hdr, proto),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST2_FIELD_IP6,
		.input_index = DST2_FIELD_IP6,
		.offset = offsetof(struct ipv6_hdr, dst_addr)-
		offsetof(struct ipv6_hdr, proto)+sizeof(uint32_t),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST3_FIELD_IP6,
		.input_index = DST3_FIELD_IP6,
		.offset = offsetof(struct ipv6_hdr, dst_addr)-
		offsetof(struct ipv6_hdr, proto)+2 * sizeof(uint32_t),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST4_FIELD_IP6,
		.input_index = DST4_FIELD_IP6,
		.offset = offsetof(struct ipv6_hdr, dst_addr)-
		offsetof(struct ipv6_hdr, proto)+3 * sizeof(uint32_t),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = SRCP_FIELD_IP6,
		.input_index = SRCP_FIELD_IP6,
		.offset = sizeof(struct ipv6_hdr) -
		offsetof(struct ipv6_hdr, proto),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = DSTP_FIELD_IP6,
		.input_index = SRCP_FIELD_IP6,
		.offset = sizeof(struct ipv6_hdr) -
		offsetof(struct ipv6_hdr, proto)+sizeof(uint16_t),
	},
};

enum {
	CB_FLD_SRC_ADDR,
	CB_FLD_DST_ADDR,
	CB_FLD_SRC_PORT_LOW,
	CB_FLD_SRC_PORT_DLM,
	CB_FLD_SRC_PORT_HIGH,
	CB_FLD_DST_PORT_LOW,
	CB_FLD_DST_PORT_DLM,
	CB_FLD_DST_PORT_HIGH,
	CB_FLD_PROTO,
	CB_FLD_USERDATA,
	CB_FLD_NUM,
};

RTE_ACL_RULE_DEF(acl_rule, RTE_DIM(ip_fields));
RTE_ACL_RULE_DEF(acl6_rule, RTE_DIM(ip6_fields));

#define GET_CB_FIELD(in, fd, base, lim, dlm)	do {		\
	unsigned long val;					\
	char *end;						\
	errno = 0;						\
	val = strtoul((in), &end, (base));			\
	if (errno != 0 || end[0] != (dlm) || val > (lim))	\
		return -EINVAL;					\
	(fd) = (typeof(fd))val;					\
	(in) = end + 1;						\
} while (0)

#define uint32_t_to_char(ip, a, b, c, d) do {\
	*a = (unsigned char)(ip >> 24 & 0xff);\
	*b = (unsigned char)(ip >> 16 & 0xff);\
	*c = (unsigned char)(ip >> 8 & 0xff);\
	*d = (unsigned char)(ip & 0xff);\
} while (0)

static void
fmt_port_range(uint8_t proto, uint16_t srcp, uint16_t srcmask,
    uint16_t dstp, uint16_t dstmask, char *buffer, size_t siz)
{
	buffer[0] = '\0';

	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_SCTP:
		snprintf(buffer, siz, "dports %hu:%hu sports %hu:%hu ",
		    srcp, srcmask, dstp, dstmask);
		break;

	default:
		snprintf(buffer, siz, "payload [0x%04x/0x%04x|0x%04x/0x%04x] ",
		    srcp, srcmask, dstp, dstmask);
		break;
	}
}

static void
fmt_actions(uint32_t actions, char *buffer, size_t siz)
{
	buffer[0] = '\0';
	if (actions & ACL_ACTION_ACCEPT) {
		strlcat(buffer, "accept ", siz);
	}
	if (actions & ACL_ACTION_DROP) {
		strlcat(buffer, "drop", siz);
	}
	if (actions & ACL_ACTION_DNAT) {
		strlcat(buffer, "dnat ", siz);
	}
	if (actions & ACL_ACTION_SNAT) {
		strlcat(buffer, "snat ", siz);
	}
	if (actions & ACL_ACTION_MONIT) {
		strlcat(buffer, "monitor ", siz);
	}
	if (actions & ACL_ACTION_COUNT) {
		strlcat(buffer, "counter ", siz);
	}
}

static void
fmt_one_ip_rule(struct acl_rule *rule, int extra, char *buffer, size_t siz)
{
	char tmp[MAX_ACL_STR_SIZE], proto[MAX_ACL_STR_SIZE];
	struct protoent ent, *entp;
	int res;
	uint8_t a, b, c, d;

	buffer[0] = '\0';

	if (rule->data.userdata & ACL_ACTION_LOCAL) {
		strlcat(buffer, "input ", siz);
	} else {
		strlcat(buffer, "forward ", siz);
	}

	uint32_t_to_char(rule->field[SRC_FIELD_IP].value.u32,
	    &a, &b, &c, &d);
	snprintf(tmp, sizeof(tmp), "ip saddr %hhu.%hhu.%hhu.%hhu/%u ",
	    a, b, c, d, rule->field[SRC_FIELD_IP].mask_range.u32);
	strlcat(buffer, tmp, siz);

	uint32_t_to_char(rule->field[DST_FIELD_IP].value.u32,
	    &a, &b, &c, &d);
	snprintf(tmp, sizeof(tmp), "ip daddr %hhu.%hhu.%hhu.%hhu/%u ",
	    a, b, c, d, rule->field[DST_FIELD_IP].mask_range.u32);
	strlcat(buffer, tmp, siz);

	res = getprotobynumber_r(rule->field[PROTO_FIELD_IP].value.u8,
	    &ent, proto, sizeof(proto), &entp);
	if (res != 0) {
		strlcpy(proto, "unknown", sizeof(proto));
	}
	snprintf(tmp, sizeof(tmp), "%s ", proto);
	strlcat(buffer, tmp, siz);

	fmt_port_range(
	    rule->field[PROTO_FIELD_IP].value.u8,
	    rule->field[SRCP_FIELD_IP].value.u16,
	    rule->field[SRCP_FIELD_IP].mask_range.u16,
	    rule->field[DSTP_FIELD_IP].value.u16,
	    rule->field[DSTP_FIELD_IP].mask_range.u16,
	    tmp,
	    sizeof(tmp));
	strlcat(buffer, tmp, siz);

	fmt_actions(rule->data.userdata, tmp, sizeof(tmp));
	strlcat(buffer, tmp, siz);

	if (extra) {
		snprintf(tmp, sizeof(tmp),
		    "category 0x%02x prio 0x%02x userdata 0x%02x",
		    rule->data.category_mask,
		    rule->data.priority,
		    rule->data.userdata);
		strlcat(buffer, tmp, siz);
	}
}

static inline void
fmt_one_ip6_rule(struct acl6_rule *rule, int extra, char *buffer, size_t siz)
{
	char tmp[MAX_ACL_STR_SIZE];
	unsigned char a, b, c, d;

	buffer[0] = '\0';
	uint32_t_to_char(rule->field[SRC1_FIELD_IP6].value.u32,
	    &a, &b, &c, &d);
	snprintf(tmp, sizeof(tmp), "%.2x%.2x:%.2x%.2x", a, b, c, d);
	strlcat(buffer, tmp, siz);

	uint32_t_to_char(rule->field[SRC2_FIELD_IP6].value.u32,
	    &a, &b, &c, &d);
	snprintf(tmp, sizeof(tmp), ":%.2x%.2x:%.2x%.2x", a, b, c, d);
	strlcat(buffer, tmp, siz);

	uint32_t_to_char(rule->field[SRC3_FIELD_IP6].value.u32,
	    &a, &b, &c, &d);
	snprintf(tmp, sizeof(tmp), ":%.2x%.2x:%.2x%.2x", a, b, c, d);
	strlcat(buffer, tmp, siz);

	uint32_t_to_char(rule->field[SRC4_FIELD_IP6].value.u32,
	    &a, &b, &c, &d);
	snprintf(tmp, sizeof(tmp), ":%.2x%.2x:%.2x%.2x/%u ", a, b, c, d,
	    rule->field[SRC1_FIELD_IP6].mask_range.u32 +
	    rule->field[SRC2_FIELD_IP6].mask_range.u32 +
	    rule->field[SRC3_FIELD_IP6].mask_range.u32 +
	    rule->field[SRC4_FIELD_IP6].mask_range.u32);
	strlcat(buffer, tmp, siz);

	uint32_t_to_char(rule->field[DST1_FIELD_IP6].value.u32,
	    &a, &b, &c, &d);
	snprintf(tmp, sizeof(tmp), "%.2x%.2x:%.2x%.2x", a, b, c, d);
	strlcat(buffer, tmp, siz);

	uint32_t_to_char(rule->field[DST2_FIELD_IP6].value.u32,
	    &a, &b, &c, &d);
	snprintf(tmp, sizeof(tmp), ":%.2x%.2x:%.2x%.2x", a, b, c, d);
	strlcat(buffer, tmp, siz);

	uint32_t_to_char(rule->field[DST3_FIELD_IP6].value.u32,
	    &a, &b, &c, &d);
	snprintf(tmp, sizeof(tmp), ":%.2x%.2x:%.2x%.2x", a, b, c, d);
	strlcat(buffer, tmp, siz);

	uint32_t_to_char(rule->field[DST4_FIELD_IP6].value.u32,
	    &a, &b, &c, &d);
	snprintf(tmp, sizeof(tmp), ":%.2x%.2x:%.2x%.2x/%u ", a, b, c, d,
	    rule->field[SRC1_FIELD_IP6].mask_range.u32 +
	    rule->field[SRC2_FIELD_IP6].mask_range.u32 +
	    rule->field[SRC3_FIELD_IP6].mask_range.u32 +
	    rule->field[SRC4_FIELD_IP6].mask_range.u32);
	strlcat(buffer, tmp, siz);

	snprintf(tmp, sizeof(tmp), "%hu:%hu %hu:%hu 0x%hhx/0x%hhx ",
	    rule->field[SRCP_FIELD_IP6].value.u16,
	    rule->field[SRCP_FIELD_IP6].mask_range.u16,
	    rule->field[DSTP_FIELD_IP6].value.u16,
	    rule->field[DSTP_FIELD_IP6].mask_range.u16,
	    rule->field[PROTO_FIELD_IP6].value.u8,
	    rule->field[PROTO_FIELD_IP6].mask_range.u8);
	strlcat(buffer, tmp, siz);

	if (extra) {
		snprintf(tmp, sizeof(tmp), "0x%x-0x%x-0x%x ",
		    rule->data.category_mask,
		    rule->data.priority,
		    rule->data.userdata);
		strlcat(buffer, tmp, siz);
	}
}

static void
dump_ip_rules(struct acl_rule *rule, int num, int extra)
{
	char buffer[MAX_ACL_STR_SIZE];
	int i;

	for (i = 0; i < num; i++, rule++) {
		buffer[0] = '\0';
		fmt_one_ip_rule(rule, extra, buffer, sizeof(buffer));
		RTE_LOG(DEBUG, ACL, "\t%d: %s\n", i + 1, buffer);
	}
}

static void
dump_ip6_rules(struct acl6_rule *rule, int num, int extra)
{
	char buffer[MAX_ACL_STR_SIZE];
	int i;

	for (i = 0; i < num; i++, rule++) {
		buffer[0] = '\0';
		fmt_one_ip6_rule(rule, extra, buffer, sizeof(buffer));
		RTE_LOG(DEBUG, ACL, "\t%d: %s\n", i + 1, buffer);
	}
}


/*
 * Parse ClassBench rules file.
 * Expected format:
 * '@'<src_ip_addr>'/'<masklen> <space> \
 * <dst_ip_addr>'/'<masklen> <space> \
 * <src_port_low> <space> ":" <src_port_high> <space> \
 * <dst_port_low> <space> ":" <dst_port_high> <space> \
 * <proto>'/'<mask>
 */
static int
parse_ip_net(const char *in, uint32_t *addr, uint32_t *mask_len)
{
	uint8_t a, b, c, d, m;

	GET_CB_FIELD(in, a, 0, UINT8_MAX, '.');
	GET_CB_FIELD(in, b, 0, UINT8_MAX, '.');
	GET_CB_FIELD(in, c, 0, UINT8_MAX, '.');
	GET_CB_FIELD(in, d, 0, UINT8_MAX, '/');
	GET_CB_FIELD(in, m, 0, sizeof(uint32_t) * CHAR_BIT, 0);

	addr[0] = IPv4(a, b, c, d);
	mask_len[0] = m;

	return 0;
}

/*
 * Parses IPv6 address, expects the following format:
 * xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx (where x is an hexadecimal digit).
 */
static int
parse_ip6_addr(const char *in, const char **end, uint32_t v[IP6_ADDR_U32],
    char dlm)
{
	uint32_t addr[IP6_ADDR_U16];

	GET_CB_FIELD(in, addr[0], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[1], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[2], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[3], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[4], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[5], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[6], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[7], 16, UINT16_MAX, dlm);

	*end = in;

	v[0] = (addr[0] << 16) + addr[1];
	v[1] = (addr[2] << 16) + addr[3];
	v[2] = (addr[4] << 16) + addr[5];
	v[3] = (addr[6] << 16) + addr[7];

	return 0;
}

static int
parse_ip6_net(const char *in, struct rte_acl_field field[4])
{
	const char *mp;
	uint32_t nbu32;
	int32_t rc;
	uint32_t i, m, v[4];

	nbu32 = sizeof(uint32_t) * CHAR_BIT;

	/* Get address */
	rc = parse_ip6_addr(in, &mp, v, '/');
	if (rc != 0) {
		return rc;
	}
	/* Get mask */
	GET_CB_FIELD(mp, m, 0, CHAR_BIT * sizeof(v), 0);

	/* Put it all together. */
	for (i = 0; i < RTE_DIM(v); i++) {
		if (m >= (i + 1) * nbu32) {
			field[i].mask_range.u32 = nbu32;
		} else {
			field[i].mask_range.u32 = m > (i * nbu32) ?
			    m - (i * 32) : 0;
		}

		field[i].value.u32 = v[i];
	}

	return 0;
}

static int
line_ignored(const char *buff)
{
	int i = 0;

	/* Comment line */
	if (buff[0] == COMMENT_LEAD_CHAR) {
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
parse_cb_ipvlan_rule(char *str, struct rte_acl_rule *v, uint32_t cnt)
{
	int i, rc;
	char *s, *sp, *in[CB_FLD_NUM];
	static const char *dlm = " \t\n";

	s = str;
	for (i = 0; i < CB_FLD_NUM; i++, s = NULL) {
		in[i] = strtok_r(s, dlm, &sp);
		if (in[i] == NULL) {
			return -EINVAL;
		}
	}

	rc = parse_ip_net(in[CB_FLD_SRC_ADDR],
	    &v->field[SRC_FIELD_IP].value.u32,
	    &v->field[SRC_FIELD_IP].mask_range.u32);
	if (rc != 0) {
		RTE_LOG(DEBUG, ACL, "Failed to read source address/mask: %s\n",
		    in[CB_FLD_SRC_ADDR]);
		return rc;
	}
	rc = parse_ip_net(in[CB_FLD_DST_ADDR],
	    &v->field[DST_FIELD_IP].value.u32,
	    &v->field[DST_FIELD_IP].mask_range.u32);
	if (rc != 0) {
		RTE_LOG(DEBUG, ACL, "Failed to read destination address/mask: %s\n",
		    in[CB_FLD_DST_ADDR]);
		return rc;
	}
	GET_CB_FIELD(in[CB_FLD_SRC_PORT_LOW],
	    v->field[SRCP_FIELD_IP].value.u16,
	    0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_SRC_PORT_HIGH],
	    v->field[SRCP_FIELD_IP].mask_range.u16,
	    0, UINT16_MAX, 0);

	if (strncmp(in[CB_FLD_SRC_PORT_DLM], ":", sizeof(":") - 1) != 0) {
		return -EINVAL;
	}
	GET_CB_FIELD(in[CB_FLD_DST_PORT_LOW], v->field[DSTP_FIELD_IP].value.u16,
	    0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_DST_PORT_HIGH],
	    v->field[DSTP_FIELD_IP].mask_range.u16,
	    0, UINT16_MAX, 0);

	if (strncmp(in[CB_FLD_DST_PORT_DLM], ":", sizeof(":")) != 0) {
		return -EINVAL;
	}
	if (v->field[SRCP_FIELD_IP].mask_range.u16 <
	    v->field[SRCP_FIELD_IP].value.u16 ||
	    v->field[DSTP_FIELD_IP].mask_range.u16 <
	    v->field[DSTP_FIELD_IP].value.u16) {
		return -EINVAL;
	}
	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IP].value.u8,
	    0, UINT8_MAX, '/');
	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IP].mask_range.u8,
	    0, UINT8_MAX, 0);

	GET_CB_FIELD(in[CB_FLD_USERDATA], v->data.userdata, 0, UINT32_MAX, 0);

	v->data.priority = RTE_ACL_MAX_PRIORITY - cnt;
	v->data.category_mask = -1;

	return 0;
}

static int
parse_cb_ip6_rule(char *str, struct rte_acl_rule *v, uint32_t cnt)
{
	char *in[CB_FLD_NUM];
	char *s, *sp;
	static const char *dlm = " \t\n";
	int i, rc;

	s = str;
	for (i = 0; i != CB_FLD_NUM; i++, s = NULL) {
		in[i] = strtok_r(s, dlm, &sp);
		if (in[i] == NULL) {
			return -EINVAL;
		}
	}

	rc = parse_ip6_net(in[CB_FLD_SRC_ADDR], v->field + SRC1_FIELD_IP6);
	if (rc != 0) {
		RTE_LOG(DEBUG, ACL, "failed to read source address/mask: %s\n",
		    in[CB_FLD_SRC_ADDR]);
		return rc;
	}
	rc = parse_ip6_net(in[CB_FLD_DST_ADDR], v->field + DST1_FIELD_IP6);
	if (rc != 0) {
		RTE_LOG(DEBUG, ACL, "failed to read destination address/mask: %s\n",
		    in[CB_FLD_DST_ADDR]);
		return rc;
	}
	/* Source port */
	GET_CB_FIELD(in[CB_FLD_SRC_PORT_LOW],
	    v->field[SRCP_FIELD_IP6].value.u16,
	    0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_SRC_PORT_HIGH],
	    v->field[SRCP_FIELD_IP6].mask_range.u16,
	    0, UINT16_MAX, 0);

	if (*in[CB_FLD_SRC_PORT_DLM] != ':') {
		return -EINVAL;
	}
	/* Destination port */
	GET_CB_FIELD(in[CB_FLD_DST_PORT_LOW],
	    v->field[DSTP_FIELD_IP6].value.u16,
	    0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_DST_PORT_HIGH],
	    v->field[DSTP_FIELD_IP6].mask_range.u16,
	    0, UINT16_MAX, 0);

	if (*in[CB_FLD_DST_PORT_DLM] != ':') {
		return -EINVAL;
	}
	if (v->field[SRCP_FIELD_IP6].mask_range.u16 <
	    v->field[SRCP_FIELD_IP6].value.u16 ||
	    v->field[DSTP_FIELD_IP6].mask_range.u16 <
	    v->field[DSTP_FIELD_IP6].value.u16) {
		return -EINVAL;
	}
	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IP6].value.u8,
	    0, UINT8_MAX, '/');
	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IP6].mask_range.u8,
	    0, UINT8_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_USERDATA], v->data.userdata, 0, UINT32_MAX, 0);

	v->data.priority = RTE_ACL_MAX_PRIORITY - cnt;
	v->data.category_mask = -1;

	return 0;
}

static int
parse_acls(char *path, struct rte_acl_rule **acl_basep,
    uint32_t *n_aclp, uint32_t acl_size,
    int (*parser) (char *, struct rte_acl_rule *, uint32_t cnt))
{
	char buff[MAX_LINE];
	struct rte_acl_rule *next;
	FILE *fp;
	uint8_t *acl_rules;
	uint32_t i, n_acl, acl_cnt;

	if ((fp = fopen(path, "rb")) == NULL) {
		return -1;
	}
	n_acl = 0;
	while (fgets(buff, MAX_LINE, fp) != NULL) {
		if (!line_ignored(buff)) {
			n_acl++;
		}
	}
	if (n_acl == 0) {
		RTE_LOG(ERR, ACL, "Could not find any ACL rule!\n");
		return -1;
	}
	if ((acl_rules = calloc(n_acl, acl_size)) == NULL) {
		RTE_LOG(ERR, ACL, "Could not allocate memory for ACLs.\n");
		return -1;
	}
	fseek(fp, 0, SEEK_SET);

	i = 0;
	acl_cnt = 0;
	while (fgets(buff, MAX_LINE, fp) != NULL) {
		i++;
		if (line_ignored(buff)) {
			continue;
		}
		next = (struct rte_acl_rule *)(acl_rules + acl_cnt * acl_size);
		if (parser(buff, next, acl_cnt) != 0) {
			RTE_LOG(ERR, ACL,
			    "%s line %u: could not parse rule.\n", path, i);
			return -1;
		}
		acl_cnt++;
	}

	fclose(fp);
	*acl_basep = (struct rte_acl_rule *)acl_rules;
	*n_aclp = n_acl;

	return 0;
}

static struct rte_acl_ctx *
setup_acl(struct zone_cfg *zone, struct rte_acl_rule *base, uint32_t n_acls,
    uint32_t sockid, struct rte_acl_field_def *defs, uint32_t defs_dim,
    uint32_t defs_size)
{
	char name[MAX_FILE_PATH];
	struct rte_acl_param acl_param;
	struct rte_acl_config acl_config;
	struct rte_acl_ctx *acl_ctx;

	snprintf(name, sizeof(name), "%s_%u_%u", zone->name, zone->version,
	    sockid);

	RTE_LOG(DEBUG, USER1, "Building ACL trie: %s\n", name);

	acl_param.name = name;
	acl_param.socket_id = sockid;
	acl_param.rule_size = RTE_ACL_RULE_SZ(defs_dim);
	acl_param.max_rule_num = MAX_ACL_RULE_NUM;

	if ((acl_ctx = rte_acl_create(&acl_param)) == NULL) {
		return NULL;
	}
	if (rte_acl_add_rules(acl_ctx, base, n_acls)) {
		return NULL;
	}
	memset(&acl_config, 0, sizeof(acl_config));

	acl_config.num_categories = MAX_ACL_CATEGORIES;
	acl_config.num_fields = defs_dim;
	memcpy(&acl_config.defs, defs, defs_size);

	if (rte_acl_build(acl_ctx, &acl_config) != 0) {
		return NULL;
	}
	return acl_ctx;
}

static void
set_cnt_id(uint32_t *udata, uint8_t id)
{
	*udata |= (id & 0x0f) << COUNT_SHIFT;
}

static int
init_ip_count(struct acl_rule *rule, uint32_t n_acl, struct zone_cfg *zone)
{
	uint32_t i;
	uint8_t n_cnt, limit;

	n_cnt = 0;
	for (i = 0; i < n_acl; i++) {
		if (rule->data.userdata & ACL_ACTION_COUNT) {
			n_cnt++;
		}
	}
	limit = MAX_ACL_COUNTERS - zone->n_rules;
	if (n_cnt > limit) {
		RTE_LOG(WARNING, ACL, "Limited IPv4 counters to %u (was %u).\n",
		    limit, n_cnt);
	}
	n_cnt = zone->n_rules;
	for (i = 0; i < n_acl; i++, rule++) {
		if ((rule->data.userdata & ACL_ACTION_COUNT) &&
		    n_cnt < MAX_ACL_COUNTERS) {
			fmt_one_ip_rule(rule, 0, zone->rules[n_cnt],
			    MAX_ACL_STR_SIZE);
			set_cnt_id(&rule->data.userdata, n_cnt);
			n_cnt++;
		}
	}
	zone->n_rules = n_cnt;

	return 0;
}

static int
init_ip6_count(struct acl6_rule *rule, uint32_t n_acl, struct zone_cfg *zone)
{
	uint32_t i;
	uint8_t n_cnt, limit;

	n_cnt = 0;
	for (i = 0; i < n_acl; i++) {
		if (rule->data.userdata & ACL_ACTION_COUNT) {
			n_cnt++;
		}
	}
	limit = MAX_ACL_COUNTERS - zone->n_rules;
	if (n_cnt > limit) {
		RTE_LOG(WARNING, ACL, "Limited IPv6 counters to %u (was %u).\n",
		    limit, n_cnt);
	}
	n_cnt = zone->n_rules;;
	for (i = 0; i < n_acl; i++, rule++) {
		if ((rule->data.userdata & ACL_ACTION_COUNT) &&
		    n_cnt < MAX_ACL_COUNTERS) {
			fmt_one_ip6_rule(rule, 0, zone->rules[n_cnt],
			    MAX_ACL_STR_SIZE);
			set_cnt_id(&rule->data.userdata, n_cnt);
			n_cnt++;
		}
	}
	zone->n_rules = n_cnt;

	return 0;
}

static int
parse_ip_acls(struct zone_cfg *zone)
{
	char path[MAX_FILE_PATH];
	struct rte_acl_rule *acl_basep;
	struct rte_acl_ctx *acl_ctx;
	uint32_t sockid, n_acl;
	int ret;

	acl_basep = NULL;
	snprintf(path, sizeof(path), "%s/%s.acl.ip.rules",
	    RULE_PATH, zone->name);
	if ((ret = parse_acls(path, &acl_basep, &n_acl, sizeof(struct acl_rule),
	    parse_cb_ipvlan_rule)) != 0) {
		RTE_LOG(DEBUG, ACL, "Could not open ACL configuration file for "
		    "zone %s (%s): %s.\n", zone->name, path, strerror(errno));
		goto done;
	}
	RTE_LOG(DEBUG, ACL, "Loaded %u IPv4 ACL entries:\n", n_acl);

	init_ip_count((struct acl_rule *)acl_basep, n_acl, zone);
	dump_ip_rules((struct acl_rule *)acl_basep, n_acl, 1);

	for (sockid = 0; sockid < RTE_DIM(zone->ip_acl); sockid++) {
		if ((acl_ctx = setup_acl(zone, acl_basep, n_acl, sockid,
		    ip_fields, RTE_DIM(ip_fields), sizeof(ip_fields)))
		    == NULL) {
			ret = -1;
			goto done;
		}
		zone->ip_acl[sockid] = acl_ctx;
	}

	ret = 0;

done:
	free(acl_basep);
	return ret;
}

static int
parse_ip6_acls(struct zone_cfg *zone)
{
	char path[MAX_FILE_PATH];
	struct rte_acl_rule *acl_basep;
	struct rte_acl_ctx *acl_ctx;
	uint32_t n_acl, sockid;
	int ret;

	acl_basep = NULL;
	snprintf(path, sizeof(path), "%s/%s.acl.ip6.rules",
	    RULE_PATH, zone->name);
	if ((ret = parse_acls(path, &acl_basep, &n_acl, sizeof(struct acl6_rule),
	    parse_cb_ip6_rule)) != 0) {
		RTE_LOG(ERR, ACL, "Could not open ACL configuration file for "
		    "zone %s (%s): %s.\n", zone->name, path, strerror(errno));
		goto done;
	}
	RTE_LOG(DEBUG, ACL, "Loaded %u IPv6 ACL entries:\n", n_acl);
	init_ip6_count((struct acl6_rule *)acl_basep, n_acl, zone);
	dump_ip6_rules((struct acl6_rule *)acl_basep, n_acl, 1);

	for (sockid = 0; sockid < RTE_DIM(zone->ip6_acl); sockid++) {
		if ((acl_ctx = setup_acl(zone, acl_basep, n_acl, sockid,
		    ip6_fields, RTE_DIM(ip6_fields), sizeof(ip6_fields)))
		    == NULL) {
			ret = -1;
			goto done;
		}
		zone->ip6_acl[sockid] = acl_ctx;
	}

	ret = 0;

done:
	free(acl_basep);
	return ret;
}

void
acl_free_rules(struct zone_cfg *zone)
{
	uint32_t i;

	for (i = 0; i < RTE_DIM(zone->ip_acl); i++) {
		rte_acl_free(zone->ip_acl[i]);
		rte_acl_free(zone->ip6_acl[i]);
	}
}

int
acl_parse_rules(struct zone_cfg *zone)
{
	int ret;

	if ((ret = parse_ip_acls(zone)) != 0) {
		return ret;
	}
	if (0) {
		parse_ip6_acls(zone);
	}
	return 0;
}
