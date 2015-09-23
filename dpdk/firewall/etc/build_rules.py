#!/usr/bin/env python2
#
#    BSD LICENSE
#
#    Copyright(c) 2015 PT Comunicacoes. All rights reserved.
#
#    Redistribution and use in source and binary forms, with or without
#    modification, are permitted provided that the following conditions
#    are met:
#
#      * Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#      * Redistributions in binary form must reproduce the above copyright
#        notice, this list of conditions and the following disclaimer in
#        the documentation and/or other materials provided with the
#        distribution.
#      * Neither the name of Intel Corporation nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
#    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#    A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#    OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#    LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#    DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#    THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import sys
import os
import socket
import re
import pylibconfig2 as cfg

from functools import partial
from cherrypy import config

try:
    import ipaddress
except ImportError:
    print('Please install the "ipaddress" package before proceeding.')
    sys.exit(1)

# These flags must be kept in sync with acl.h
# Please note that the last 4 bits are reserved for
# rule statistics purposes.
ACL_ACTION_ACCEPT   = 1 << 0
ACL_ACTION_DROP     = 1 << 1
ACL_ACTION_LOCAL    = 1 << 2
ACL_ACTION_SNAT     = 1 << 3
ACL_ACTION_DNAT     = 1 << 4
ACL_ACTION_COUNT    = 1 << 5
ACL_ACTION_MONIT    = 1 << 6

ICMP_ECHOREPLY      = 0
ICMP_DEST_UNREACH   = 3
ICMP_SOURCE_QUENCH  = 4
ICMP_REDIRECT       = 5
ICMP_ECHO           = 8
ICMP_TIME_EXCEEDED  = 11
ICMP_PARAMETERPROB  = 12
ICMP_TIMESTAMP      = 13
ICMP_TIMESTAMPREPLY = 14
ICMP_INFO_REQUEST   = 15
ICMP_INFO_REPLY     = 16
ICMP_ADDRESS        = 17
ICMP_ADDRESSREPLY   = 18

PORT_RANGE_WILDCARD = '0:65535'
IP_NET_WILDCARD = unicode('0.0.0.0/0')
IP6_NET_WILDCARD = unicode('::0/0')
PORT_DELIM = ':'

ZONE_PATH = 'zones'
RULE_PATH = '{}/rules'.format(ZONE_PATH)

class Zone(object):
    def __init__(self, name, rules):
        self.name = name
        self.rules = rules


class IPHeader(object):

    def __init__(self, family, proto, snet, dnet):
        self.family = family
        snet = self._net_wildcard(snet)
        dnet = self._net_wildcard(dnet)

        self.proto = proto
        self.snet = ipaddress.ip_network(unicode(snet))
        self.dnet = ipaddress.ip_network(unicode(dnet))

    def _net_wildcard(self, net):
        if self.family == 'ip':
            net = net if net else IP_NET_WILDCARD
        else:
            net = net if net else IP6_NET_WILDCARD
        return net

    def version(self):
        return self.snet.version

    def snet_contains(self, addr):
        return addr.overlaps(self.snet)

    def dnet_contains(self, addr):
        return addr.overlaps(self.dnet)


class TransportHeader(object):
    def __init__(self, sport_range, dport_range):
        sport_range = self._port_wildcard(sport_range)
        dport_range = self._port_wildcard(dport_range)

        self.sport_lo, self.sport_hi = sport_range.split(PORT_DELIM)
        self.dport_lo, self.dport_hi = dport_range.split(PORT_DELIM)

    def _port_wildcard(self, range):
        return range if range else PORT_RANGE_WILDCARD

    def sport_lo_orig(self):
        return self.sport_lo
    
    def sport_hi_orig(self):
        return self.sport_hi

    def dport_lo_orig(self):
        return self.dport_lo
    
    def dport_hi_orig(self):
        return self.dport_hi
    
    def sport_lo_reply(self):
        return self.dport_lo

    def sport_hi_reply(self):
        return self.dport_hi

    def dport_lo_reply(self):
        return self.sport_lo

    def dport_hi_reply(self):
        return self.sport_hi


class TCPHeader(TransportHeader):
    def __init__(self, *args):
        super(TCPHeader, self).__init__('tcp', *args)


class UDPHeader(TransportHeader):
    def __init__(self, *args):
        super(UDPHeader, self).__init__('udp', *args)

# TODO: proper ICMP echo-reply pairing
class ICMPHeader(TransportHeader):
    '''
    In the current ACL model, the first two bytes of the layer 4
    header are the source port.

    In an ICMP packet, the first two bytes are the type and code, respectively.
    To make the ACL engine match ICMP packets with specific codes, fake a
    "source port" where the appropriate code + type bits are set in the first
    two bytes.
    '''

    _type_to_int = {
        'echo-reply': ICMP_ECHOREPLY,
        'destination-unreachable': ICMP_DEST_UNREACH,
        'source-quench': ICMP_SOURCE_QUENCH,
        'redirect': ICMP_REDIRECT,
        'echo-request': ICMP_ECHO,
        'time-exceeded': ICMP_TIME_EXCEEDED,
        'parameter-problem': ICMP_PARAMETERPROB,
        'timestamp-request': ICMP_TIMESTAMP,
        'timestamp-reply': ICMP_TIMESTAMPREPLY,
        'info-request': ICMP_INFO_REQUEST,
        'info-reply': ICMP_INFO_REPLY,
        'address-mask-request': ICMP_ADDRESS,
        'address-mask-reply': ICMP_ADDRESSREPLY
    }
    
    _type_reply = {
        'echo-request': 'echo-reply',
        'info-request': 'info-reply',
        'timestamp-request': 'timestamp-reply',
        'address-mask-request': 'address-mask-reply'
    }

    def __init__(self, _type, code):
        self.type_str = _type
        self.type = self._type_to_int.get(_type, -1)
        self.code = int(code) if code != 'all' else -1

        sport_range = self._type_to_range(self.type, self.code)

        super(ICMPHeader, self).__init__(sport_range, PORT_RANGE_WILDCARD)

    def _type_to_range(self, _type, code):
        # Any icmp
        if _type == -1:
            sport_range = PORT_RANGE_WILDCARD

        # Specific type, any code
        elif code == -1:
            begin_port = (self.type & 0xff) << 8
            end_port = begin_port | 0xff
            sport_range = '{}:{}'.format(begin_port, end_port)

        # Specific type and code
        else:
            begin_port = (self.type & 0xff) << 8 | (self.code & 0xff)
            sport_range = '{}:{}'.format(begin_port, begin_port)

        return sport_range

    def sport_lo_orig(self):
        return self.sport_lo
    
    def sport_hi_orig(self):
        return self.sport_hi

    def dport_lo_orig(self):
        return self.dport_lo
    
    def dport_hi_orig(self):
        return self.dport_hi
    
    def sport_lo_reply(self):
        return '0'

    def sport_hi_reply(self):
        return '65535'

    def dport_lo_reply(self):
        return '0'

    def dport_hi_reply(self):
        return '65535'


class ACLRule(object):
    def __init__(self, iphdr, ulhdr, actions):
        self.iphdr = iphdr
        self.ulhdr = ulhdr
        self.ip_extra = {}
        
        self.action = 0
        for action in actions:
            self.action |= self.action_to_code(action)

        # Do not monitor local traffic. The kernel will see it regardless.
        local_monit = ACL_ACTION_LOCAL|ACL_ACTION_MONIT
        if self.action & local_monit == local_monit:
            self.action &= ~ACL_ACTION_MONIT

    @classmethod
    def action_to_code(cls, action):
        codes = {
            'accept': ACL_ACTION_ACCEPT,
            'drop': ACL_ACTION_DROP,
            'local': ACL_ACTION_LOCAL,
            'counter': ACL_ACTION_COUNT,
            'monitor': ACL_ACTION_MONIT
        }
        return codes.get(action)

    def set_local(self):
        self.action |= ACL_ACTION_LOCAL

    def is_local(self):
        return (self.action & ACL_ACTION_LOCAL) == ACL_ACTION_LOCAL

    def snet_contains(self, addr):
        return ipaddress.ip_network(addr).overlaps(self.iphdr.snet)

    def dnet_contains(self, addr):
        return ipaddress.ip_network(addr).overlaps(self.iphdr.dnet)

    def type(self):
        return '{}_acl'.format(self.iphdr.family)


class DNATRule(object):
    def __init__(self, orig_ip, trans_ip):
        self.orig_ip = orig_ip
        self.trans_ip = trans_ip

    def type(self):
        return 'ip{}_nat'.format('' if self.orig_ip.version == 4 else '6')


class DNATRuleFormatter(object):
    def __init__(self, dnat):
        self.dnat = dnat

    def orig(self):
        output = []
        output.append(self.dnat.orig_ip)
        output.append(self.dnat.trans_ip)        
        return '\t'.join(str(o) for o in output) + '\n'

    def reply(self):
        output = []
        output.append(self.dnat.trans_ip)
        output.append(self.dnat.orig_ip)        
        return '\t'.join(str(o) for o in output) + '\n'


class ACLRuleFormatter(object):

    def __init__(self, acl):
        self.acl = acl

    def _get_proto_mask(self, proto_str):
        if proto_str == 'any':
            return '0x00/0x00'

        proto = socket.getprotobyname(proto_str)
        proto = '0x{:02x}/0xff'.format(proto)
        return proto

    def _format_ports(self, lo, hi):
        ports = [lo, PORT_DELIM, hi]
        return ' '.join(ports)

    def _orig(self):
        rule = []

        rule.append(self.acl.iphdr.snet.exploded)
        rule.append(self.acl.iphdr.dnet.exploded)

        srange = self._format_ports(self.acl.ulhdr.sport_lo_orig(),
                                    self.acl.ulhdr.sport_hi_orig())
        rule.append(srange)

        drange = self._format_ports(self.acl.ulhdr.dport_lo_orig(),
                                    self.acl.ulhdr.dport_hi_orig())
        rule.append(drange)

        protomask = self._get_proto_mask(self.acl.iphdr.proto)
        rule.append(protomask)
        rule.append(str(self.acl.action))

        return '\t'.join(rule)

    def _reply(self):
        rule = []

        if self.acl.action & ACL_ACTION_DNAT:
            rule.append(self.acl.dnat.trans_ip.exploded)
        else:
            rule.append(self.acl.iphdr.dnet.exploded)

        rule.append(self.acl.iphdr.snet.exploded)

        srange = self._format_ports(self.acl.ulhdr.sport_lo_reply(),
                                    self.acl.ulhdr.sport_hi_reply())
        rule.append(srange)
        drange = self._format_ports(self.acl.ulhdr.dport_lo_reply(),
                                    self.acl.ulhdr.dport_hi_reply())
        rule.append(drange)

        # Swap DNAT with SNAT
        if self.acl.action & ACL_ACTION_DNAT:
            self.acl.action &= ~ACL_ACTION_DNAT
            self.acl.action |= ACL_ACTION_SNAT

        protomask = self._get_proto_mask(self.acl.iphdr.proto)
        rule.append(protomask)
        rule.append(str(self.acl.action))

        return '\t'.join(rule)

    def orig(self):
        output = []
        output.append(self._orig())

        if self.acl.is_local():
            output.append(self._reply())

        return '\n'.join(output)

    def reply(self):
        output = []
        output.append(self._reply())

        if self.acl.is_local():
            output.append(self._orig())

        return '\n'.join(output)


# TODO: make this a context manager (to close files automatically)
class RuleSerializer(object):
        
    def __init__(self, zone):
        self.zone = zone

        name = self.zone.name
        ip_acl_p = '{}/{}.acl.ip.rules'.format(RULE_PATH, name)
        ip_acl_rev_p = '{}/{}_rev.acl.ip.rules'.format(RULE_PATH, name)

        ip6_acl_p = '{}/{}.acl.ip6.rules'.format(RULE_PATH, name)
        ip6_acl_rev_p = '{}/{}_rev.acl.ip6.rules'.format(RULE_PATH, name)

        ip_nat_p = '{}/{}.nat.ip.rules'.format(RULE_PATH, name)
        ip_nat_rev_p = '{}/{}_rev.nat.ip.rules'.format(RULE_PATH, name)

        try:
            os.mkdir(RULE_PATH)
        except OSError as ose:
            import errno
            if ose.errno != errno.EEXIST:
                print("Could not create rules directory: {}".format(ose))
                sys.exit(1)

        ip_acl = open(ip_acl_p, 'wb')
        ip_acl_rev = open(ip_acl_rev_p, 'wb')
        ip6_acl = open(ip6_acl_p, 'wb')
        ip6_acl_rev = open(ip6_acl_rev_p, 'wb')
        ip_nat = open(ip_nat_p, 'wb')
        ip_nat_rev = open(ip_nat_rev_p, 'wb')

        self.rule_files = {
            'ip_acl': {'orig': ip_acl, 'rev': ip_acl_rev},
            'ip6_acl': {'orig': ip6_acl, 'rev': ip6_acl_rev},
            'ip_nat': {'orig': ip_nat, 'rev': ip_nat_rev},
        }

    def get_formatter(self, rule):
        if isinstance(rule, ACLRule):
            return ACLRuleFormatter
        elif isinstance(rule, DNATRule):
            return DNATRuleFormatter
        else:
            raise TypeError('Could not find formatter for {}'.
                            format(rule))

    def get_rule_files(self, rule):
        files = self.rule_files[rule.type()]
        return files['orig'], files['rev']

    def write(self, rule):
        rule_formatter = self.get_formatter(rule)
        rule_file, rev_rule_file = self.get_rule_files(rule)
        rule_file.write(rule_formatter(rule).orig() + '\n')
        rev_rule_file.write(rule_formatter(rule).reply() + '\n')


class MatchContext(object):
    def __init__(self):
        self.matches = {
            'any': {},
            'ip': {},
            'ip6': {},
            'tcp': {},
            'udp': {},
            'udplite': {},
            'sctp': {},
            'ah': {},
            'esp': {},
            'icmp': {},
            'icmpv6': {},
            'ipcomp': {},
        }


class NFTRuleParser(object):
    rule_re = re.compile(
        r'nft\s+add\s+rule\s+'
        r'((?P<family>(ip|ip6|arp|bridge|inet))(?:\s+))?'
        r'(?P<table>[a-zA-Z]+)\s+'
        r'(?P<chain>[a-zA-Z]+)\s+'
        r'(?P<rest>.+)'
    )

    def __init__(self, path, ipaddrs, ip6addrs):
        self.path = path
        self.ipaddrs = ipaddrs
        self.ip6addrs = ip6addrs
        self.ip_acl = []
        self.ip6_acl = []
        self.ip_nat = []
        self.mctx = None

    def _parse_generic_match(self, match, arg, value):
        self.mctx.matches[match][arg] = value

    def _parse_ip6_match(self, arg, value):
        self.mctx.matches['ip6'][arg] = value

    def _get_match_parser(self, match):
        if match == 'ip6':
            return self._parse_ip6_match
        else:
            return partial(self._parse_generic_match, match)

    def _parse_matches(self, parts):
        match = None
        arg = None

        for part in parts:
            if match is None:
                if part in self.mctx.matches:
                    match = part
                else:
                    print("Warning: match {!r} is unknown.".format(part))
                arg = None

            elif arg:
                parser = self._get_match_parser(match)
                parser(arg, part)
                match = None
                arg = None

            else:
                arg = part

    def _find_upper_layer_proto(self, rule):
        protos = [
            'tcp',
            'udp',
            'udplite',
            'icmp',
            'icmpv6',
            'ah',
            'esp',
            'sctp',
            'dccp',
            'ipcomp'
        ]

        for proto in protos:
            if proto in rule:
                return proto

        nexthdr = self.mctx.matches['ip6'].get('nexthdr')
        if nexthdr is not None:
            return nexthdr

        return 'any'

    def _parse_rule(self, rule):
        self.mctx = MatchContext()
        rule = rule.strip('\n')

        match = self.rule_re.match(rule)
        if match is None:
            raise ValueError('Could not parse line: {!r}'.format(rule))

        table = match.group('table')
        family = match.group('family')
        family = family if family else 'ip'
        if family not in ('ip', 'ip6'):
            raise ValueError('Sorry, {!r} family is not yet supported.'.
                             format(family))

        if table == 'nat':
            #import ipdb
            #ipdb.set_trace()
            self._parse_nat_rule(family, match, rule)
        else:
            self._parse_filter_rule(family, match, rule)

    def _parse_port(self, port):
        if port:
            if '-' in port:
                port = port.replace('-', PORT_DELIM)
            else:
                port = '{}{}{}'.format(port, PORT_DELIM, port)
        else:
            port = PORT_RANGE_WILDCARD

        return port

    def _parse_filter_rule(self, family, match, rule):
        rule_parts = rule.split()
        self._parse_matches(rule_parts)

        snet = self.mctx.matches[family].get('saddr')
        dnet = self.mctx.matches[family].get('daddr')

        actions = []
        for token in reversed(rule_parts):
            if ACLRule.action_to_code(token) is not None:
                actions.append(token)
            else:
                break

        ulp = self._find_upper_layer_proto(rule)
        iphdr = IPHeader(family, ulp, snet, dnet)

        if ulp in ('any', 'tcp', 'udp', 'udplite', 'stcp', 'dccp'):
            sport_range = self._parse_port(self.mctx.matches[ulp].get('sport'))
            dport_range = self._parse_port(self.mctx.matches[ulp].get('dport'))
            ulhdr = TransportHeader(sport_range, dport_range)

        elif ulp in ('icmp', 'icmpv6'):
            _type = self.mctx.matches[ulp].get('type', 'all')
            code = self.mctx.matches[ulp].get('code', 'all')
            ulhdr = ICMPHeader(_type, code)

        else:
            raise AssertionError('Unknown protocol!')

        acl = ACLRule(iphdr, ulhdr, actions)
        if family == 'ip':
            if match.group('chain') == 'input':
                for ipaddr in self.ipaddrs:
                    iphdr = IPHeader(family, ulp, snet, ipaddr)
                    acl = ACLRule(iphdr, ulhdr, actions)
                    acl.set_local()
                    self.ip_acl.append(acl)
            else:
                self.ip_acl.append(acl)
        else:
            if match.group('chain') == 'input':
                for ip6addr in self.ip6addrs:
                    iphdr = IPHeader(family, ulp, snet, ip6addr)
                    acl = ACLRule(ip6hdr, ulhdr, actions)
                    acl.set_local()
                    self.ip6_acl.append(acl)
            else:
                self.ip6_acl.append(acl)

    def _parse_nat_rule(self, family, match, rule):
        rule = rule.strip('\n')

        if 'snat' in rule:
            raise ValueError('Source NAT not yet supported.')

        rule_parts = rule.split()
        self._parse_matches(rule_parts)

        fdict = self.mctx.matches['ip'] if family else self.mctx.matches['ip6'] 
        orig_ip = fdict.get('daddr')
        assert(orig_ip)

        trans_ip = rule_parts[rule_parts.index('dnat') + 1]

        orig_ip = ipaddress.ip_network(unicode(orig_ip))
        trans_ip = ipaddress.ip_network(unicode(trans_ip))

        if family == 'ip':
            self.ip_nat.append(DNATRule(orig_ip, trans_ip))
        else:
            raise NotImplementedError('IPv6 NAT not yet supported.')

    def _ignored(self, line):
        if line.startswith('#'):
            return True
        elif line[0] == '\n':
            return True
        else:
            return False
    
    def _sort_rules(self, data):
        '''
        Make sure that rules in the input chain are parsed first
        '''
        
        new_data = []

        for line in data:
            match = self.rule_re.match(line)
            if match and match.group('chain') == 'input':
                new_data.append(line)

        for line in data:
            match = self.rule_re.match(line)
            if match and match.group('chain') != 'input':
                new_data.append(line)

        return new_data

    def parse(self):
        with open(self.path, 'rb') as rfile:
            data = rfile.readlines()
            data = self._sort_rules(data)
            for line in data:
                if not self._ignored(line):
                    self._parse_rule(line)

class ConfigParser(object):
    def __init__(self, config):
        self.config = config
        
    def ipaddrs(self, zname):
        addrs = []
        for nic in self.config.ifaces:
            if nic.zone == zname:
                try:
                    addrs.append(nic.ip_addr)
                except AttributeError:
                    pass

        return addrs

    def ip6addrs(self, zname):
        addrs = []
        for nic in self.config.ifaces:
            if nic.zone == zname:
                try:
                    addrs.append(nic.ip6_addr)
                except AttributeError:
                    pass

        return addrs


def main():
    if len(sys.argv) < 3:
        print("usage: {} <firewall_config> <zone_config>".format(sys.argv[0]))
        print("example: {} pipeline.conf {}/example.conf".
              format(sys.argv[0], ZONE_PATH))
        return -1

    conf_path = sys.argv[1]
    rule_path = sys.argv[2]

    try:
        config = cfg.Config(open(conf_path, 'rb').read())
    except (EnvironmentError,
            cfg.ParseException,
            cfg.ParseFatalException) as err:
        print("Could not load configuration file: {}".format(err))
        return -1

    zname = os.path.basename(rule_path).split('.')[0]

    cfgp = ConfigParser(config)
    rules = NFTRuleParser(rule_path,
                          cfgp.ipaddrs(zname),
                          cfgp.ip6addrs(zname))
    rules.parse()

    zone = Zone(zname, rules)
    serializer = RuleSerializer(zone)

    for acl in zone.rules.ip_acl:
        for nat in zone.rules.ip_nat:
            # Destination NAT
            if acl.dnet_contains(nat.orig_ip):
                if acl.iphdr.dnet.hostmask != ipaddress.IPv4Address(u'0.0.0.0'):
                    raise AssertionError(
                        'ACL rules which are NATed must refer to a single '
                        'destination host. {} is not valid.'.
                        format(acl.iphdr.dnet))
                acl.dnat = nat
                acl.action |= ACL_ACTION_DNAT

    for acl in zone.rules.ip_acl:
        serializer.write(acl)
    for acl in zone.rules.ip6_acl:
        serializer.write(acl)
    for nat in zone.rules.ip_nat:
        serializer.write(nat)

    return 0

if __name__ == '__main__':
    ret = main()
    sys.exit(ret)
