#!/usr/bin/env python3
"""Regenerate mape_rules.go from luci-app-fleth's fleth-map-e.lua.
Usage: tools/gen-mape-rules.py /path/to/luci-app-fleth/root/usr/sbin/fleth-map-e.lua > mape_rules.go && gofmt -w mape_rules.go
"""
import re, sys

src = open(sys.argv[1]).read()

def table(name):
    m = re.search(r'local %s = \{(.*?)\n\}' % name, src, re.S)
    out = []
    for k, v in re.findall(r'\[0x([0-9a-f]+)\]\s*=\s*\{([^}]*)\}', m.group(1)):
        out.append((int(k, 16), [int(x) for x in v.split(',')]))
    return sorted(out)

def emit(name, t, n, comment):
    lines = ['// ' + comment, 'var %s = map[uint64][%d]byte{' % (name, n)]
    lines += ['\t0x%x: {%s},' % (k, ', '.join(map(str, v))) for k, v in t]
    lines.append('}')
    return '\n'.join(lines)

print('''// Code generated from luci-app-fleth root/usr/sbin/fleth-map-e.lua; DO NOT EDIT.
// Copyright (c) 2024 huggy, MIT licensed; see NOTICE.
// Sources: https://ipv4.web.fc2.com/map-e.html and site-u2023/config-software, collated by luci-app-fleth.
// Japanese IPoE does not deliver MAP-E rules over DHCPv6, so this community-measured table is the only source.

package main
''')
print(emit('mapeRule31', table('ruleprefix31'), 2, 'mapeRule31: key is the top 31 bits of the IPv6 prefix (right-aligned to 32 bits), value is the first 2 IPv4 octets. /31 rules for JPNE v6plus and BIGLOBE, EA-len 25, PSID 8 bits, offset 4.'))
print()
print(emit('mapeRule38', table('ruleprefix38'), 3, 'mapeRule38: key is the top 38 bits of the IPv6 prefix (right-aligned to 40 bits), value is the first 3 IPv4 octets. /38 rules for BIGLOBE and NURO, EA-len 18, PSID 8 bits, offset 4.'))
print()
print(emit('mapeRule38x20', table('ruleprefix38_20'), 3, 'mapeRule38x20: also a /38 rule but with an IPv4 /20, OCN. EA-len 18, PSID 6 bits, offset 6.'))
