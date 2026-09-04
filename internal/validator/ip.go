package validator

import (
	"fmt"
	"net/netip"
)

var nonGlobalPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

var documentationPrefixes = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func (s *validationState) checkIP(raw any, where string) (string, bool) {
	text, ok := raw.(string)
	if !ok {
		s.err(fmt.Sprintf("%s: unparseable IP %s", where, pythonRepr(raw)))
		return "", false
	}
	address, err := netip.ParseAddr(text)
	if err != nil {
		s.err(fmt.Sprintf("%s: unparseable IP %s", where, pythonRepr(text)))
		return "", false
	}
	if !s.options.allowDocumentationRanges || !isDocumentationAddress(address) {
		if !isGlobalAddress(address) {
			s.err(fmt.Sprintf("%s: non-global address published: %s", where, address))
			return "", false
		}
	}
	if !address.Is4() {
		s.err(fmt.Sprintf(
			"%s: IPv6 address %s published, but this feed's contract is IPv4-only. The ipset/iptables recipes create `family inet` sets, which reject a v6 address instead of blocking it -- consumers would silently not be protected. Design the v6 contract and update the recipes before relaxing ALLOWED_IP_VERSIONS.",
			where, address,
		))
		return "", false
	}
	return address.String(), true
}

func isGlobalAddress(address netip.Addr) bool {
	if !address.IsValid() || address.IsMulticast() {
		return false
	}
	if address == netip.MustParseAddr("192.0.0.9") || address == netip.MustParseAddr("192.0.0.10") {
		return true
	}
	for _, prefix := range nonGlobalPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return address.IsGlobalUnicast()
}

func isDocumentationAddress(address netip.Addr) bool {
	for _, prefix := range documentationPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}
