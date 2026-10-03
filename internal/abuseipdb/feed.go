package abuseipdb

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
)

// Published feed fields plus optional protocol for richer local JSON.
// The public blocklist.json schema does not currently emit protocol.
type Entry struct {
	IP       string `json:"ip"`
	Tier     string `json:"tier"`
	Bans     int64  `json:"bans"`
	Attempts int64  `json:"attempts"`
	LastSeen string `json:"last_seen"`
	Protocol string `json:"protocol,omitempty"`
	Spam     bool   `json:"spam,omitempty"`
}

type Feed struct {
	IPs []Entry `json:"ips"`
}

func LoadFeed(path string) (Feed, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Feed{}, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseFeed(raw)
}

func ParseFeed(raw []byte) (Feed, error) {
	var feed Feed
	if err := json.Unmarshal(raw, &feed); err != nil {
		return Feed{}, fmt.Errorf("parse blocklist JSON: %w", err)
	}
	if feed.IPs == nil {
		return Feed{}, fmt.Errorf("blocklist JSON ips must be an array")
	}
	return feed, nil
}

var reservedPrefixes = []netip.Prefix{
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
}

// Reportable is true for a globally routable IPv4 address. Private, reserved,
// documentation, and IPv6 addresses are skipped.
func Reportable(ip string) bool {
	address, err := netip.ParseAddr(ip)
	if err != nil || !address.Is4() {
		return false
	}
	if !address.IsGlobalUnicast() || address.IsMulticast() || address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range reservedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func limitEntries(entries []Entry, limit int) []Entry {
	if limit <= 0 || limit >= len(entries) {
		return entries
	}
	return entries[:limit]
}
