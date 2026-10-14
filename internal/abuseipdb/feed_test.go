package abuseipdb

import (
	"testing"
)

func TestParseFeed(t *testing.T) {
	feed, err := ParseFeed([]byte(`{
		"meta": {"count": 2},
		"ips": [
			{"ip": "192.0.2.1", "tier": "credential", "bans": 2, "attempts": 80, "last_seen": "2026-09-01T00:00:00Z"},
			{"ip": "203.0.113.10", "tier": "scanner", "bans": 0, "attempts": 1000, "last_seen": "2026-09-02T00:00:00Z", "protocol": "vnc"}
		]
	}`))
	if err != nil {
		t.Fatalf("ParseFeed() error = %v", err)
	}
	if len(feed.IPs) != 2 {
		t.Fatalf("ParseFeed() len = %d, want 2", len(feed.IPs))
	}
	if feed.IPs[0].IP != "192.0.2.1" || feed.IPs[0].Tier != "credential" || feed.IPs[0].Attempts != 80 {
		t.Fatalf("ParseFeed()[0] = %+v", feed.IPs[0])
	}
	if feed.IPs[1].Protocol != "vnc" {
		t.Fatalf("ParseFeed() optional protocol = %q, want vnc", feed.IPs[1].Protocol)
	}
}

func TestParseFeedRejectsMissingIPs(t *testing.T) {
	if _, err := ParseFeed([]byte(`{"meta": {}}`)); err == nil {
		t.Fatal("ParseFeed() missing ips: expected error")
	}
}

func TestParseFeedRejectsInvalidJSON(t *testing.T) {
	if _, err := ParseFeed([]byte(`{`)); err == nil {
		t.Fatal("ParseFeed() invalid JSON: expected error")
	}
}

func TestReportable(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{ip: "8.8.8.8", want: true},
		{ip: "1.2.3.4", want: true},
		{ip: "192.0.2.1", want: false},
		{ip: "198.51.100.1", want: false},
		{ip: "203.0.113.10", want: false},
		{ip: "10.0.0.1", want: false},
		{ip: "192.168.1.1", want: false},
		{ip: "127.0.0.1", want: false},
		{ip: "169.254.1.1", want: false},
		{ip: "100.64.0.1", want: false},
		{ip: "0.0.0.0", want: false},
		{ip: "224.0.0.1", want: false},
		{ip: "not-an-ip", want: false},
		{ip: "2001:db8::1", want: false},
	}
	for _, test := range tests {
		t.Run(test.ip, func(t *testing.T) {
			if got := Reportable(test.ip); got != test.want {
				t.Fatalf("Reportable(%q) = %v, want %v", test.ip, got, test.want)
			}
		})
	}
}

func TestLimitEntries(t *testing.T) {
	entries := []Entry{{IP: "a"}, {IP: "b"}, {IP: "c"}}
	if got := limitEntries(entries, 2); len(got) != 2 || got[1].IP != "b" {
		t.Fatalf("limitEntries(., 2) = %+v", got)
	}
	if got := limitEntries(entries, 0); len(got) != 3 {
		t.Fatalf("limitEntries(., 0) len = %d", len(got))
	}
}
