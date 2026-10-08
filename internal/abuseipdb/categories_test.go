package abuseipdb

import (
	"reflect"
	"strings"
	"testing"
)

func TestCategories(t *testing.T) {
	tests := []struct {
		name  string
		entry Entry
		want  []int
	}{
		{name: "credential default is SSH", entry: Entry{Tier: "credential"}, want: []int{18, 22}},
		{name: "credential ssh", entry: Entry{Tier: "credential", Protocol: "SSH"}, want: []int{18, 22}},
		{name: "credential ftp", entry: Entry{Tier: "credential", Protocol: "ftp"}, want: []int{5, 18}},
		{name: "credential telnet", entry: Entry{Tier: "credential", Protocol: "telnet"}, want: []int{15, 18}},
		{name: "credential vnc", entry: Entry{Tier: "credential", Protocol: "vnc"}, want: []int{15, 18}},
		{name: "credential mysql not 16", entry: Entry{Tier: "credential", Protocol: "mysql"}, want: []int{15, 18}},
		{name: "credential smtp not spam", entry: Entry{Tier: "credential", Protocol: "smtp"}, want: []int{15}},
		{name: "credential email spam", entry: Entry{Tier: "credential", Protocol: "email", Spam: true}, want: []int{11}},
		{name: "credential http", entry: Entry{Tier: "credential", Protocol: "http"}, want: []int{21, 18}},
		{name: "scanner ignores protocol", entry: Entry{Tier: "scanner", Protocol: "ssh"}, want: []int{14, 15}},
		{name: "loader is payload evidence", entry: Entry{Tier: "loader"}, want: []int{15, 19}},
		{name: "unknown tier is hacking only", entry: Entry{Tier: "other"}, want: []int{15}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := Categories(test.entry)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("Categories(%+v) = %v, want %v", test.entry, got, test.want)
			}
		})
	}
}

func TestComment(t *testing.T) {
	text := Comment(Entry{
		Tier:     "credential",
		Attempts: 80,
		Bans:     2,
		LastSeen: "2026-09-01T00:00:00Z",
		Protocol: "ssh",
	})
	for _, want := range []string{
		"honeypot-confirmed credential-tier activity",
		"protocol=ssh",
		"attempts=80",
		"bans=2",
		"last_seen=2026-09-01T00:00:00Z",
		"https://jacobrakai.org/feed/",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Comment() = %q, missing %q", text, want)
		}
	}
	for _, banned := range []string{"password", "username", "root", "wget"} {
		if strings.Contains(strings.ToLower(text), banned) {
			t.Fatalf("Comment() leaked %q: %s", banned, text)
		}
	}

	loader := Comment(Entry{Tier: "loader", Attempts: 1, LastSeen: "2026-09-01T00:00:00Z"})
	if !strings.Contains(loader, "loader-tier payload delivery") {
		t.Fatalf("Comment(loader) = %q", loader)
	}
}

func TestIsKnown(t *testing.T) {
	tests := []struct {
		name         string
		score        int
		totalReports int
		threshold    int
		want         bool
	}{
		{name: "default threshold known", score: 25, totalReports: 1, threshold: 25, want: true},
		{name: "default threshold novel", score: 24, totalReports: 40, threshold: 25, want: false},
		{name: "zero threshold any report", score: 0, totalReports: 1, threshold: 0, want: true},
		{name: "zero threshold no reports", score: 0, totalReports: 0, threshold: 0, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := IsKnown(test.score, test.totalReports, test.threshold); got != test.want {
				t.Fatalf("IsKnown(%d, %d, %d) = %v, want %v", test.score, test.totalReports, test.threshold, got, test.want)
			}
		})
	}
}

func TestFormatCategories(t *testing.T) {
	if got := FormatCategories([]int{18, 22}); got != "18,22" {
		t.Fatalf("FormatCategories() = %q", got)
	}
}
