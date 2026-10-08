package abuseipdb

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	catFTPBrute     = 5
	catEmailSpam    = 11
	catPortScan     = 14
	catHacking      = 15
	catBruteForce   = 18
	catExploit      = 19
	catWebAppAttack = 21
	catSSH          = 22

	feedURL       = "https://jacobrakai.org/feed/"
	maxCommentLen = 512
)

// Categories maps a published (or richer local) entry to AbuseIPDB category
// IDs. Published JSON has no protocol field, so credential defaults to SSH
// brute-force (18,22). Loader is published on payload evidence, so it is
// 15+19. Keep the set honest and minimal.
func Categories(entry Entry) []int {
	switch strings.ToLower(strings.TrimSpace(entry.Tier)) {
	case "scanner":
		return []int{catPortScan, catHacking}
	case "loader":
		return []int{catHacking, catExploit}
	case "credential":
		return credentialCategories(entry.Protocol, entry.Spam)
	default:
		return []int{catHacking}
	}
}

func credentialCategories(protocol string, spam bool) []int {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "ftp":
		return []int{catFTPBrute, catBruteForce}
	case "telnet", "vnc", "mysql":
		return []int{catHacking, catBruteForce}
	case "smtp", "email":
		if spam {
			return []int{catEmailSpam}
		}
		return []int{catHacking}
	case "http", "https":
		return []int{catWebAppAttack, catBruteForce}
	case "ssh", "":
		return []int{catBruteForce, catSSH}
	default:
		return []int{catBruteForce, catSSH}
	}
}

func FormatCategories(cats []int) string {
	parts := make([]string, 0, len(cats))
	for _, cat := range cats {
		parts = append(parts, strconv.Itoa(cat))
	}
	return strings.Join(parts, ",")
}

// Comment builds a short PII-free report comment. It never includes captured
// credentials, usernames, or payload contents.
func Comment(entry Entry) string {
	tier := strings.TrimSpace(entry.Tier)
	if tier == "" {
		tier = "unknown"
	}
	var b strings.Builder
	b.WriteString("honeypot-confirmed ")
	b.WriteString(tier)
	b.WriteString("-tier")
	if tier == "loader" {
		b.WriteString(" payload delivery")
	} else {
		b.WriteString(" activity")
	}
	if proto := strings.TrimSpace(entry.Protocol); proto != "" {
		b.WriteString("; protocol=")
		b.WriteString(proto)
	}
	b.WriteString(fmt.Sprintf("; attempts=%d bans=%d", entry.Attempts, entry.Bans))
	if entry.LastSeen != "" {
		b.WriteString("; last_seen=")
		b.WriteString(entry.LastSeen)
	}
	b.WriteString("; source ")
	b.WriteString(feedURL)
	text := b.String()
	if len(text) > maxCommentLen {
		return text[:maxCommentLen]
	}
	return text
}

// IsKnown reports whether an AbuseIPDB check looks already-listed.
// threshold <= 0 means any prior report (totalReports > 0).
func IsKnown(score, totalReports, threshold int) bool {
	if threshold <= 0 {
		return totalReports > 0
	}
	return score >= threshold
}
