package abuseipdb

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

const (
	DefaultThreshold    = 25
	DefaultStatePath    = "/tmp/honeypot-blocklist-abuseipdb-state.json"
	recentReportWindow  = 15 * time.Minute
	DefaultRequestSleep = 200 * time.Millisecond
)

type CheckOptions struct {
	Path       string
	Limit      int
	DryRun     bool
	MaxAgeDays int
	Threshold  int
	Sleep      time.Duration
	Client     *Client
	Output     io.Writer
	Now        time.Time
}

type ReportOptions struct {
	Path   string
	Limit  int
	Submit bool
	State  string
	Sleep  time.Duration
	Client *Client
	Output io.Writer
	Now    time.Time
}

func RunCheck(opts CheckOptions) error {
	out := opts.Output
	if out == nil {
		out = os.Stdout
	}
	if opts.MaxAgeDays <= 0 {
		opts.MaxAgeDays = DefaultMaxAgeDays
	}
	feed, err := LoadFeed(opts.Path)
	if err != nil {
		return err
	}
	entries := limitEntries(feed.IPs, opts.Limit)
	if opts.DryRun {
		fmt.Fprintf(out, "# dry-run: %d IPs from %s (no API call)\n", len(entries), opts.Path)
		for _, entry := range entries {
			if !Reportable(entry.IP) {
				fmt.Fprintf(out, "%s\tskip\treserved\n", entry.IP)
				continue
			}
			fmt.Fprintf(out, "%s\twould_check\ttier=%s\n", entry.IP, entry.Tier)
		}
		return nil
	}
	if opts.Client == nil {
		return fmt.Errorf("AbuseIPDB client is required (set %s or pass -dry-run)", EnvAPIKey)
	}

	var known, novel, skipped, failed int
	for i, entry := range entries {
		if !Reportable(entry.IP) {
			fmt.Fprintf(out, "%s\tskip\treserved\n", entry.IP)
			skipped++
			continue
		}
		if i > 0 {
			sleepDuration(opts.Client, opts.Sleep)
		}
		result, err := opts.Client.Check(entry.IP, opts.MaxAgeDays)
		if err != nil {
			if _, ok := err.(*RateLimitError); ok {
				fmt.Fprintf(out, "# summary: checked=%d known=%d novel=%d skipped=%d errors=%d\n",
					known+novel, known, novel, skipped, failed+1)
				return err
			}
			fmt.Fprintf(out, "%s\terror\t%s\n", entry.IP, err)
			failed++
			continue
		}
		if IsKnown(result.AbuseConfidenceScore, result.TotalReports, opts.Threshold) {
			fmt.Fprintf(out, "%s\tknown\tscore=%d\treports=%d\n", entry.IP, result.AbuseConfidenceScore, result.TotalReports)
			known++
			continue
		}
		fmt.Fprintf(out, "%s\tnovel\tscore=%d\treports=%d\n", entry.IP, result.AbuseConfidenceScore, result.TotalReports)
		novel++
	}
	fmt.Fprintf(out, "# summary: checked=%d known=%d novel=%d skipped=%d errors=%d\n",
		known+novel, known, novel, skipped, failed)
	if failed > 0 {
		return fmt.Errorf("check finished with %d error(s)", failed)
	}
	return nil
}

func RunReport(opts ReportOptions) error {
	out := opts.Output
	if out == nil {
		out = os.Stdout
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	feed, err := LoadFeed(opts.Path)
	if err != nil {
		return err
	}
	entries := limitEntries(feed.IPs, opts.Limit)
	statePath := opts.State
	if statePath == "" {
		statePath = DefaultStatePath
	}
	state, err := loadState(statePath)
	if err != nil {
		return err
	}

	if !opts.Submit {
		fmt.Fprintf(out, "# dry-run: %d IPs from %s (pass -submit to POST)\n", len(entries), opts.Path)
	} else if opts.Client == nil {
		return fmt.Errorf("AbuseIPDB client is required for -submit (set %s)", EnvAPIKey)
	}

	var reported, skippedReserved, skippedRecent, failed int
	for i, entry := range entries {
		cats := FormatCategories(Categories(entry))
		comment := Comment(entry)
		if !Reportable(entry.IP) {
			fmt.Fprintf(out, "%s\tskip\treserved\n", entry.IP)
			skippedReserved++
			continue
		}
		if recentlyReported(state, entry.IP, now) {
			fmt.Fprintf(out, "%s\tskip\trecent\n", entry.IP)
			skippedRecent++
			continue
		}
		if !opts.Submit {
			fmt.Fprintf(out, "%s\twould_report\tcategories=%s\ttimestamp=%s\tcomment=%s\n",
				entry.IP, cats, entry.LastSeen, comment)
			reported++
			continue
		}
		if i > 0 {
			sleepDuration(opts.Client, opts.Sleep)
		}
		result, err := opts.Client.Report(entry.IP, cats, comment, entry.LastSeen)
		if err != nil {
			if _, ok := err.(*RateLimitError); ok {
				if writeErr := saveState(statePath, state); writeErr != nil {
					fmt.Fprintf(out, "# failed to write state %s: %v\n", statePath, writeErr)
				}
				fmt.Fprintf(out, "# summary: reported=%d skipped_reserved=%d skipped_recent=%d errors=%d\n",
					reported, skippedReserved, skippedRecent, failed+1)
				return err
			}
			fmt.Fprintf(out, "%s\terror\t%s\n", entry.IP, err)
			failed++
			continue
		}
		state[entry.IP] = now.UTC().Format(time.RFC3339)
		fmt.Fprintf(out, "%s\tsubmitted\tscore=%d\tcategories=%s\n", entry.IP, result.AbuseConfidenceScore, cats)
		reported++
	}
	if opts.Submit {
		if err := saveState(statePath, state); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "# summary: reported=%d skipped_reserved=%d skipped_recent=%d errors=%d\n",
		reported, skippedReserved, skippedRecent, failed)
	if failed > 0 {
		return fmt.Errorf("report finished with %d error(s)", failed)
	}
	return nil
}

func sleepDuration(client *Client, d time.Duration) {
	if d <= 0 {
		return
	}
	if client != nil && client.Sleep != nil {
		client.Sleep(d)
		return
	}
	time.Sleep(d)
}

func loadState(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("read state %s: %w", path, err)
	}
	var state map[string]string
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	if state == nil {
		state = map[string]string{}
	}
	return state, nil
}

func saveState(path string, state map[string]string) error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write state %s: %w", path, err)
	}
	return nil
}

func recentlyReported(state map[string]string, ip string, now time.Time) bool {
	raw, ok := state[ip]
	if !ok || raw == "" {
		return false
	}
	seen, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return false
	}
	return now.Sub(seen) < recentReportWindow
}
