package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jacobyoby/honeypot-blocklist/internal/abuseipdb"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(exitCode(err))
	}
}

func run(args []string) error {
	if len(args) < 1 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(os.Stderr, usageText())
		if len(args) < 1 {
			return errUsage
		}
		return nil
	}

	switch args[0] {
	case "check":
		return runCheck(args[1:])
	case "report":
		return runReport(args[1:])
	default:
		fmt.Fprint(os.Stderr, usageText())
		return errUsage
	}
}

var errUsage = fmt.Errorf("usage: blocklist-abuseipdb check|report [flags]")

func exitCode(err error) int {
	if err == errUsage {
		return 2
	}
	return 1
}

func usageText() string {
	return `usage: blocklist-abuseipdb check|report [flags]

check   compare published IPs to AbuseIPDB reputation
report  print (default) or POST category-mapped reports

The API key is read from ABUSEIPDB_API_KEY only (header Key).
report is dry-run unless -submit is set. This command never writes
AbuseIPDB data into the published feed.

`
}

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	path := fs.String("path", "blocklist.json", "path to blocklist.json")
	limit := fs.Int("limit", 0, "check at most N entries (0 = all)")
	dryRun := fs.Bool("dry-run", false, "parse the feed only; do not call the API")
	maxAge := fs.Int("max-age-days", abuseipdb.DefaultMaxAgeDays, "AbuseIPDB maxAgeInDays")
	threshold := fs.Int("threshold", abuseipdb.DefaultThreshold, "known if score >= N; 0 = any prior report")
	sleep := fs.Duration("sleep", abuseipdb.DefaultRequestSleep, "delay between API calls")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}

	opts := abuseipdb.CheckOptions{
		Path:       *path,
		Limit:      *limit,
		DryRun:     *dryRun,
		MaxAgeDays: *maxAge,
		Threshold:  *threshold,
		Sleep:      *sleep,
		Output:     os.Stdout,
	}
	if !*dryRun {
		key := os.Getenv(abuseipdb.EnvAPIKey)
		if key == "" {
			return fmt.Errorf("%s is not set (use -dry-run to parse without an API call)", abuseipdb.EnvAPIKey)
		}
		opts.Client = abuseipdb.NewClient(key)
	}
	return abuseipdb.RunCheck(opts)
}

func runReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	path := fs.String("path", "blocklist.json", "path to blocklist.json")
	limit := fs.Int("limit", 0, "report at most N entries (0 = all)")
	submit := fs.Bool("submit", false, "POST reports; default is dry-run")
	state := fs.String("state", abuseipdb.DefaultStatePath, "recent-report state file")
	sleep := fs.Duration("sleep", abuseipdb.DefaultRequestSleep, "delay between API calls")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}

	opts := abuseipdb.ReportOptions{
		Path:   *path,
		Limit:  *limit,
		Submit: *submit,
		State:  *state,
		Sleep:  *sleep,
		Output: os.Stdout,
		Now:    time.Now().UTC(),
	}
	if *submit {
		key := os.Getenv(abuseipdb.EnvAPIKey)
		if key == "" {
			return fmt.Errorf("%s is not set (report is dry-run unless -submit is set)", abuseipdb.EnvAPIKey)
		}
		opts.Client = abuseipdb.NewClient(key)
	}
	return abuseipdb.RunReport(opts)
}
