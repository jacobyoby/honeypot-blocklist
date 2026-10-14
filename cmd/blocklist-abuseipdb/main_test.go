package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunMissingCommand(t *testing.T) {
	err := run(nil)
	if err != errUsage {
		t.Fatalf("run(nil) = %v, want errUsage", err)
	}
	if exitCode(err) != 2 {
		t.Fatalf("exitCode = %d, want 2", exitCode(err))
	}
}

func TestRunUnknownCommand(t *testing.T) {
	if err := run([]string{"blacklist"}); err != errUsage {
		t.Fatalf("unknown command = %v, want errUsage", err)
	}
}

func TestRunCheckDryRunNoKey(t *testing.T) {
	path := writeCLIFeed(t)
	t.Setenv("ABUSEIPDB_API_KEY", "")
	if err := run([]string{"check", "-path", path, "-dry-run"}); err != nil {
		t.Fatalf("check -dry-run: %v", err)
	}
}

func TestRunCheckRequiresKey(t *testing.T) {
	path := writeCLIFeed(t)
	t.Setenv("ABUSEIPDB_API_KEY", "")
	err := run([]string{"check", "-path", path})
	if err == nil || !strings.Contains(err.Error(), "ABUSEIPDB_API_KEY") {
		t.Fatalf("check without key = %v", err)
	}
}

func TestRunReportDefaultIsDryRun(t *testing.T) {
	path := writeCLIFeed(t)
	t.Setenv("ABUSEIPDB_API_KEY", "")
	if err := run([]string{"report", "-path", path, "-state", filepath.Join(t.TempDir(), "state.json")}); err != nil {
		t.Fatalf("report dry-run: %v", err)
	}
}

func writeCLIFeed(t *testing.T) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"ips": []map[string]any{{
			"ip":        "192.0.2.1",
			"tier":      "credential",
			"bans":      1,
			"attempts":  80,
			"last_seen": "2026-09-01T00:00:00Z",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "blocklist.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMainHelp(t *testing.T) {
	if err := run([]string{"-h"}); err != nil {
		t.Fatalf("help: %v", err)
	}
}
