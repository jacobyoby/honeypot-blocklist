package abuseipdb

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunCheckDryRun(t *testing.T) {
	path := writeFeed(t, []Entry{
		{IP: "192.0.2.1", Tier: "credential", Attempts: 80, LastSeen: "2026-09-01T00:00:00Z"},
		{IP: "8.8.8.8", Tier: "scanner", Attempts: 1000, LastSeen: "2026-09-01T00:00:00Z"},
	})
	var out strings.Builder
	err := RunCheck(CheckOptions{Path: path, DryRun: true, Output: &out})
	if err != nil {
		t.Fatalf("RunCheck dry-run: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "192.0.2.1\tskip\treserved") {
		t.Fatalf("dry-run missing reserved skip:\n%s", text)
	}
	if !strings.Contains(text, "8.8.8.8\twould_check") {
		t.Fatalf("dry-run missing would_check:\n%s", text)
	}
	if strings.Contains(text, "known") || strings.Contains(text, "novel") {
		t.Fatalf("dry-run must not classify via API:\n%s", text)
	}
}

func TestRunCheckKnownAndNovel(t *testing.T) {
	path := writeFeed(t, []Entry{
		{IP: "8.8.8.8", Tier: "credential", Attempts: 80, LastSeen: "2026-09-01T00:00:00Z"},
		{IP: "1.2.3.4", Tier: "scanner", Attempts: 1000, LastSeen: "2026-09-01T00:00:00Z"},
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ipAddress")
		score, reports := 0, 0
		if ip == "8.8.8.8" {
			score, reports = 80, 3
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"ipAddress": ip, "abuseConfidenceScore": score, "totalReports": reports},
		})
	}))
	t.Cleanup(server.Close)

	var out strings.Builder
	err := RunCheck(CheckOptions{
		Path:       path,
		Threshold:  25,
		Client:     testClient(server),
		Output:     &out,
		Sleep:      0,
		MaxAgeDays: 30,
	})
	if err != nil {
		t.Fatalf("RunCheck: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "8.8.8.8\tknown\tscore=80") {
		t.Fatalf("missing known:\n%s", text)
	}
	if !strings.Contains(text, "1.2.3.4\tnovel\tscore=0") {
		t.Fatalf("missing novel:\n%s", text)
	}
	if !strings.Contains(text, "# summary: checked=2 known=1 novel=1") {
		t.Fatalf("summary:\n%s", text)
	}
}

func TestRunCheckStopsOn429(t *testing.T) {
	path := writeFeed(t, []Entry{
		{IP: "8.8.8.8", Tier: "credential", Attempts: 80, LastSeen: "2026-09-01T00:00:00Z"},
		{IP: "1.2.3.4", Tier: "scanner", Attempts: 1000, LastSeen: "2026-09-01T00:00:00Z"},
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "12")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"errors":[{"detail":"rate limited","status":429}]}`))
	}))
	t.Cleanup(server.Close)

	var out strings.Builder
	err := RunCheck(CheckOptions{Path: path, Client: testClient(server), Output: &out})
	if _, ok := err.(*RateLimitError); !ok {
		t.Fatalf("error type = %T (%v)", err, err)
	}
	if strings.Contains(out.String(), "1.2.3.4") {
		t.Fatalf("continued after 429:\n%s", out.String())
	}
}

func TestRunCheckLimit(t *testing.T) {
	path := writeFeed(t, []Entry{
		{IP: "8.8.8.8", Tier: "credential"},
		{IP: "1.2.3.4", Tier: "scanner"},
	})
	var out strings.Builder
	if err := RunCheck(CheckOptions{Path: path, DryRun: true, Limit: 1, Output: &out}); err != nil {
		t.Fatalf("RunCheck: %v", err)
	}
	if strings.Contains(out.String(), "1.2.3.4") {
		t.Fatalf("limit ignored:\n%s", out.String())
	}
}

func TestRunReportDryRunDefault(t *testing.T) {
	path := writeFeed(t, []Entry{
		{IP: "192.0.2.1", Tier: "credential", Attempts: 80, Bans: 2, LastSeen: "2026-09-01T00:00:00Z"},
		{IP: "8.8.8.8", Tier: "loader", Attempts: 1, LastSeen: "2026-09-01T00:00:00Z"},
	})
	var out strings.Builder
	err := RunReport(ReportOptions{Path: path, Submit: false, Output: &out, State: filepath.Join(t.TempDir(), "state.json")})
	if err != nil {
		t.Fatalf("RunReport dry-run: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "# dry-run") || !strings.Contains(text, "pass -submit") {
		t.Fatalf("missing dry-run banner:\n%s", text)
	}
	if !strings.Contains(text, "192.0.2.1\tskip\treserved") {
		t.Fatalf("missing reserved skip:\n%s", text)
	}
	if !strings.Contains(text, "8.8.8.8\twould_report\tcategories=15,19") {
		t.Fatalf("missing loader would_report:\n%s", text)
	}
	if strings.Contains(text, "submitted") {
		t.Fatalf("dry-run submitted:\n%s", text)
	}
}

func TestRunReportSubmitAndRecentSkip(t *testing.T) {
	path := writeFeed(t, []Entry{
		{IP: "8.8.8.8", Tier: "credential", Attempts: 80, Bans: 2, LastSeen: "2026-09-01T00:00:00Z"},
	})
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"ipAddress": "8.8.8.8", "abuseConfidenceScore": 52},
		})
	}))
	t.Cleanup(server.Close)

	statePath := filepath.Join(t.TempDir(), "state.json")
	now := time.Date(2026, 9, 20, 17, 0, 0, 0, time.UTC)
	var first strings.Builder
	err := RunReport(ReportOptions{
		Path: path, Submit: true, State: statePath, Client: testClient(server),
		Output: &first, Now: now, Sleep: 0,
	})
	if err != nil {
		t.Fatalf("first submit: %v", err)
	}
	if hits != 1 || !strings.Contains(first.String(), "8.8.8.8\tsubmitted\tscore=52") {
		t.Fatalf("first submit output:\n%s", first.String())
	}

	var second strings.Builder
	err = RunReport(ReportOptions{
		Path: path, Submit: true, State: statePath, Client: testClient(server),
		Output: &second, Now: now.Add(5 * time.Minute), Sleep: 0,
	})
	if err != nil {
		t.Fatalf("second submit: %v", err)
	}
	if hits != 1 {
		t.Fatalf("recent skip still POSTed, hits=%d", hits)
	}
	if !strings.Contains(second.String(), "8.8.8.8\tskip\trecent") {
		t.Fatalf("missing recent skip:\n%s", second.String())
	}
}

func TestRunReportRequiresClientOnSubmit(t *testing.T) {
	path := writeFeed(t, []Entry{{IP: "8.8.8.8", Tier: "credential"}})
	err := RunReport(ReportOptions{Path: path, Submit: true, Output: ioDiscard{}, State: filepath.Join(t.TempDir(), "state.json")})
	if err == nil || !strings.Contains(err.Error(), EnvAPIKey) {
		t.Fatalf("error = %v", err)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }

func writeFeed(t *testing.T, entries []Entry) string {
	t.Helper()
	feed := Feed{IPs: entries}
	raw, err := json.Marshal(feed)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "blocklist.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
