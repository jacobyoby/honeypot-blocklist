package abuseipdb

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testKey = "test-abuseipdb-key-not-secret"

func TestClientCheckSuccess(t *testing.T) {
	var sawKeyInQuery bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/check" {
			t.Errorf("path = %s, want /check", r.URL.Path)
		}
		if r.Header.Get("Key") != testKey {
			t.Errorf("Key header = %q", r.Header.Get("Key"))
		}
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("Accept = %q", r.Header.Get("Accept"))
		}
		if r.URL.Query().Get("key") != "" || strings.Contains(r.URL.RawQuery, testKey) {
			sawKeyInQuery = true
		}
		if r.URL.Query().Get("ipAddress") != "8.8.8.8" {
			t.Errorf("ipAddress = %q", r.URL.Query().Get("ipAddress"))
		}
		if r.URL.Query().Get("maxAgeInDays") != "30" {
			t.Errorf("maxAgeInDays = %q", r.URL.Query().Get("maxAgeInDays"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"ipAddress":            "8.8.8.8",
				"abuseConfidenceScore": 80,
				"totalReports":         4,
			},
		})
	}))
	t.Cleanup(server.Close)

	client := testClient(server)
	got, err := client.Check("8.8.8.8", 30)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if sawKeyInQuery {
		t.Fatal("API key appeared in the query string")
	}
	if got.AbuseConfidenceScore != 80 || got.TotalReports != 4 {
		t.Fatalf("Check() = %+v", got)
	}
}

func TestClientReportSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/report" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Key") != testKey {
			t.Errorf("Key header = %q", r.Header.Get("Key"))
		}
		body, _ := io.ReadAll(r.Body)
		form := string(body)
		if strings.Contains(form, testKey) {
			t.Fatal("API key appeared in the form body")
		}
		if !strings.Contains(form, "ip=8.8.8.8") {
			t.Errorf("form missing ip: %q", form)
		}
		if !strings.Contains(form, "categories=18%2C22") && !strings.Contains(form, "categories=18,22") {
			t.Errorf("form missing categories: %q", form)
		}
		if !strings.Contains(form, "comment=") || !strings.Contains(form, "timestamp=") {
			t.Errorf("form missing comment/timestamp: %q", form)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"ipAddress":            "8.8.8.8",
				"abuseConfidenceScore": 52,
			},
		})
	}))
	t.Cleanup(server.Close)

	client := testClient(server)
	got, err := client.Report("8.8.8.8", "18,22", "honeypot-confirmed credential-tier activity", "2026-09-01T00:00:00Z")
	if err != nil {
		t.Fatalf("Report() error = %v", err)
	}
	if got.AbuseConfidenceScore != 52 {
		t.Fatalf("Report() = %+v", got)
	}
}

func TestClientRetriesShort429(t *testing.T) {
	var sleeps []time.Duration
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if hits == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"errors":[{"detail":"slow down","status":429}]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{"ipAddress": "8.8.8.8", "abuseConfidenceScore": 1, "totalReports": 0},
		})
	}))
	t.Cleanup(server.Close)

	client := testClient(server)
	client.Sleep = func(d time.Duration) { sleeps = append(sleeps, d) }
	if _, err := client.Check("8.8.8.8", 30); err != nil {
		t.Fatalf("Check() after short 429: %v", err)
	}
	if hits != 2 {
		t.Fatalf("hits = %d, want 2", hits)
	}
	if len(sleeps) != 0 {
		t.Fatalf("Retry-After 0 should not sleep, got %v", sleeps)
	}
}

func TestClientDoesNotSleepLong429(t *testing.T) {
	slept := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"errors":[{"detail":"Daily rate limit of 1000 requests exceeded for this endpoint.","status":429}]}`))
	}))
	t.Cleanup(server.Close)

	client := testClient(server)
	client.Sleep = func(time.Duration) { slept = true }
	_, err := client.Check("8.8.8.8", 30)
	rate, ok := err.(*RateLimitError)
	if !ok {
		t.Fatalf("Check() error type = %T (%v), want *RateLimitError", err, err)
	}
	if rate.RetryAfter != 30*time.Second {
		t.Fatalf("RetryAfter = %s", rate.RetryAfter)
	}
	if !strings.Contains(rate.Error(), "Daily rate limit") {
		t.Fatalf("Error() = %q", rate.Error())
	}
	if slept {
		t.Fatal("long Retry-After must not sleep")
	}
	if strings.Contains(err.Error(), testKey) {
		t.Fatal("error leaked API key")
	}
}

func TestClientCheckRequiresKey(t *testing.T) {
	client := &Client{BaseURL: "http://127.0.0.1"}
	if _, err := client.Check("8.8.8.8", 30); err == nil {
		t.Fatal("Check() without key: expected error")
	}
}

func testClient(server *httptest.Server) *Client {
	return &Client{
		BaseURL:    server.URL,
		APIKey:     testKey,
		HTTPClient: server.Client(),
		Sleep:      func(time.Duration) {},
	}
}
