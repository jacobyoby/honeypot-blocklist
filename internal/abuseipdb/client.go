package abuseipdb

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultBaseURL    = "https://api.abuseipdb.com/api/v2"
	EnvAPIKey         = "ABUSEIPDB_API_KEY"
	DefaultMaxAgeDays = 30
	userAgent         = "jacobyoby-honeypot-blocklist-abuseipdb/1.0 (+https://jacobrakai.org/feed/)"
	shortRetry        = 2 * time.Second
)

type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
	Sleep      func(time.Duration)
}

type CheckResult struct {
	IP                   string
	AbuseConfidenceScore int
	TotalReports         int
}

type ReportResult struct {
	IP                   string
	AbuseConfidenceScore int
}

type RateLimitError struct {
	RetryAfter time.Duration
	Detail     string
}

func (e *RateLimitError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("AbuseIPDB rate limited (Retry-After %s)", e.RetryAfter)
	}
	return fmt.Sprintf("AbuseIPDB rate limited (Retry-After %s): %s", e.RetryAfter, e.Detail)
}

func NewClient(apiKey string) *Client {
	return &Client{
		BaseURL: DefaultBaseURL,
		APIKey:  apiKey,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
		Sleep: time.Sleep,
	}
}

func (c *Client) Check(ip string, maxAgeDays int) (CheckResult, error) {
	query := url.Values{}
	query.Set("ipAddress", ip)
	query.Set("maxAgeInDays", strconv.Itoa(maxAgeDays))
	raw, err := c.request(http.MethodGet, "/check", query, nil)
	if err != nil {
		return CheckResult{}, err
	}
	var parsed struct {
		Data struct {
			IPAddress            string `json:"ipAddress"`
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			TotalReports         int    `json:"totalReports"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return CheckResult{}, fmt.Errorf("decode check response: %w", err)
	}
	if parsed.Data.IPAddress == "" {
		parsed.Data.IPAddress = ip
	}
	return CheckResult{
		IP:                   parsed.Data.IPAddress,
		AbuseConfidenceScore: parsed.Data.AbuseConfidenceScore,
		TotalReports:         parsed.Data.TotalReports,
	}, nil
}

func (c *Client) Report(ip, categories, comment, timestamp string) (ReportResult, error) {
	form := url.Values{}
	form.Set("ip", ip)
	form.Set("categories", categories)
	if comment != "" {
		form.Set("comment", comment)
	}
	if timestamp != "" {
		form.Set("timestamp", timestamp)
	}
	raw, err := c.request(http.MethodPost, "/report", nil, form)
	if err != nil {
		return ReportResult{}, err
	}
	var parsed struct {
		Data struct {
			IPAddress            string `json:"ipAddress"`
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return ReportResult{}, fmt.Errorf("decode report response: %w", err)
	}
	if parsed.Data.IPAddress == "" {
		parsed.Data.IPAddress = ip
	}
	return ReportResult{
		IP:                   parsed.Data.IPAddress,
		AbuseConfidenceScore: parsed.Data.AbuseConfidenceScore,
	}, nil
}

func (c *Client) request(method, endpoint string, query url.Values, form url.Values) ([]byte, error) {
	if strings.TrimSpace(c.APIKey) == "" {
		return nil, fmt.Errorf("ABUSEIPDB_API_KEY is not set")
	}
	var formBytes []byte
	if form != nil {
		formBytes = []byte(form.Encode())
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		var body io.Reader
		if formBytes != nil {
			body = strings.NewReader(string(formBytes))
		}
		req, err := http.NewRequest(method, c.endpointURL(endpoint, query), body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Key", c.APIKey)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", userAgent)
		if formBytes != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := c.http().Do(req)
		if err != nil {
			return nil, err
		}
		payload, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read AbuseIPDB response: %w", readErr)
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			wait := retryAfter(resp)
			detail := apiDetail(payload)
			if attempt == 0 && wait <= shortRetry {
				c.sleep(wait)
				lastErr = &RateLimitError{RetryAfter: wait, Detail: detail}
				continue
			}
			return nil, &RateLimitError{RetryAfter: wait, Detail: detail}
		}
		if resp.StatusCode >= 300 {
			return nil, fmt.Errorf("AbuseIPDB %s %s: HTTP %d: %s", method, endpoint, resp.StatusCode, apiDetail(payload))
		}
		return payload, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("AbuseIPDB request failed")
}

func (c *Client) endpointURL(endpoint string, query url.Values) string {
	base := strings.TrimRight(c.BaseURL, "/")
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}
	u := base + endpoint
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	return u
}

func (c *Client) http() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func (c *Client) sleep(d time.Duration) {
	if d <= 0 {
		return
	}
	if c.Sleep != nil {
		c.Sleep(d)
		return
	}
	time.Sleep(d)
}

func retryAfter(resp *http.Response) time.Duration {
	raw := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if raw == "" {
		return time.Second
	}
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds < 0 {
		return time.Second
	}
	return time.Duration(seconds) * time.Second
}

func apiDetail(payload []byte) string {
	var parsed struct {
		Errors []struct {
			Detail string `json:"detail"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(payload, &parsed); err == nil && len(parsed.Errors) > 0 && parsed.Errors[0].Detail != "" {
		return parsed.Errors[0].Detail
	}
	text := strings.TrimSpace(string(payload))
	if text == "" {
		return "empty error body"
	}
	if len(text) > 200 {
		return text[:200]
	}
	return text
}
