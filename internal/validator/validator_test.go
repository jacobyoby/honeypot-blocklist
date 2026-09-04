package validator

import (
	"io"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

func TestValidateSanitizedFixture(t *testing.T) {
	result := validate(fixtureFS(), validationOptions{
		displayRoot:              ".",
		allowDocumentationRanges: true,
	})

	if result.ExitCode() != 0 || len(result.Warnings) != 0 || len(result.Errors) != 0 {
		t.Fatalf("Validate() = warnings %v, errors %v", result.Warnings, result.Errors)
	}
}

func TestValidateRejectsDocumentationAddressInProduction(t *testing.T) {
	result := Validate(fixtureFS())

	if result.ExitCode() != 1 || !hasErrorContaining(result, "non-global address published: 203.0.113.10") {
		t.Fatalf("Validate() errors = %v", result.Errors)
	}
}

func TestValidateRequiresMISPFeed(t *testing.T) {
	fixture := fixtureFS()
	delete(fixture, "blocklist.misp.csv")

	result := validate(fixture, validationOptions{
		displayRoot:              ".",
		allowDocumentationRanges: true,
	})

	if !hasErrorContaining(result, "blocklist.misp.csv is missing") {
		t.Fatalf("Validate() errors = %v", result.Errors)
	}
}

func TestValidateRejectsFormulaCells(t *testing.T) {
	fixture := fixtureFS()
	row := "203.0.113.10,credential,1,50,2026-09-01T00:00:00Z,2026-09-01T00:00:00Z,2026-09-01T00:00:00Z,=cmd\r\n"
	fixture["blocklist.csv"] = mapFile("ip,tier,bans,attempts,first_seen,last_seen,first_banned,asn\r\n" + row)
	fixture["blocklist.misp.csv"] = mapFile(row)

	result := validate(fixture, validationOptions{
		displayRoot:              ".",
		allowDocumentationRanges: true,
	})

	if !hasErrorContaining(result, "begins with a formula character") {
		t.Fatalf("Validate() errors = %v", result.Errors)
	}
}

func TestValidateRejectsDuplicateCSVRows(t *testing.T) {
	fixture := fixtureFS()
	row := "203.0.113.10,credential,1,50,2026-09-01T00:00:00Z,2026-09-01T00:00:00Z,2026-09-01T00:00:00Z,AS64500\r\n"
	fixture["blocklist.csv"] = mapFile("ip,tier,bans,attempts,first_seen,last_seen,first_banned,asn\r\n" + row + row)
	fixture["blocklist.misp.csv"] = mapFile(row + row)

	result := validate(fixture, validationOptions{
		displayRoot:              ".",
		allowDocumentationRanges: true,
	})

	if !hasErrorContaining(result, "duplicate row") || !hasErrorContaining(result, "blocklist.misp.csv:2: duplicate") {
		t.Fatalf("Validate() errors = %v", result.Errors)
	}
}

func TestValidateRejectsBooleanCounters(t *testing.T) {
	fixture := fixtureFS()
	fixture["blocklist.json"] = mapFile(strings.Replace(
		string(fixture["blocklist.json"].Data),
		`"bans": 1`,
		`"bans": true`,
		1,
	))

	result := validate(fixture, validationOptions{
		displayRoot:              ".",
		allowDocumentationRanges: true,
	})

	if !hasErrorContaining(result, "bans must be a non-negative int") {
		t.Fatalf("Validate() errors = %v", result.Errors)
	}
}

func TestValidateRequiresCompleteEntrySchema(t *testing.T) {
	fixture := fixtureFS()
	original := string(fixture["blocklist.json"].Data)
	mutated := strings.Replace(original, ",\n      \"asn\": \"AS64500\"", "", 1)
	if mutated == original {
		t.Fatal("fixture mutation did not remove asn")
	}
	fixture["blocklist.json"] = mapFile(mutated)

	result := validate(fixture, validationOptions{
		displayRoot:              ".",
		allowDocumentationRanges: true,
	})

	if !hasErrorContaining(result, "missing fields ['asn']") {
		t.Fatalf("Validate() errors = %v", result.Errors)
	}
}

func TestValidateRejectsMalformedASNInEveryStructuredFormat(t *testing.T) {
	fixture := fixtureFS()
	for _, name := range []string{"blocklist.json", "blocklist.csv", "blocklist.misp.csv"} {
		fixture[name] = mapFile(strings.ReplaceAll(string(fixture[name].Data), "AS64500", "not-an-asn"))
	}

	result := validate(fixture, validationOptions{
		displayRoot:              ".",
		allowDocumentationRanges: true,
	})

	for _, location := range []string{"blocklist.json[0]", "blocklist.csv:2", "blocklist.misp.csv:1"} {
		if !hasErrorContaining(result, location+": asn must match AS<number>") {
			t.Fatalf("Validate() did not reject malformed ASN at %s; errors = %v", location, result.Errors)
		}
	}
}

func TestValidateRejectsMISPValueDrift(t *testing.T) {
	fixture := fixtureFS()
	fixture["blocklist.misp.csv"] = mapFile(strings.ReplaceAll(
		string(fixture["blocklist.misp.csv"].Data),
		"AS64500",
		"AS64501",
	))

	result := validate(fixture, validationOptions{
		displayRoot:              ".",
		allowDocumentationRanges: true,
	})

	if !hasErrorContaining(result, "csv and blocklist.misp.csv disagree on 1 field value") {
		t.Fatalf("Validate() errors = %v", result.Errors)
	}
}

func TestIPPolicy(t *testing.T) {
	tests := []struct {
		name       string
		address    string
		wantGlobal bool
	}{
		{name: "public", address: "1.1.1.1", wantGlobal: true},
		{name: "private", address: "10.0.0.1", wantGlobal: false},
		{name: "shared", address: "100.64.0.1", wantGlobal: false},
		{name: "documentation", address: "192.0.2.1", wantGlobal: false},
		{name: "benchmark", address: "198.18.0.1", wantGlobal: false},
		{name: "multicast", address: "224.0.0.1", wantGlobal: false},
		{name: "protocol anycast exception", address: "192.0.0.9", wantGlobal: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := validationState{options: validationOptions{}, result: Result{}}
			_, got := state.checkIP(test.address, "fixture")
			if got != test.wantGlobal {
				t.Fatalf("checkIP(%q) = %v, errors %v", test.address, got, state.result.Errors)
			}
		})
	}
}

func TestValidateRejectsGlobalIPv6UntilContractExists(t *testing.T) {
	state := validationState{options: validationOptions{}, result: Result{}}
	if _, ok := state.checkIP("2606:4700:4700::1111", "fixture"); ok {
		t.Fatal("checkIP() accepted IPv6")
	}
	if !hasErrorContaining(state.result, "feed's contract is IPv4-only") {
		t.Fatalf("checkIP() errors = %v", state.result.Errors)
	}
}

func FuzzValidateNeverPanics(f *testing.F) {
	fixture := fixtureFS()
	f.Add(
		fixture["blocklist.json"].Data,
		fixture["blocklist.txt"].Data,
		fixture["blocklist.csv"].Data,
		fixture["blocklist.misp.csv"].Data,
		fixture["README.md"].Data,
	)
	f.Add([]byte(`{}`), []byte(""), []byte(""), []byte(""), []byte(""))

	f.Fuzz(func(t *testing.T, jsonData, txtData, csvData, mispData, readmeData []byte) {
		fuzzFS := fstest.MapFS{
			"blocklist.json":     &fstest.MapFile{Data: jsonData},
			"blocklist.txt":      &fstest.MapFile{Data: txtData},
			"blocklist.csv":      &fstest.MapFile{Data: csvData},
			"blocklist.misp.csv": &fstest.MapFile{Data: mispData},
			"README.md":          &fstest.MapFile{Data: readmeData},
		}
		result := Validate(fuzzFS)
		if err := result.Render(io.Discard); err != nil {
			t.Fatalf("Render() error = %v", err)
		}
	})
}

func fixtureFS() fstest.MapFS {
	jsonDocument := `{
  "meta": {
    "schema_version": "1.0",
    "name": "fixture",
    "description": "sanitized fixture",
    "maintainer": "fixture",
    "homepage": "https://example.invalid/feed/",
    "contact": "security@example.invalid",
    "inclusion_criteria": "credential fixture",
    "window_days": 30,
    "count": 1,
    "count_by_tier": {"credential": 1},
    "updated": "2026-09-01T00:00:00Z",
    "license": "CC0-1.0"
  },
  "ips": [
    {
      "ip": "203.0.113.10",
      "tier": "credential",
      "bans": 1,
      "attempts": 50,
      "first_seen": "2026-09-01T00:00:00Z",
      "last_seen": "2026-09-01T00:00:00Z",
      "first_banned": "2026-09-01T00:00:00Z",
      "asn": "AS64500"
    }
  ]
}`
	row := "203.0.113.10,credential,1,50,2026-09-01T00:00:00Z,2026-09-01T00:00:00Z,2026-09-01T00:00:00Z,AS64500\r\n"
	return fstest.MapFS{
		"blocklist.json":     mapFile(jsonDocument),
		"blocklist.txt":      mapFile("# sanitized fixture\n203.0.113.10\n"),
		"blocklist.csv":      mapFile("ip,tier,bans,attempts,first_seen,last_seen,first_banned,asn\r\n" + row),
		"blocklist.misp.csv": mapFile(row),
		"README.md":          mapFile("**1 IPs**\n\nClaims measured 2026-09-01 against the live 1-entry feed.\n"),
	}
}

func mapFile(content string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte(content), Mode: fs.FileMode(0o600)}
}

func hasErrorContaining(result Result, fragment string) bool {
	for _, validationError := range result.Errors {
		if strings.Contains(validationError, fragment) {
			return true
		}
	}
	return false
}
