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

func TestValidateRejectsFormulaCellsWithLeadingSpaces(t *testing.T) {
	fixture := fixtureFS()
	row := "203.0.113.10,credential,1,50,2026-09-01T00:00:00Z,2026-09-01T00:00:00Z,2026-09-01T00:00:00Z, =cmd|' /C calc'!A0\r\n"
	fixture["blocklist.csv"] = mapFile("ip,tier,bans,attempts,first_seen,last_seen,first_banned,asn\r\n" + row)
	fixture["blocklist.misp.csv"] = mapFile(" =cmd|' /C calc'!A0\r\n")

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

func hasWarningContaining(result Result, fragment string) bool {
	for _, w := range result.Warnings {
		if strings.Contains(w, fragment) {
			return true
		}
	}
	return false
}

func TestNegativeFixtures(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(fstest.MapFS)
		wantError   string
		wantWarning string
	}{
		{
			name: "inclusion floor credential",
			mutate: func(f fstest.MapFS) {
				f["blocklist.json"] = mapFile(strings.ReplaceAll(
					strings.ReplaceAll(string(f["blocklist.json"].Data),
						`"attempts": 50`, `"attempts": 49`),
					`"count": 1`, `"count": 1`))
				f["blocklist.csv"] = mapFile(strings.ReplaceAll(
					string(f["blocklist.csv"].Data), ",50,", ",49,"))
				f["blocklist.misp.csv"] = mapFile(strings.ReplaceAll(
					string(f["blocklist.misp.csv"].Data), ",50,", ",49,"))
			},
			wantError: "below the documented inclusion threshold",
		},
		{
			name: "inclusion floor scanner_min_events",
			mutate: func(f fstest.MapFS) {
				jsonDoc := `{
  "meta": {
    "schema_version": "1.0",
    "name": "fixture",
    "description": "sanitized fixture",
    "maintainer": "fixture",
    "homepage": "https://example.invalid/feed/",
    "contact": "security@example.invalid",
    "inclusion_criteria": "scanner fixture",
    "window_days": 30,
    "scanner_min_events": 500,
    "count": 1,
    "count_by_tier": {"scanner": 1},
    "updated": "2026-09-01T00:00:00Z",
    "license": "CC0-1.0"
  },
  "ips": [
    {
      "ip": "203.0.113.10",
      "tier": "scanner",
      "bans": 0,
      "attempts": 499,
      "first_seen": "2026-09-01T00:00:00Z",
      "last_seen": "2026-09-01T00:00:00Z",
      "first_banned": null,
      "asn": "AS64500"
    }
  ]
}`
				row := "203.0.113.10,scanner,0,499,2026-09-01T00:00:00Z,2026-09-01T00:00:00Z,,AS64500\r\n"
				f["blocklist.json"] = mapFile(jsonDoc)
				f["blocklist.csv"] = mapFile("ip,tier,bans,attempts,first_seen,last_seen,first_banned,asn\r\n" + row)
				f["blocklist.misp.csv"] = mapFile(row)
			},
			wantError: "below the documented inclusion threshold",
		},
		{
			name: "meta count mismatch",
			mutate: func(f fstest.MapFS) {
				f["blocklist.json"] = mapFile(strings.Replace(
					string(f["blocklist.json"].Data),
					`"count": 1`, `"count": 99`, 1))
			},
			wantError: "meta.count=",
		},
		{
			name: "meta count_by_tier mismatch",
			mutate: func(f fstest.MapFS) {
				f["blocklist.json"] = mapFile(strings.Replace(
					string(f["blocklist.json"].Data),
					`"count_by_tier": {"credential": 1}`,
					`"count_by_tier": {"credential": 2}`, 1))
			},
			wantError: "meta.count_by_tier=",
		},
		{
			name: "first_seen after last_seen",
			mutate: func(f fstest.MapFS) {
				f["blocklist.json"] = mapFile(strings.Replace(
					string(f["blocklist.json"].Data),
					`"first_seen": "2026-09-01T00:00:00Z"`,
					`"first_seen": "2026-09-05T00:00:00Z"`, 1))
				f["blocklist.csv"] = mapFile(strings.Replace(
					string(f["blocklist.csv"].Data),
					"2026-09-01T00:00:00Z,2026-09-01T00:00:00Z,2026-09-01T00:00:00Z",
					"2026-09-05T00:00:00Z,2026-09-01T00:00:00Z,2026-09-01T00:00:00Z", 1))
				f["blocklist.misp.csv"] = mapFile(strings.Replace(
					string(f["blocklist.misp.csv"].Data),
					"2026-09-01T00:00:00Z,2026-09-01T00:00:00Z,2026-09-01T00:00:00Z",
					"2026-09-05T00:00:00Z,2026-09-01T00:00:00Z,2026-09-01T00:00:00Z", 1))
			},
			wantError: "first_seen",
		},
		{
			name: "bans positive but first_banned null",
			mutate: func(f fstest.MapFS) {
				f["blocklist.json"] = mapFile(strings.Replace(
					string(f["blocklist.json"].Data),
					`"first_banned": "2026-09-01T00:00:00Z"`,
					`"first_banned": null`, 1))
				f["blocklist.csv"] = mapFile(strings.Replace(
					string(f["blocklist.csv"].Data),
					",2026-09-01T00:00:00Z,AS64500",
					",,AS64500", 1))
				f["blocklist.misp.csv"] = mapFile(strings.Replace(
					string(f["blocklist.misp.csv"].Data),
					",2026-09-01T00:00:00Z,AS64500",
					",,AS64500", 1))
			},
			wantError: "first_banned is empty",
		},
		{
			name: "first_banned set but bans zero",
			mutate: func(f fstest.MapFS) {
				f["blocklist.json"] = mapFile(strings.Replace(
					string(f["blocklist.json"].Data),
					`"bans": 1`, `"bans": 0`, 1))
				f["blocklist.csv"] = mapFile(strings.Replace(
					string(f["blocklist.csv"].Data),
					",credential,1,", ",credential,0,", 1))
				f["blocklist.misp.csv"] = mapFile(strings.Replace(
					string(f["blocklist.misp.csv"].Data),
					",credential,1,", ",credential,0,", 1))
			},
			wantError: "bans=0 but first_banned=",
		},
		{
			name: "scanner tier with non-zero bans",
			mutate: func(f fstest.MapFS) {
				jsonDoc := `{
  "meta": {
    "schema_version": "1.0",
    "name": "fixture",
    "description": "sanitized fixture",
    "maintainer": "fixture",
    "homepage": "https://example.invalid/feed/",
    "contact": "security@example.invalid",
    "inclusion_criteria": "scanner fixture",
    "window_days": 30,
    "count": 1,
    "count_by_tier": {"scanner": 1},
    "updated": "2026-09-01T00:00:00Z",
    "license": "CC0-1.0"
  },
  "ips": [
    {
      "ip": "203.0.113.10",
      "tier": "scanner",
      "bans": 3,
      "attempts": 1000,
      "first_seen": "2026-09-01T00:00:00Z",
      "last_seen": "2026-09-01T00:00:00Z",
      "first_banned": "2026-09-01T00:00:00Z",
      "asn": "AS64500"
    }
  ]
}`
				row := "203.0.113.10,scanner,3,1000,2026-09-01T00:00:00Z,2026-09-01T00:00:00Z,2026-09-01T00:00:00Z,AS64500\r\n"
				f["blocklist.json"] = mapFile(jsonDoc)
				f["blocklist.csv"] = mapFile("ip,tier,bans,attempts,first_seen,last_seen,first_banned,asn\r\n" + row)
				f["blocklist.misp.csv"] = mapFile(row)
				f["blocklist.txt"] = mapFile("# sanitized fixture\n203.0.113.10\n")
			},
			wantError: "scanner-tier entry has bans=",
		},
		{
			name: "txt json membership disagreement",
			mutate: func(f fstest.MapFS) {
				f["blocklist.txt"] = mapFile("# sanitized fixture\n198.51.100.10\n")
			},
			wantError: "json/txt disagree",
		},
		{
			name: "csv json membership disagreement",
			mutate: func(f fstest.MapFS) {
				row := "198.51.100.10,credential,1,50,2026-09-01T00:00:00Z,2026-09-01T00:00:00Z,2026-09-01T00:00:00Z,AS64500\r\n"
				f["blocklist.csv"] = mapFile("ip,tier,bans,attempts,first_seen,last_seen,first_banned,asn\r\n" + row)
			},
			wantError: "json/csv disagree",
		},
		{
			name: "CSV header order drift",
			mutate: func(f fstest.MapFS) {
				row := "203.0.113.10,credential,1,50,2026-09-01T00:00:00Z,2026-09-01T00:00:00Z,2026-09-01T00:00:00Z,AS64500\r\n"
				f["blocklist.csv"] = mapFile("tier,ip,bans,attempts,first_seen,last_seen,first_banned,asn\r\n" + row)
			},
			wantError: "header",
		},
		{
			name: "schema_version MAJOR mismatch",
			mutate: func(f fstest.MapFS) {
				f["blocklist.json"] = mapFile(strings.Replace(
					string(f["blocklist.json"].Data),
					`"schema_version": "1.0"`, `"schema_version": "2.0"`, 1))
			},
			wantError: "different MAJOR",
		},
		{
			name: "schema_version MINOR drift",
			mutate: func(f fstest.MapFS) {
				f["blocklist.json"] = mapFile(strings.Replace(
					string(f["blocklist.json"].Data),
					`"schema_version": "1.0"`, `"schema_version": "1.1"`, 1))
			},
			wantWarning: "MINOR drift",
		},
		{
			name: "README count drift",
			mutate: func(f fstest.MapFS) {
				f["README.md"] = mapFile("**99 IPs**\n\nClaims measured 2026-09-01 against the live 99-entry feed.\n")
			},
			wantWarning: "does not state the current count",
		},
		{
			name: "README claim drift",
			mutate: func(f fstest.MapFS) {
				f["README.md"] = mapFile("**1 IPs**\n\nClaims measured 2026-09-01 against the live 500-entry feed.\n")
			},
			wantWarning: "drift",
		},
		{
			name: "malformed timestamp",
			mutate: func(f fstest.MapFS) {
				f["blocklist.json"] = mapFile(strings.Replace(
					string(f["blocklist.json"].Data),
					`"first_seen": "2026-09-01T00:00:00Z"`,
					`"first_seen": "2026-02-30T00:00:00Z"`, 1))
				f["blocklist.csv"] = mapFile(strings.Replace(
					string(f["blocklist.csv"].Data),
					"2026-09-01T00:00:00Z,2026-09-01T00:00:00Z",
					"2026-02-30T00:00:00Z,2026-09-01T00:00:00Z", 1))
				f["blocklist.misp.csv"] = mapFile(strings.Replace(
					string(f["blocklist.misp.csv"].Data),
					"2026-09-01T00:00:00Z,2026-09-01T00:00:00Z",
					"2026-02-30T00:00:00Z,2026-09-01T00:00:00Z", 1))
			},
			wantError: "not a real date/time",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fixture := fixtureFS()
			tc.mutate(fixture)

			result := validate(fixture, validationOptions{
				displayRoot:              ".",
				allowDocumentationRanges: true,
			})

			if tc.wantError != "" && !hasErrorContaining(result, tc.wantError) {
				t.Errorf("expected error containing %q, got errors: %v", tc.wantError, result.Errors)
			}
			if tc.wantWarning != "" && !hasWarningContaining(result, tc.wantWarning) {
				t.Errorf("expected warning containing %q, got warnings: %v", tc.wantWarning, result.Warnings)
			}
		})
	}
}

func TestValidateRealCorpus(t *testing.T) {
	result := ValidateDir("../../")
	if result.ExitCode() != 0 {
		t.Fatalf("ValidateDir on real repo files: exit code %d, errors: %v, warnings: %v",
			result.ExitCode(), result.Errors, result.Warnings)
	}
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
