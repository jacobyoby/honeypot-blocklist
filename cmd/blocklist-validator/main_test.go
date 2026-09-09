package main

import (
	"testing"

	"github.com/jacobyoby/honeypot-blocklist/internal/validator"
)

func TestCLIMissingDirectoryReturnsExitCode1(t *testing.T) {
	result := validator.ValidateDir("/nonexistent/path/that/does/not/exist")
	if result.ExitCode() != 1 {
		t.Fatalf("ValidateDir on missing directory: expected exit code 1, got %d", result.ExitCode())
	}
	if len(result.Errors) == 0 {
		t.Fatal("ValidateDir on missing directory: expected errors, got none")
	}
}

func TestCLIValidDirectoryReturnsExitCode0(t *testing.T) {
	// Use real repo files since they're known to pass validation
	result := validator.ValidateDir("../../")
	if result.ExitCode() != 0 {
		t.Fatalf("ValidateDir on real repo: expected exit code 0, got %d, errors: %v, warnings: %v",
			result.ExitCode(), result.Errors, result.Warnings)
	}
}
