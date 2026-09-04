package validator

import (
	"bytes"
	"errors"
	"testing"
)

func TestResultSuccessContract(t *testing.T) {
	result := Result{Warnings: []string{"first", "second"}}

	var output bytes.Buffer
	if err := result.Render(&output); err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if got, want := output.String(), "WARN  first\nWARN  second\nOK — 2 warning(s)\n"; got != want {
		t.Fatalf("Render() = %q, want %q", got, want)
	}
	if got := result.ExitCode(); got != 0 {
		t.Fatalf("ExitCode() = %d, want 0", got)
	}
}

func TestResultFailureContract(t *testing.T) {
	result := Result{
		Warnings: []string{"warning"},
		Errors:   []string{"first", "second"},
	}

	var output bytes.Buffer
	if err := result.Render(&output); err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	want := "WARN  warning\nERROR first\nERROR second\n\n2 error(s)\n"
	if got := output.String(); got != want {
		t.Fatalf("Render() = %q, want %q", got, want)
	}
	if got := result.ExitCode(); got != 1 {
		t.Fatalf("ExitCode() = %d, want 1", got)
	}
}

func TestResultPropagatesWriterError(t *testing.T) {
	want := errors.New("write failed")
	writer := errorWriter{err: want}

	if err := (Result{}).Render(writer); !errors.Is(err, want) {
		t.Fatalf("Render() error = %v, want %v", err, want)
	}
}

type errorWriter struct {
	err error
}

func (w errorWriter) Write([]byte) (int, error) {
	return 0, w.err
}
