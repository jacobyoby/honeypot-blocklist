// Package validator validates the generated blocklist publication contract.
package validator

import (
	"fmt"
	"io"
)

// Result preserves the legacy validator's ordered warnings and errors.
type Result struct {
	Warnings []string
	Errors   []string
}

// ExitCode returns the command exit code for this result.
func (r Result) ExitCode() int {
	if len(r.Errors) != 0 {
		return 1
	}
	return 0
}

// Render writes the legacy validator's stdout contract.
func (r Result) Render(w io.Writer) error {
	for _, warning := range r.Warnings {
		if _, err := fmt.Fprintf(w, "WARN  %s\n", warning); err != nil {
			return err
		}
	}
	for _, validationError := range r.Errors {
		if _, err := fmt.Fprintf(w, "ERROR %s\n", validationError); err != nil {
			return err
		}
	}
	if len(r.Errors) != 0 {
		_, err := fmt.Fprintf(w, "\n%d error(s)\n", len(r.Errors))
		return err
	}
	_, err := fmt.Fprintf(w, "OK — %d warning(s)\n", len(r.Warnings))
	return err
}
