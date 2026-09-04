package main

import (
	"fmt"
	"os"

	"github.com/jacobyoby/honeypot-blocklist/internal/validator"
)

func main() {
	directory := "."
	if len(os.Args) > 1 {
		directory = os.Args[1]
	}

	result := validator.ValidateDir(directory)
	if err := result.Render(os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "write validation result: %v\n", err)
		os.Exit(2)
	}
	os.Exit(result.ExitCode())
}
