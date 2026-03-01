// Command validate lints a policy file without starting the server.
// Exits 0 on success, 1 on any validation error.
//
// Usage:
//
//	svid-exchange-validate [policy-file]
//
// If no argument is given the POLICY_FILE env var is used, falling back to
// config/policy.example.yaml.
package main

import (
	"fmt"
	"os"

	"github.com/ngaddam369/svid-exchange/internal/policy"
)

func main() {
	path := policyPath()

	if _, err := policy.LoadFile(path); err != nil {
		fmt.Fprintf(os.Stderr, "invalid policy %q: %v\n", path, err)
		os.Exit(1)
	}

	fmt.Printf("policy %q is valid\n", path)
}

func policyPath() string {
	if len(os.Args) > 1 {
		return os.Args[1]
	}
	if p := os.Getenv("POLICY_FILE"); p != "" {
		return p
	}
	return "config/policy.example.yaml"
}
