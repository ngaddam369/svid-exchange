//go:build e2e

// Package e2e_test runs the end-to-end flow against the live Docker Compose
// dev stack. Start the base stack first with `make compose-up`, then run:
//
//	go test -v -tags e2e -timeout 120s ./test/e2e/
package e2e_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestE2EFlow verifies the full token exchange flow:
//
//  1. e2e-spire-init registers the e2e-caller workload entry with SPIRE.
//  2. e2e-validator starts and becomes healthy (JWKS reachable, /healthz up).
//  3. e2e-caller fetches the e2e-caller SVID, exchanges it for a JWT targeting
//     e2e-validator, and calls /ping on the validator.
//  4. e2e-validator verifies the JWT (signature, audience, scope, expiry) and
//     returns 200; the caller exits 0.
func TestE2EFlow(t *testing.T) {
	// compose returns a docker compose command using both compose files.
	// Working directory for go test is the package directory (test/e2e/).
	compose := func(args ...string) *exec.Cmd {
		full := append([]string{
			"compose",
			"-f", "../../docker-compose.yml",
			"-f", "docker-compose.yml",
		}, args...)
		cmd := exec.Command("docker", full...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd
	}

	// Require the base stack to be running before proceeding.
	check := exec.Command("docker", "compose", "-f", "../../docker-compose.yml",
		"ps", "--services", "--filter", "status=running")
	out, err := check.Output()
	if err != nil || !strings.Contains(string(out), "svid-exchange") {
		t.Skip("base Docker Compose stack not running; run 'make compose-up' first")
	}

	t.Cleanup(func() {
		if err := compose("rm", "-fsv", "e2e-caller", "e2e-validator", "e2e-spire-init").Run(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})

	// Start e2e services in detached mode. Dependencies are honoured by Compose.
	if err := compose("up", "--build", "--force-recreate", "-d",
		"e2e-spire-init", "e2e-validator", "e2e-caller").Run(); err != nil {
		t.Fatalf("bring up e2e services: %v", err)
	}

	// Retrieve the container ID of e2e-caller (needed for docker wait).
	psCmd := compose("ps", "-q", "--all", "e2e-caller")
	psCmd.Stdout = nil // capture instead of forwarding
	idBytes, err := psCmd.Output()
	if err != nil {
		t.Fatalf("get e2e-caller container ID: %v", err)
	}
	containerID := strings.TrimSpace(string(idBytes))
	if containerID == "" {
		t.Fatal("e2e-caller container not found")
	}

	// Wait for e2e-caller to exit and read its exit code.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	waitOut, err := exec.CommandContext(ctx, "docker", "wait", containerID).Output()
	if err != nil {
		t.Fatalf("docker wait: %v", err)
	}
	exitCode := strings.TrimSpace(string(waitOut))
	if exitCode != "0" {
		// Print caller logs to help diagnose failures.
		if err := compose("logs", "e2e-caller").Run(); err != nil {
			fmt.Fprintln(os.Stderr, "dump caller logs:", err)
		}
		t.Fatalf("e2e-caller exited with code %s", exitCode)
	}
}
