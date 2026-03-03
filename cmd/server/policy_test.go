package main

import (
	"os"
	"testing"

	"github.com/ngaddam369/svid-exchange/internal/policy"
)

// loadTestPolicy writes a minimal policy YAML to a temp file and loads it.
func loadTestPolicy(t *testing.T, subject, target string) *policy.Loader {
	t.Helper()
	yaml := "policies:\n" +
		"  - name: test\n" +
		"    subject: \"" + subject + "\"\n" +
		"    target: \"" + target + "\"\n" +
		"    allowed_scopes: [\"r:w\"]\n" +
		"    max_ttl: 60\n"
	f, err := os.CreateTemp(t.TempDir(), "policy-*.yaml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.WriteString(yaml); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	pl, err := policy.LoadFile(f.Name())
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	return pl
}

func TestAtomicPolicy(t *testing.T) {
	const (
		subA = "spiffe://cluster.local/ns/default/sa/a"
		subB = "spiffe://cluster.local/ns/default/sa/b"
		tgt  = "spiffe://cluster.local/ns/default/sa/target"
	)

	t.Run("evaluates against initial policy", func(t *testing.T) {
		ap := newAtomicPolicy(loadTestPolicy(t, subA, tgt))

		res := ap.Evaluate(subA, tgt, []string{"r:w"}, 30)
		if !res.Allowed {
			t.Error("expected Allowed=true for initial policy")
		}
		res = ap.Evaluate(subB, tgt, []string{"r:w"}, 30)
		if res.Allowed {
			t.Error("expected Allowed=false for subB not in initial policy")
		}
	})

	t.Run("swap changes which policy is active", func(t *testing.T) {
		ap := newAtomicPolicy(loadTestPolicy(t, subA, tgt))

		// Before swap: subA allowed, subB denied.
		if !ap.Evaluate(subA, tgt, []string{"r:w"}, 30).Allowed {
			t.Fatal("subA should be allowed before swap")
		}
		if ap.Evaluate(subB, tgt, []string{"r:w"}, 30).Allowed {
			t.Fatal("subB should be denied before swap")
		}

		// Swap to a policy that only permits subB.
		ap.swap(loadTestPolicy(t, subB, tgt))

		// After swap: subB allowed, subA denied.
		if ap.Evaluate(subA, tgt, []string{"r:w"}, 30).Allowed {
			t.Error("subA should be denied after swap")
		}
		if !ap.Evaluate(subB, tgt, []string{"r:w"}, 30).Allowed {
			t.Error("subB should be allowed after swap")
		}
	})
}
