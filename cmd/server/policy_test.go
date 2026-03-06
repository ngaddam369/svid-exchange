package main

import (
	"os"
	"path/filepath"
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

func newTestStore(t *testing.T) *policy.Store {
	t.Helper()
	s, err := policy.OpenStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("store Close: %v", err)
		}
	})
	return s
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

func TestAtomicPolicySetBase(t *testing.T) {
	const (
		subA = "spiffe://cluster.local/ns/default/sa/a"
		subB = "spiffe://cluster.local/ns/default/sa/b"
		tgt  = "spiffe://cluster.local/ns/default/sa/target"
	)
	ap := newAtomicPolicy(loadTestPolicy(t, subA, tgt))

	// Replace base with a new set of policies.
	newBase := loadTestPolicy(t, subB, tgt).Policies()
	ap.setBase(newBase)

	got := ap.yamlPolicies()
	if len(got) != 1 || got[0].Subject != subB {
		t.Errorf("yamlPolicies after setBase = %v, want 1 policy with subject %q", got, subB)
	}

	// Mutating the returned slice must not affect internal base.
	got[0].Name = "mutated"
	if ap.yamlPolicies()[0].Name == "mutated" {
		t.Error("mutation of returned slice leaked into internal base")
	}
}

func TestAtomicPolicyRebuild(t *testing.T) {
	const (
		subA = "spiffe://cluster.local/ns/default/sa/a"
		subB = "spiffe://cluster.local/ns/default/sa/b"
		tgt  = "spiffe://cluster.local/ns/default/sa/target"
	)

	t.Run("empty store preserves YAML policies", func(t *testing.T) {
		ap := newAtomicPolicy(loadTestPolicy(t, subA, tgt))
		store := newTestStore(t)

		if err := ap.rebuild(store); err != nil {
			t.Fatalf("rebuild: %v", err)
		}
		if !ap.Evaluate(subA, tgt, []string{"r:w"}, 30).Allowed {
			t.Error("subA should still be allowed after rebuild with empty store")
		}
	})

	t.Run("dynamic policies are merged with YAML", func(t *testing.T) {
		ap := newAtomicPolicy(loadTestPolicy(t, subA, tgt))
		store := newTestStore(t)

		if err := store.Save(policy.Policy{
			Name:          "dynamic-b",
			Subject:       subB,
			Target:        tgt,
			AllowedScopes: []string{"r:w"},
			MaxTTL:        60,
		}); err != nil {
			t.Fatalf("Save: %v", err)
		}

		if err := ap.rebuild(store); err != nil {
			t.Fatalf("rebuild: %v", err)
		}
		if !ap.Evaluate(subA, tgt, []string{"r:w"}, 30).Allowed {
			t.Error("subA should be allowed after rebuild")
		}
		if !ap.Evaluate(subB, tgt, []string{"r:w"}, 30).Allowed {
			t.Error("subB should be allowed after rebuild with dynamic policy")
		}
	})

	t.Run("duplicate subject-target pair returns error", func(t *testing.T) {
		ap := newAtomicPolicy(loadTestPolicy(t, subA, tgt))
		store := newTestStore(t)

		// Dynamic policy duplicates the YAML policy's (subject, target) pair.
		if err := store.Save(policy.Policy{
			Name:          "duplicate",
			Subject:       subA,
			Target:        tgt,
			AllowedScopes: []string{"r:w"},
			MaxTTL:        60,
		}); err != nil {
			t.Fatalf("Save: %v", err)
		}

		if err := ap.rebuild(store); err == nil {
			t.Error("expected error for duplicate (subject, target) pair, got nil")
		}
	})
}
