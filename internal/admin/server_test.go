package admin

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ngaddam369/svid-exchange/internal/policy"
	adminv1 "github.com/ngaddam369/svid-exchange/proto/admin/v1"
)

const (
	subA = "spiffe://cluster.local/ns/default/sa/a"
	subB = "spiffe://cluster.local/ns/default/sa/b"
	subC = "spiffe://cluster.local/ns/default/sa/c"
	tgt  = "spiffe://cluster.local/ns/default/sa/target"
	tgt2 = "spiffe://cluster.local/ns/default/sa/target2"
)

var yamlRule = policy.Policy{
	Name:          "yaml-policy",
	Subject:       subA,
	Target:        tgt,
	AllowedScopes: []string{"read"},
	MaxTTL:        60,
}

func newTestServer(t *testing.T) (*Server, *policy.Store) {
	t.Helper()
	return newTestServerWithRevoke(t, func(_ string, _ time.Time) bool { return true })
}

func newTestServerWithRevoke(t *testing.T, revoke func(string, time.Time) bool) (*Server, *policy.Store) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "policy.db")
	store, err := policy.OpenStore(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	yamlPolicies := []policy.Policy{yamlRule}
	svc := New(
		store,
		func() []policy.Policy { return yamlPolicies },
		func(_ *policy.Loader) {},
		func() error { return nil },
		revoke,
	)
	return svc, store
}

func newRule(name, subject, target string) *adminv1.PolicyRule {
	return &adminv1.PolicyRule{
		Name:          name,
		Subject:       subject,
		Target:        target,
		AllowedScopes: []string{"read"},
		MaxTtl:        60,
	}
}

func TestCreatePolicy(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, store := newTestServer(t)
		resp, err := svc.CreatePolicy(context.Background(), &adminv1.CreatePolicyRequest{
			Rule: newRule("new-policy", subB, tgt),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Rule.Name != "new-policy" {
			t.Errorf("expected name %q, got %q", "new-policy", resp.Rule.Name)
		}
		got, _ := store.List()
		if len(got) != 1 || got[0].Name != "new-policy" {
			t.Errorf("expected policy in store, got %+v", got)
		}
	})

	t.Run("nil rule returns InvalidArgument", func(t *testing.T) {
		svc, _ := newTestServer(t)
		_, err := svc.CreatePolicy(context.Background(), &adminv1.CreatePolicyRequest{})
		assertCode(t, err, codes.InvalidArgument)
	})

	t.Run("invalid SPIFFE ID returns InvalidArgument", func(t *testing.T) {
		svc, _ := newTestServer(t)
		_, err := svc.CreatePolicy(context.Background(), &adminv1.CreatePolicyRequest{
			Rule: newRule("bad", "not-a-spiffe-id", tgt),
		})
		assertCode(t, err, codes.InvalidArgument)
	})

	t.Run("duplicate name in YAML returns AlreadyExists", func(t *testing.T) {
		svc, _ := newTestServer(t)
		_, err := svc.CreatePolicy(context.Background(), &adminv1.CreatePolicyRequest{
			Rule: newRule("yaml-policy", subB, tgt2),
		})
		assertCode(t, err, codes.AlreadyExists)
	})

	t.Run("duplicate subject+target in YAML returns AlreadyExists", func(t *testing.T) {
		svc, _ := newTestServer(t)
		_, err := svc.CreatePolicy(context.Background(), &adminv1.CreatePolicyRequest{
			Rule: newRule("other-name", subA, tgt),
		})
		assertCode(t, err, codes.AlreadyExists)
	})

	t.Run("duplicate name in store returns AlreadyExists", func(t *testing.T) {
		svc, _ := newTestServer(t)
		req := &adminv1.CreatePolicyRequest{Rule: newRule("dynamic-policy", subB, tgt)}
		if _, err := svc.CreatePolicy(context.Background(), req); err != nil {
			t.Fatalf("first create: %v", err)
		}
		_, err := svc.CreatePolicy(context.Background(), &adminv1.CreatePolicyRequest{
			Rule: newRule("dynamic-policy", subC, tgt2),
		})
		assertCode(t, err, codes.AlreadyExists)
	})
}

func TestDeletePolicy(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, store := newTestServer(t)
		// seed a dynamic policy
		if err := store.Save(policy.Policy{
			Name: "dyn", Subject: subB, Target: tgt2,
			AllowedScopes: []string{"read"}, MaxTTL: 60,
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if _, err := svc.DeletePolicy(context.Background(), &adminv1.DeletePolicyRequest{Name: "dyn"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got, _ := store.List()
		if len(got) != 0 {
			t.Errorf("expected store to be empty, got %+v", got)
		}
	})

	t.Run("empty name returns InvalidArgument", func(t *testing.T) {
		svc, _ := newTestServer(t)
		_, err := svc.DeletePolicy(context.Background(), &adminv1.DeletePolicyRequest{})
		assertCode(t, err, codes.InvalidArgument)
	})

	t.Run("YAML policy returns FailedPrecondition", func(t *testing.T) {
		svc, _ := newTestServer(t)
		_, err := svc.DeletePolicy(context.Background(), &adminv1.DeletePolicyRequest{Name: "yaml-policy"})
		assertCode(t, err, codes.FailedPrecondition)
	})

	t.Run("unknown name returns NotFound", func(t *testing.T) {
		svc, _ := newTestServer(t)
		_, err := svc.DeletePolicy(context.Background(), &adminv1.DeletePolicyRequest{Name: "does-not-exist"})
		assertCode(t, err, codes.NotFound)
	})
}

func TestListPolicies(t *testing.T) {
	svc, store := newTestServer(t)
	if err := store.Save(policy.Policy{
		Name: "dyn", Subject: subB, Target: tgt2,
		AllowedScopes: []string{"read"}, MaxTTL: 60,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	resp, err := svc.ListPolicies(context.Background(), &adminv1.ListPoliciesRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(resp.Policies))
	}

	sources := map[string]string{}
	for _, e := range resp.Policies {
		sources[e.Rule.Name] = e.Source
	}
	if sources["yaml-policy"] != "yaml" {
		t.Errorf("expected yaml-policy source=yaml, got %q", sources["yaml-policy"])
	}
	if sources["dyn"] != "dynamic" {
		t.Errorf("expected dyn source=dynamic, got %q", sources["dyn"])
	}
}

func TestReloadPolicy(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "policy.db")
		store, err := policy.OpenStore(dbPath)
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		t.Cleanup(func() { store.Close() })
		svc := New(
			store,
			func() []policy.Policy { return nil },
			func(_ *policy.Loader) {},
			func() error { return nil },
			func(_ string, _ time.Time) bool { return true },
		)
		if _, err := svc.ReloadPolicy(context.Background(), &adminv1.ReloadPolicyRequest{}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("reload error returns Internal", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "policy.db")
		store, err := policy.OpenStore(dbPath)
		if err != nil {
			t.Fatalf("open store: %v", err)
		}
		t.Cleanup(func() { store.Close() })
		svc := New(
			store,
			func() []policy.Policy { return nil },
			func(_ *policy.Loader) {},
			func() error { return errors.New("bad yaml") },
			func(_ string, _ time.Time) bool { return true },
		)
		_, err = svc.ReloadPolicy(context.Background(), &adminv1.ReloadPolicyRequest{})
		assertCode(t, err, codes.Internal)
	})
}

func TestRevokeToken(t *testing.T) {
	t.Run("empty token_id returns InvalidArgument", func(t *testing.T) {
		svc, _ := newTestServer(t)
		_, err := svc.RevokeToken(context.Background(), &adminv1.RevokeTokenRequest{ExpiresAt: time.Now().Add(time.Minute).Unix()})
		assertCode(t, err, codes.InvalidArgument)
	})

	t.Run("zero expires_at returns InvalidArgument", func(t *testing.T) {
		svc, _ := newTestServer(t)
		_, err := svc.RevokeToken(context.Background(), &adminv1.RevokeTokenRequest{TokenId: "some-jti"})
		assertCode(t, err, codes.InvalidArgument)
	})

	t.Run("valid request persists and calls revoke callback", func(t *testing.T) {
		var revoked []string
		svc, store := newTestServerWithRevoke(t, func(jti string, _ time.Time) bool { revoked = append(revoked, jti); return true })

		exp := time.Now().Add(time.Minute).Unix()
		_, err := svc.RevokeToken(context.Background(), &adminv1.RevokeTokenRequest{
			TokenId:   "test-jti",
			ExpiresAt: exp,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Callback was called.
		if len(revoked) != 1 || revoked[0] != "test-jti" {
			t.Errorf("revoke callback: got %v, want [test-jti]", revoked)
		}

		// Entry persisted in store.
		entries, err := store.ListRevocations()
		if err != nil {
			t.Fatalf("list revocations: %v", err)
		}
		if len(entries) != 1 || entries[0].JTI != "test-jti" || entries[0].ExpiresAt != exp {
			t.Errorf("store entries: got %+v", entries)
		}
	})
}

func TestListRevokedTokens(t *testing.T) {
	t.Run("empty store returns empty list", func(t *testing.T) {
		svc, _ := newTestServer(t)
		resp, err := svc.ListRevokedTokens(context.Background(), &adminv1.ListRevokedTokensRequest{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.Tokens) != 0 {
			t.Errorf("expected 0 tokens, got %d", len(resp.Tokens))
		}
	})

	t.Run("expired entry is filtered out", func(t *testing.T) {
		svc, store := newTestServer(t)
		if err := store.SaveRevocation("expired-jti", time.Now().Add(-time.Minute).Unix()); err != nil {
			t.Fatalf("seed: %v", err)
		}
		resp, err := svc.ListRevokedTokens(context.Background(), &adminv1.ListRevokedTokensRequest{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.Tokens) != 0 {
			t.Errorf("expected expired entry to be filtered, got %+v", resp.Tokens)
		}
	})

	t.Run("active entry is returned", func(t *testing.T) {
		svc, store := newTestServer(t)
		exp := time.Now().Add(time.Minute).Unix()
		if err := store.SaveRevocation("active-jti", exp); err != nil {
			t.Fatalf("seed: %v", err)
		}
		resp, err := svc.ListRevokedTokens(context.Background(), &adminv1.ListRevokedTokensRequest{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.Tokens) != 1 || resp.Tokens[0].TokenId != "active-jti" || resp.Tokens[0].ExpiresAt != exp {
			t.Errorf("expected active-jti, got %+v", resp.Tokens)
		}
	})

	t.Run("mixed entries returns only active", func(t *testing.T) {
		svc, store := newTestServer(t)
		if err := store.SaveRevocation("expired-jti", time.Now().Add(-time.Minute).Unix()); err != nil {
			t.Fatalf("seed expired: %v", err)
		}
		if err := store.SaveRevocation("active-jti", time.Now().Add(time.Minute).Unix()); err != nil {
			t.Fatalf("seed active: %v", err)
		}
		resp, err := svc.ListRevokedTokens(context.Background(), &adminv1.ListRevokedTokensRequest{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.Tokens) != 1 || resp.Tokens[0].TokenId != "active-jti" {
			t.Errorf("expected only active-jti, got %+v", resp.Tokens)
		}
	})
}

func assertCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %v, got nil", want)
	}
	if got := status.Code(err); got != want {
		t.Errorf("expected code %v, got %v: %v", want, got, err)
	}
}
