package policy

import (
	"os"
	"testing"
)

const testPolicyYAML = `
policies:
  - name: order-to-payment
    subject: "spiffe://cluster.local/ns/default/sa/order"
    target:  "spiffe://cluster.local/ns/default/sa/payment"
    allowed_scopes:
      - payments:charge
      - payments:refund
    max_ttl: 300

  - name: warehouse-to-inventory
    subject: "spiffe://cluster.local/ns/default/sa/warehouse"
    target:  "spiffe://cluster.local/ns/default/sa/inventory"
    allowed_scopes:
      - inventory:read
    max_ttl: 60
`

func newTestLoader(t *testing.T) *Loader {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "policy-*.yaml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.WriteString(testPolicyYAML); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	l, err := LoadFile(f.Name())
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	return l
}

func TestEvaluate(t *testing.T) {
	l := newTestLoader(t)

	tests := []struct {
		name        string
		subject     string
		target      string
		scopes      []string
		ttl         int32
		wantAllowed bool
		wantScopes  []string
		wantTTL     int32
	}{
		{
			name:        "allow exact scopes",
			subject:     "spiffe://cluster.local/ns/default/sa/order",
			target:      "spiffe://cluster.local/ns/default/sa/payment",
			scopes:      []string{"payments:charge", "payments:refund"},
			ttl:         300,
			wantAllowed: true,
			wantScopes:  []string{"payments:charge", "payments:refund"},
			wantTTL:     300,
		},
		{
			name:        "allow subset of scopes",
			subject:     "spiffe://cluster.local/ns/default/sa/order",
			target:      "spiffe://cluster.local/ns/default/sa/payment",
			scopes:      []string{"payments:charge"},
			ttl:         100,
			wantAllowed: true,
			wantScopes:  []string{"payments:charge"},
			wantTTL:     100,
		},
		{
			name:        "ttl capped to max_ttl",
			subject:     "spiffe://cluster.local/ns/default/sa/order",
			target:      "spiffe://cluster.local/ns/default/sa/payment",
			scopes:      []string{"payments:charge"},
			ttl:         9999,
			wantAllowed: true,
			wantScopes:  []string{"payments:charge"},
			wantTTL:     300,
		},
		{
			name:        "zero ttl uses max_ttl",
			subject:     "spiffe://cluster.local/ns/default/sa/order",
			target:      "spiffe://cluster.local/ns/default/sa/payment",
			scopes:      []string{"payments:charge"},
			ttl:         0,
			wantAllowed: true,
			wantScopes:  []string{"payments:charge"},
			wantTTL:     300,
		},
		{
			name:        "deny unknown subject",
			subject:     "spiffe://cluster.local/ns/default/sa/unknown",
			target:      "spiffe://cluster.local/ns/default/sa/payment",
			scopes:      []string{"payments:charge"},
			ttl:         100,
			wantAllowed: false,
		},
		{
			name:        "deny wrong target",
			subject:     "spiffe://cluster.local/ns/default/sa/order",
			target:      "spiffe://cluster.local/ns/default/sa/inventory",
			scopes:      []string{"payments:charge"},
			ttl:         100,
			wantAllowed: false,
		},
		{
			name:        "deny scope not in policy",
			subject:     "spiffe://cluster.local/ns/default/sa/order",
			target:      "spiffe://cluster.local/ns/default/sa/payment",
			scopes:      []string{"admin:delete"},
			ttl:         100,
			wantAllowed: false,
		},
		{
			name:        "filter out disallowed scopes from request",
			subject:     "spiffe://cluster.local/ns/default/sa/order",
			target:      "spiffe://cluster.local/ns/default/sa/payment",
			scopes:      []string{"payments:charge", "admin:delete"},
			ttl:         100,
			wantAllowed: true,
			wantScopes:  []string{"payments:charge"},
			wantTTL:     100,
		},
		{
			name:        "second policy — allow inventory:read",
			subject:     "spiffe://cluster.local/ns/default/sa/warehouse",
			target:      "spiffe://cluster.local/ns/default/sa/inventory",
			scopes:      []string{"inventory:read"},
			ttl:         60,
			wantAllowed: true,
			wantScopes:  []string{"inventory:read"},
			wantTTL:     60,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := l.Evaluate(tc.subject, tc.target, tc.scopes, tc.ttl)
			if result.Allowed != tc.wantAllowed {
				t.Errorf("Allowed = %v, want %v", result.Allowed, tc.wantAllowed)
			}
			if !tc.wantAllowed {
				return
			}
			if len(result.GrantedScopes) != len(tc.wantScopes) {
				t.Errorf("GrantedScopes = %v, want %v", result.GrantedScopes, tc.wantScopes)
			} else {
				for i, s := range tc.wantScopes {
					if result.GrantedScopes[i] != s {
						t.Errorf("GrantedScopes[%d] = %q, want %q", i, result.GrantedScopes[i], s)
					}
				}
			}
			if result.GrantedTTL != tc.wantTTL {
				t.Errorf("GrantedTTL = %d, want %d", result.GrantedTTL, tc.wantTTL)
			}
		})
	}
}
