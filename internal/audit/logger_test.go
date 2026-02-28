package audit

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestLogExchange(t *testing.T) {
	tests := []struct {
		name       string
		event      ExchangeEvent
		wantFields map[string]any
		absentKeys []string
	}{
		{
			name: "granted",
			event: ExchangeEvent{
				Subject:         "spiffe://cluster.local/ns/default/sa/order",
				Target:          "spiffe://cluster.local/ns/default/sa/payment",
				ScopesRequested: []string{"payments:charge"},
				ScopesGranted:   []string{"payments:charge"},
				Granted:         true,
				TTL:             300,
				TokenID:         "test-jti-123",
			},
			wantFields: map[string]any{
				"event":    "token.exchange",
				"subject":  "spiffe://cluster.local/ns/default/sa/order",
				"target":   "spiffe://cluster.local/ns/default/sa/payment",
				"granted":  true,
				"ttl":      float64(300),
				"token_id": "test-jti-123",
			},
			absentKeys: []string{"denial_reason"},
		},
		{
			name: "denied",
			event: ExchangeEvent{
				Subject:         "spiffe://cluster.local/ns/default/sa/order",
				Target:          "spiffe://cluster.local/ns/default/sa/admin",
				ScopesRequested: []string{"admin:delete"},
				Granted:         false,
				DenialReason:    "no policy permits order → admin",
			},
			wantFields: map[string]any{
				"granted":       false,
				"denial_reason": "no policy permits order → admin",
			},
			absentKeys: []string{"token_id", "ttl"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			l := New(&buf)
			l.LogExchange(tc.event)

			var entry map[string]any
			if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
				t.Fatalf("output is not valid JSON: %v\noutput: %s", err, buf.String())
			}

			for k, want := range tc.wantFields {
				if got := entry[k]; got != want {
					t.Errorf("field %q = %v, want %v", k, got, want)
				}
			}
			for _, k := range tc.absentKeys {
				if _, ok := entry[k]; ok {
					t.Errorf("field %q should not be present", k)
				}
			}
		})
	}
}
