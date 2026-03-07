package client

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

type mockTokenSource struct {
	token *oauth2.Token
	err   error
}

func (m *mockTokenSource) Token() (*oauth2.Token, error) {
	return m.token, m.err
}

func TestExchangeForGCPToken(t *testing.T) {
	expiry := time.Date(2030, 6, 1, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		mock    *mockTokenSource
		wantErr bool
		check   func(t *testing.T, got *GCPToken)
	}{
		{
			name: "returns access token on success",
			mock: &mockTokenSource{
				token: &oauth2.Token{
					AccessToken: "ya29.example",
					Expiry:      expiry,
				},
			},
			check: func(t *testing.T, got *GCPToken) {
				t.Helper()
				if got.AccessToken != "ya29.example" {
					t.Errorf("AccessToken = %q, want %q", got.AccessToken, "ya29.example")
				}
				if !got.Expiry.Equal(expiry) {
					t.Errorf("Expiry = %v, want %v", got.Expiry, expiry)
				}
			},
		},
		{
			name:    "token source error propagates",
			mock:    &mockTokenSource{err: errors.New("gcp sts unavailable")},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := gcpTokenFromSource(tc.mock)
			if (err != nil) != tc.wantErr {
				t.Fatalf("gcpTokenFromSource() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.check != nil && got != nil {
				tc.check(t, got)
			}
		})
	}
}
