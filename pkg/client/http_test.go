package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPTransport(t *testing.T) {
	const targetID = "spiffe://test.local/payment"

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "Authorization header injected",
			run: func(t *testing.T) {
				var got string
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					got = r.Header.Get("Authorization")
				}))
				t.Cleanup(srv.Close)

				mock := &mockExchanger{}
				c := newWithExchanger(mock, targetID, []string{"read"}, 60)
				hc := &http.Client{Transport: NewHTTPTransport(c, nil)}

				req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
				resp, err := hc.Do(req)
				if err != nil {
					t.Fatalf("Do: %v", err)
				}
				resp.Body.Close()

				if got != "Bearer mock-token-1" {
					t.Errorf("Authorization = %q, want %q", got, "Bearer mock-token-1")
				}
			},
		},
		{
			name: "token reused from cache on second request",
			run: func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
				t.Cleanup(srv.Close)

				mock := &mockExchanger{}
				c := newWithExchanger(mock, targetID, []string{"read"}, 60)
				hc := &http.Client{Transport: NewHTTPTransport(c, nil)}

				for range 2 {
					req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
					resp, err := hc.Do(req)
					if err != nil {
						t.Fatalf("Do: %v", err)
					}
					resp.Body.Close()
				}

				if n := mock.callCount(); n != 1 {
					t.Errorf("Exchange called %d times, want 1", n)
				}
			},
		},
		{
			name: "Token error propagates",
			run: func(t *testing.T) {
				var requestReceived bool
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requestReceived = true
				}))
				t.Cleanup(srv.Close)

				wantErr := errors.New("exchange failed")
				mock := &mockExchanger{err: wantErr}
				c := newWithExchanger(mock, targetID, []string{"read"}, 60)
				hc := &http.Client{Transport: NewHTTPTransport(c, nil)}

				req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
				_, err := hc.Do(req)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if requestReceived {
					t.Error("request was sent despite token error")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, tc.run)
	}
}
