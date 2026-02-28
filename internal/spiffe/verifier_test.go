package spiffe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// certWithURI builds a bare x509.Certificate with the given SPIFFE URI SAN.
// No crypto: extractFromTLSState only reads the URIs field.
func certWithURI(t *testing.T, spiffeID string) *x509.Certificate {
	t.Helper()
	u, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatalf("parse SPIFFE URI %q: %v", spiffeID, err)
	}
	return &x509.Certificate{URIs: []*url.URL{u}}
}

func ctxWithTLS(certs ...*x509.Certificate) context.Context {
	p := &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{PeerCertificates: certs},
		},
	}
	return peer.NewContext(context.Background(), p)
}

func TestExtractFromTLSState(t *testing.T) {
	tests := []struct {
		name    string
		state   tls.ConnectionState
		wantID  string // set on success
		wantErr error  // set when a specific sentinel error is expected
		// if both are zero, any non-nil error is accepted
	}{
		{
			name: "valid SPIFFE URI",
			state: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{
					certWithURI(t, "spiffe://cluster.local/ns/default/sa/order"),
				},
			},
			wantID: "spiffe://cluster.local/ns/default/sa/order",
		},
		{
			name:    "no certs",
			state:   tls.ConnectionState{},
			wantErr: ErrNoCerts,
		},
		{
			name: "no SPIFFE URI SAN",
			state: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{{}},
			},
			wantErr: ErrNoSPIFFEID,
		},
		{
			name: "missing trust domain",
			state: tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{
					certWithURI(t, "spiffe://"),
				},
			},
			// structurally invalid — any error accepted
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractFromTLSState(tc.state)
			switch {
			case tc.wantID != "":
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tc.wantID {
					t.Errorf("got %q, want %q", got, tc.wantID)
				}
			case tc.wantErr != nil:
				if err != tc.wantErr {
					t.Errorf("got %v, want %v", err, tc.wantErr)
				}
			default:
				if err == nil {
					t.Error("expected error, got nil")
				}
			}
		})
	}
}

func TestExtractID(t *testing.T) {
	tests := []struct {
		name    string
		ctx     context.Context
		wantID  string
		wantErr error
	}{
		{
			name:    "no peer info in context",
			ctx:     context.Background(),
			wantErr: ErrNoPeerInfo,
		},
		{
			name:    "peer has no TLS auth info",
			ctx:     peer.NewContext(context.Background(), &peer.Peer{}),
			wantErr: ErrNoTLSInfo,
		},
		{
			name:   "valid SPIFFE URI",
			ctx:    ctxWithTLS(certWithURI(t, "spiffe://cluster.local/ns/default/sa/order")),
			wantID: "spiffe://cluster.local/ns/default/sa/order",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExtractID(tc.ctx)
			switch {
			case tc.wantID != "":
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != tc.wantID {
					t.Errorf("got %q, want %q", got, tc.wantID)
				}
			case tc.wantErr != nil:
				if err != tc.wantErr {
					t.Errorf("got %v, want %v", err, tc.wantErr)
				}
			default:
				if err == nil {
					t.Error("expected error, got nil")
				}
			}
		})
	}
}
