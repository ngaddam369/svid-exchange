// Package spiffe extracts and verifies SPIFFE SVIDs from mTLS peer certificates.
package spiffe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

const spiffeScheme = "spiffe"

var (
	ErrNoPeerInfo = errors.New("no peer info in context")
	ErrNoTLSInfo  = errors.New("peer has no TLS auth info")
	ErrNoCerts    = errors.New("peer presented no certificates")
	ErrNoSPIFFEID = errors.New("peer certificate contains no SPIFFE SAN URI")
)

// ExtractID pulls the SPIFFE ID from the first URI SAN on the peer's leaf
// certificate. It returns an error if no SPIFFE URI is found.
//
// In a real deployment this would use go-spiffe's x509bundle verification;
// for the MVP we perform structural validation only and delegate trust to the
// mTLS handshake configured at the gRPC server level.
func ExtractID(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", ErrNoPeerInfo
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", ErrNoTLSInfo
	}

	return extractFromTLSState(tlsInfo.State)
}

func extractFromTLSState(state tls.ConnectionState) (string, error) {
	if len(state.PeerCertificates) == 0 {
		return "", ErrNoCerts
	}
	leaf := state.PeerCertificates[0]
	for _, uri := range leaf.URIs {
		if uri.Scheme == spiffeScheme {
			if err := validateSPIFFEID(uri); err != nil {
				return "", fmt.Errorf("invalid SPIFFE ID %q: %w", uri.String(), err)
			}
			return uri.String(), nil
		}
	}
	return "", ErrNoSPIFFEID
}

// validateSPIFFEID enforces the SPIFFE ID format: spiffe://<trust-domain>/...
func validateSPIFFEID(u *url.URL) error {
	if u.Host == "" {
		return errors.New("missing trust domain")
	}
	return nil
}
