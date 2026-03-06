package integration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/ngaddam369/svid-exchange/internal/audit"
	"github.com/ngaddam369/svid-exchange/internal/policy"
	"github.com/ngaddam369/svid-exchange/internal/server"
	"github.com/ngaddam369/svid-exchange/internal/spiffe"
	"github.com/ngaddam369/svid-exchange/internal/token"
	exchangev1 "github.com/ngaddam369/svid-exchange/proto/exchange/v1"
)

// testEnv holds the running in-process gRPC server's address, signing minter,
// and the test CA material needed to mint additional client certificates.
type testEnv struct {
	addr   string
	minter *token.Minter
	rootCA *x509.CertPool
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
}

// newCA generates a self-signed ECDSA P-256 certificate authority.
func newCA(t *testing.T) (*x509.CertPool, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pool, caCert, key
}

// newClientCert generates an ECDSA P-256 leaf certificate for client auth,
// signed by the given CA. When spiffeURI is non-empty it is embedded as a
// URI SAN; when empty the cert carries no SPIFFE ID (for the unauthenticated
// test case).
func newClientCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, spiffeURI string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if spiffeURI != "" {
		u, err := url.Parse(spiffeURI)
		if err != nil {
			t.Fatalf("parse SPIFFE URI %q: %v", spiffeURI, err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("build tls.Certificate: %v", err)
	}
	return tlsCert
}

// newTestEnv starts an in-process gRPC server wired with real dependencies:
// spiffe.Extractor, policy.Loader, token.Minter, and audit.Logger. The server
// enforces mTLS — clients must present a certificate signed by the test CA.
func newTestEnv(t *testing.T, policies []policy.Policy) *testEnv {
	t.Helper()
	rootCA, caCert, caKey := newCA(t)

	// Server cert: signed by the test CA with an IP SAN so clients can verify
	// it when connecting to 127.0.0.1.
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	serverTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(10),
		Subject:      pkix.Name{CommonName: "test-server"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTmpl, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create server cert: %v", err)
	}
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	serverKeyBytes, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyBytes})
	serverTLSCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("build server tls.Certificate: %v", err)
	}

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    rootCA,
	}

	loader, err := policy.NewLoader(policies)
	if err != nil {
		t.Fatalf("new policy loader: %v", err)
	}
	minter, err := token.NewMinter()
	if err != nil {
		t.Fatalf("new minter: %v", err)
	}

	svc := server.New(spiffe.Extractor{}, loader, minter, audit.New(io.Discard))

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	grpcSrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	exchangev1.RegisterTokenExchangeServer(grpcSrv, svc)
	go grpcSrv.Serve(lis)
	t.Cleanup(grpcSrv.GracefulStop)

	return &testEnv{
		addr:   lis.Addr().String(),
		minter: minter,
		rootCA: rootCA,
		caCert: caCert,
		caKey:  caKey,
	}
}

// clientAs returns a TokenExchangeClient that presents cert on every call.
func clientAs(t *testing.T, addr string, cert tls.Certificate, rootCA *x509.CertPool) exchangev1.TokenExchangeClient {
	t.Helper()
	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootCA,
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Logf("close conn: %v", err)
		}
	})
	return exchangev1.NewTokenExchangeClient(conn)
}

func TestExchange(t *testing.T) {
	const (
		subjectID = "spiffe://test.local/order"
		targetID  = "spiffe://test.local/payment"
	)

	policies := []policy.Policy{{
		Name:          "order-to-payment",
		Subject:       subjectID,
		Target:        targetID,
		AllowedScopes: []string{"read", "write"},
		MaxTTL:        300,
	}}

	env := newTestEnv(t, policies)
	orderCert := newClientCert(t, env.caCert, env.caKey, subjectID)
	noURICert := newClientCert(t, env.caCert, env.caKey, "") // no SPIFFE URI SAN

	tests := []struct {
		name     string
		cert     tls.Certificate
		req      *exchangev1.ExchangeRequest
		wantCode codes.Code
		check    func(t *testing.T, resp *exchangev1.ExchangeResponse)
	}{
		{
			name: "permitted exchange",
			cert: orderCert,
			req: &exchangev1.ExchangeRequest{
				TargetService: targetID,
				Scopes:        []string{"read"},
				TtlSeconds:    60,
			},
			wantCode: codes.OK,
			check: func(t *testing.T, resp *exchangev1.ExchangeResponse) {
				t.Helper()
				tok, err := jwt.Parse(resp.Token,
					func(_ *jwt.Token) (any, error) { return env.minter.PublicKey(), nil },
					jwt.WithValidMethods([]string{"ES256"}),
					jwt.WithExpirationRequired(),
					jwt.WithAudience(targetID),
				)
				if err != nil {
					t.Fatalf("parse JWT: %v", err)
				}
				claims, ok := tok.Claims.(jwt.MapClaims)
				if !ok {
					t.Fatal("claims not MapClaims")
				}
				if claims["sub"] != subjectID {
					t.Errorf("sub = %v, want %q", claims["sub"], subjectID)
				}
				if claims["scope"] != "read" {
					t.Errorf("scope = %v, want \"read\"", claims["scope"])
				}
			},
		},
		{
			name: "scope intersection",
			cert: orderCert,
			req: &exchangev1.ExchangeRequest{
				TargetService: targetID,
				Scopes:        []string{"read", "unknown"},
				TtlSeconds:    60,
			},
			wantCode: codes.OK,
			check: func(t *testing.T, resp *exchangev1.ExchangeResponse) {
				t.Helper()
				if len(resp.GrantedScopes) != 1 || resp.GrantedScopes[0] != "read" {
					t.Errorf("granted_scopes = %v, want [read]", resp.GrantedScopes)
				}
			},
		},
		{
			name: "TTL capped to policy max",
			cert: orderCert,
			req: &exchangev1.ExchangeRequest{
				TargetService: targetID,
				Scopes:        []string{"read"},
				TtlSeconds:    9999,
			},
			wantCode: codes.OK,
			check: func(t *testing.T, resp *exchangev1.ExchangeResponse) {
				t.Helper()
				expiry := time.Unix(resp.ExpiresAt, 0)
				// max_ttl is 300 s; allow 5 s of grace for test latency.
				maxExpiry := time.Now().Add(305 * time.Second)
				if expiry.After(maxExpiry) {
					t.Errorf("expires_at %v exceeds policy max_ttl (300 s)", expiry)
				}
			},
		},
		{
			name: "no policy for pair",
			cert: orderCert,
			req: &exchangev1.ExchangeRequest{
				TargetService: "spiffe://test.local/inventory",
				Scopes:        []string{"read"},
				TtlSeconds:    60,
			},
			wantCode: codes.PermissionDenied,
		},
		{
			name: "no SPIFFE URI in cert",
			cert: noURICert,
			req: &exchangev1.ExchangeRequest{
				TargetService: targetID,
				Scopes:        []string{"read"},
				TtlSeconds:    60,
			},
			wantCode: codes.Unauthenticated,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			client := clientAs(t, env.addr, tc.cert, env.rootCA)
			resp, err := client.Exchange(ctx, tc.req)
			if status.Code(err) != tc.wantCode {
				t.Fatalf("code = %v, want %v: %v", status.Code(err), tc.wantCode, err)
			}
			if tc.wantCode != codes.OK {
				return
			}
			if resp.Token == "" {
				t.Error("token is empty")
			}
			if tc.check != nil {
				tc.check(t, resp)
			}
		})
	}
}
