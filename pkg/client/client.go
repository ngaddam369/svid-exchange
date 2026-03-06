// Package client provides a token exchange client for svid-exchange.
//
// Callers use [Client] to obtain scoped JWTs from svid-exchange via SPIFFE mTLS
// and inject them into outgoing gRPC requests. Receivers use [Verifier] to
// validate those JWTs using the JWKS endpoint.
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	exchangev1 "github.com/ngaddam369/svid-exchange/proto/exchange/v1"
)

// exchanger is the interface backed by the generated gRPC client in production
// and by a test double in tests. It matches exchangev1.TokenExchangeClient.
type exchanger interface {
	Exchange(ctx context.Context, in *exchangev1.ExchangeRequest, opts ...grpc.CallOption) (*exchangev1.ExchangeResponse, error)
}

// Options configures a [Client].
type Options struct {
	// Addr is the svid-exchange gRPC server address (e.g. "localhost:8080").
	Addr string
	// SpiffeSocket is the SPIFFE Workload API socket path
	// (e.g. "unix:///tmp/agent.sock"). When empty the value of the
	// SPIFFE_ENDPOINT_SOCKET environment variable is used instead.
	SpiffeSocket string
	// TargetService is the SPIFFE ID of the service this client calls.
	TargetService string
	// Scopes are the permission scopes to request.
	Scopes []string
	// TTLSeconds is the requested token lifetime. 0 lets the policy decide.
	TTLSeconds int32
}

// Client fetches scoped JWTs from svid-exchange and caches them until close to
// expiry. A zero-value Client is not usable; use [New].
type Client struct {
	exc  exchanger
	conn *grpc.ClientConn        // non-nil only when created by New
	src  *workloadapi.X509Source // non-nil only when created by New
	opts Options

	cached struct {
		mu        sync.Mutex
		token     string
		exp       time.Time
		refreshAt time.Time
	}
}

// New creates a Client that connects to svid-exchange using SPIFFE mTLS.
// The Workload API socket is read from opts.SpiffeSocket, falling back to the
// SPIFFE_ENDPOINT_SOCKET environment variable.
// Call [Client.Close] when done to release the underlying connection and X509Source.
func New(ctx context.Context, opts Options) (*Client, error) {
	socket := opts.SpiffeSocket
	if socket == "" {
		socket = os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	}
	if socket == "" {
		return nil, fmt.Errorf("client: SpiffeSocket or SPIFFE_ENDPOINT_SOCKET must be set")
	}

	src, err := workloadapi.NewX509Source(
		ctx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(socket)),
	)
	if err != nil {
		return nil, fmt.Errorf("client: new X509Source: %w", err)
	}

	tlsCfg := tlsconfig.MTLSClientConfig(src, src, tlsconfig.AuthorizeAny())
	tlsCfg.MinVersion = tls.VersionTLS13

	conn, err := grpc.NewClient(opts.Addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		if e := src.Close(); e != nil {
			return nil, fmt.Errorf("client: dial %q: %w; close source: %v", opts.Addr, err, e)
		}
		return nil, fmt.Errorf("client: dial %q: %w", opts.Addr, err)
	}

	return &Client{
		exc:  exchangev1.NewTokenExchangeClient(conn),
		conn: conn,
		src:  src,
		opts: opts,
	}, nil
}

// Token returns a valid JWT for the configured target and scopes. Cached tokens
// are returned immediately; a new exchange call is made when the token is within
// 20% of its TTL (i.e. refresh triggers at 80% consumed). Concurrent callers
// are serialised: only one exchange call is in flight at a time.
func (c *Client) Token(ctx context.Context) (string, error) {
	c.cached.mu.Lock()
	defer c.cached.mu.Unlock()

	if c.cached.token != "" && time.Now().Before(c.cached.refreshAt) {
		return c.cached.token, nil
	}

	mintTime := time.Now()
	resp, err := c.exc.Exchange(ctx, &exchangev1.ExchangeRequest{
		TargetService: c.opts.TargetService,
		Scopes:        c.opts.Scopes,
		TtlSeconds:    c.opts.TTLSeconds,
	})
	if err != nil {
		return "", fmt.Errorf("client: exchange: %w", err)
	}

	exp := time.Unix(resp.ExpiresAt, 0)
	ttl := exp.Sub(mintTime)
	c.cached.token = resp.Token
	c.cached.exp = exp
	c.cached.refreshAt = exp.Add(-ttl / 5)

	return c.cached.token, nil
}

// GRPCCredentials returns a [credentials.PerRPCCredentials] that injects an
// Authorization: Bearer header on every outgoing gRPC call. Pass the result
// to [grpc.NewClient] via [grpc.WithPerRPCCredentials].
func (c *Client) GRPCCredentials() credentials.PerRPCCredentials {
	return perRPCCreds{c: c}
}

// Close releases the gRPC connection and X509Source created by [New].
// Safe to call on a Client constructed by test helpers (Close is a no-op then).
func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	if c.src != nil {
		if e := c.src.Close(); err == nil {
			err = e
		}
	}
	return err
}

// perRPCCreds implements [credentials.PerRPCCredentials] by fetching a token
// from the Client and returning it as an Authorization: Bearer header.
type perRPCCreds struct{ c *Client }

func (p perRPCCreds) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	tok, err := p.c.Token(ctx)
	if err != nil {
		return nil, err
	}
	return map[string]string{"authorization": "Bearer " + tok}, nil
}

func (perRPCCreds) RequireTransportSecurity() bool { return true }
