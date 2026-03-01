// Command server starts the svid-exchange gRPC service and HTTP health endpoints.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	"github.com/ngaddam369/svid-exchange/internal/audit"
	"github.com/ngaddam369/svid-exchange/internal/policy"
	"github.com/ngaddam369/svid-exchange/internal/server"
	"github.com/ngaddam369/svid-exchange/internal/spiffe"
	"github.com/ngaddam369/svid-exchange/internal/token"
	exchangev1 "github.com/ngaddam369/svid-exchange/proto/exchange/v1"
)

const (
	defaultGRPCAddr   = ":8080"
	defaultHealthAddr = ":8081"
	shutdownTimeout   = 10 * time.Second
)

func main() {
	log := zerolog.New(os.Stdout).With().Timestamp().Str("service", "svid-exchange").Logger()

	policyPath := os.Getenv("POLICY_FILE")
	if policyPath == "" {
		policyPath = "config/policy.example.yaml"
	}

	grpcAddr := os.Getenv("GRPC_ADDR")
	if grpcAddr == "" {
		grpcAddr = defaultGRPCAddr
	}

	healthAddr := os.Getenv("HEALTH_ADDR")
	if healthAddr == "" {
		healthAddr = defaultHealthAddr
	}

	// --- Policy ---
	pl, err := policy.LoadFile(policyPath)
	if err != nil {
		log.Fatal().Err(err).Str("path", policyPath).Msg("load policy")
	}
	log.Info().Str("path", policyPath).Msg("policy loaded")

	// --- Token minter ---
	minter, err := token.NewMinter()
	if err != nil {
		log.Fatal().Err(err).Msg("init minter")
	}

	// --- Audit logger ---
	auditLog := audit.New(os.Stdout)

	// --- gRPC server ---
	// mTLS is mandatory — TLS_CERT_FILE, TLS_KEY_FILE, TLS_CA_FILE must all be set.
	// The service cannot start without them: identity extraction depends on the
	// peer certificate presented during the TLS handshake.
	tlsCert := os.Getenv("TLS_CERT_FILE")
	tlsKey := os.Getenv("TLS_KEY_FILE")
	tlsCA := os.Getenv("TLS_CA_FILE")

	if tlsCert == "" || tlsKey == "" || tlsCA == "" {
		log.Fatal().Msg("TLS_CERT_FILE, TLS_KEY_FILE, and TLS_CA_FILE must all be set — plaintext mode is not supported")
	}

	tlsConfig, err := buildMTLSConfig(tlsCert, tlsKey, tlsCA)
	if err != nil {
		log.Fatal().Err(err).Msg("build mTLS config")
	}
	serverOpts := []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsConfig))}
	log.Info().Msg("mTLS enabled")

	grpcServer := grpc.NewServer(serverOpts...)
	svc := server.New(spiffe.Extractor{}, pl, minter, auditLog)
	exchangev1.RegisterTokenExchangeServer(grpcServer, svc)

	if os.Getenv("GRPC_REFLECTION") != "false" {
		reflection.Register(grpcServer)
	}

	grpcLis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		log.Fatal().Err(err).Str("addr", grpcAddr).Msg("listen gRPC")
	}

	// --- Health HTTP server ---
	var ready atomic.Bool
	ready.Store(true) // ready once policy + minter are initialised (already done above)
	mux := http.NewServeMux()
	mux.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, _ *http.Request) {
		if ready.Load() {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	healthServer := &http.Server{
		Addr:    healthAddr,
		Handler: mux,
	}

	// --- Start ---
	go func() {
		log.Info().Str("addr", grpcAddr).Msg("gRPC listening")
		if err := grpcServer.Serve(grpcLis); err != nil {
			log.Error().Err(err).Msg("gRPC serve error")
		}
	}()

	go func() {
		log.Info().Str("addr", healthAddr).Msg("health HTTP listening")
		if err := healthServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error().Err(err).Msg("health serve error")
		}
	}()

	// --- Graceful shutdown ---
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("shutting down")
	ready.Store(false)

	grpcServer.GracefulStop()

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := healthServer.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("health server shutdown error")
	}

	log.Info().Msg("stopped")
}

// buildMTLSConfig creates a TLS config requiring client certificate verification
// against the provided CA. This is the transport-layer complement to the
// SPIFFE ID extraction done at the application layer in spiffe/verifier.go.
func buildMTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server key pair: %w", err)
	}

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("parse CA cert: no valid certificates found")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
