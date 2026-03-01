// Command server starts the svid-exchange gRPC service and HTTP health endpoints.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
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

	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

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
	// mTLS is mandatory — the service is SPIFFE-native.
	// SPIFFE_ENDPOINT_SOCKET must point to the SPIRE Workload API socket.
	// X509Source fetches and rotates the SVID automatically; every TLS
	// handshake picks up the latest certificate without a process restart.
	spiffeSocket := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	if spiffeSocket == "" {
		log.Fatal().Msg("SPIFFE_ENDPOINT_SOCKET must be set")
	}

	src, err := workloadapi.NewX509Source(
		rootCtx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(spiffeSocket)),
	)
	if err != nil {
		log.Fatal().Err(err).Str("socket", spiffeSocket).Msg("connect to SPIRE Workload API")
	}

	tlsCfg := tlsconfig.MTLSServerConfig(src, src, tlsconfig.AuthorizeAny())
	tlsCfg.MinVersion = tls.VersionTLS13

	serverOpts := []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsCfg))}
	log.Info().Str("socket", spiffeSocket).Msg("mTLS via SPIRE Workload API")

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
	rootCancel()              // stop Workload API watcher
	grpcServer.GracefulStop() // drain in-flight RPCs (source still serves from cache)
	if err := src.Close(); err != nil {
		log.Error().Err(err).Msg("close X509Source")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()
	if err := healthServer.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("health server shutdown error")
	}

	log.Info().Msg("stopped")
}
