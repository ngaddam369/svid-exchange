// Command server starts the svid-exchange gRPC service and HTTP health endpoints.
package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/ngaddam369/svid-exchange/internal/audit"
	"github.com/ngaddam369/svid-exchange/internal/policy"
	"github.com/ngaddam369/svid-exchange/internal/server"
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
	auditLog := audit.New()

	// --- gRPC server ---
	// NOTE: mTLS is required in production. For the MVP the server runs without
	// TLS to allow local testing without a SPIRE agent. See TODO.md.
	grpcServer := grpc.NewServer()
	svc := server.New(pl, minter, auditLog)
	exchangev1.RegisterTokenExchangeServer(grpcServer, svc)
	reflection.Register(grpcServer)

	grpcLis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		log.Fatal().Err(err).Str("addr", grpcAddr).Msg("listen gRPC")
	}

	// --- Health HTTP server ---
	ready := true // ready once policy + minter are initialised (already done above)
	mux := http.NewServeMux()
	mux.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/health/ready", func(w http.ResponseWriter, _ *http.Request) {
		if ready {
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
	ready = false

	grpcServer.GracefulStop()

	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := healthServer.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("health server shutdown error")
	}

	log.Info().Msg("stopped")
}
