// Command server starts the svid-exchange gRPC service and HTTP health endpoints.
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	"github.com/ngaddam369/svid-exchange/internal/admin"
	"github.com/ngaddam369/svid-exchange/internal/audit"
	"github.com/ngaddam369/svid-exchange/internal/policy"
	"github.com/ngaddam369/svid-exchange/internal/server"
	"github.com/ngaddam369/svid-exchange/internal/spiffe"
	"github.com/ngaddam369/svid-exchange/internal/token"
	adminv1 "github.com/ngaddam369/svid-exchange/proto/admin/v1"
	exchangev1 "github.com/ngaddam369/svid-exchange/proto/exchange/v1"
)

const (
	defaultGRPCAddr   = ":8080"
	defaultHealthAddr = ":8081"
	defaultAdminAddr  = ":8082"
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

	adminAddr := os.Getenv("ADMIN_ADDR")
	if adminAddr == "" {
		adminAddr = defaultAdminAddr
	}

	// --- Policy ---
	pl, err := policy.LoadFile(policyPath)
	if err != nil {
		log.Fatal().Err(err).Str("path", policyPath).Msg("load policy")
	}
	log.Info().Str("path", policyPath).Msg("policy loaded")
	ap := newAtomicPolicy(pl)

	// --- Policy store (BoltDB) ---
	// Dynamic policies added via the admin API are persisted here and merged
	// with the YAML base on startup and after every SIGHUP reload.
	policyDBPath := os.Getenv("POLICY_DB")
	if policyDBPath == "" {
		policyDBPath = "data/policy.db"
	}
	if err := os.MkdirAll(filepath.Dir(policyDBPath), 0o700); err != nil {
		log.Fatal().Err(err).Str("path", policyDBPath).Msg("create policy db directory")
	}
	store, err := policy.OpenStore(policyDBPath)
	if err != nil {
		log.Fatal().Err(err).Str("path", policyDBPath).Msg("open policy store")
	}
	log.Info().Str("path", policyDBPath).Msg("policy store opened")
	// Merge YAML base with any dynamic policies persisted from a previous run.
	if err := ap.rebuild(store); err != nil {
		log.Fatal().Err(err).Msg("merge policy store")
	}

	// --- Token minter ---
	minter, err := token.NewMinter()
	if err != nil {
		log.Fatal().Err(err).Msg("init minter")
	}

	// --- Signing key rotation ---
	// KEY_ROTATION_INTERVAL controls how often a new signing key is generated.
	// The outgoing key is retained for one interval so that tokens signed just
	// before a rotation remain verifiable. Unset or empty disables rotation.
	var rotationInterval time.Duration
	if v := os.Getenv("KEY_ROTATION_INTERVAL"); v != "" {
		if rotationInterval, err = time.ParseDuration(v); err != nil {
			log.Fatal().Err(err).Str("value", v).Msg("invalid KEY_ROTATION_INTERVAL")
		}
	}
	if rotationInterval > 0 {
		log.Info().Dur("interval", rotationInterval).Msg("signing key rotation enabled")
		go func() {
			ticker := time.NewTicker(rotationInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					if err := minter.Rotate(); err != nil {
						log.Error().Err(err).Msg("signing key rotation failed")
						continue
					}
					log.Info().Msg("signing key rotated")
				case <-rootCtx.Done():
					return
				}
			}
		}()
	}

	// --- Audit logger ---
	var auditKey []byte
	if v := os.Getenv("AUDIT_HMAC_KEY"); v != "" {
		if auditKey, err = hex.DecodeString(v); err != nil {
			log.Fatal().Err(err).Msg("invalid AUDIT_HMAC_KEY: must be hex-encoded")
		}
		if len(auditKey) != 32 {
			log.Fatal().Int("bytes", len(auditKey)).Msg("AUDIT_HMAC_KEY must be 32 bytes (64 hex chars)")
		}
		log.Info().Msg("audit log HMAC signing enabled")
	}
	auditLog := audit.NewWithHMAC(os.Stdout, auditKey)

	// --- Tracing ---
	tracingShutdown, err := initTracing(rootCtx)
	if err != nil {
		log.Fatal().Err(err).Msg("init tracing")
	}
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" {
		log.Info().Str("endpoint", os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")).Msg("OTLP tracing enabled")
	}

	// --- Rate limiting ---
	var rps float64
	if v := os.Getenv("RATE_LIMIT_RPS"); v != "" {
		if rps, err = strconv.ParseFloat(v, 64); err != nil {
			log.Fatal().Err(err).Str("value", v).Msg("invalid RATE_LIMIT_RPS")
		}
	}
	var burst int
	if v := os.Getenv("RATE_LIMIT_BURST"); v != "" {
		if burst, err = strconv.Atoi(v); err != nil {
			log.Fatal().Err(err).Str("value", v).Msg("invalid RATE_LIMIT_BURST")
		}
	}
	if burst <= 0 && rps > 0 {
		burst = int(math.Ceil(rps))
	}
	if rps > 0 {
		log.Info().Float64("rps", rps).Int("burst", burst).Msg("rate limiting enabled")
	}

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

	metricsInterceptor := initMetrics()
	rateLimiter := newRateLimitInterceptor(rps, burst)
	serverOpts := []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.UnaryInterceptor(chainUnary(metricsInterceptor, rateLimiter)),
		newTracingServerOption(),
	}
	log.Info().Str("socket", spiffeSocket).Msg("mTLS via SPIRE Workload API")

	grpcServer := grpc.NewServer(serverOpts...)
	svc := server.New(spiffe.Extractor{}, ap, minter, auditLog)
	exchangev1.RegisterTokenExchangeServer(grpcServer, svc)
	registerMetrics(grpcServer)

	if os.Getenv("GRPC_REFLECTION") != "false" {
		reflection.Register(grpcServer)
	}

	grpcLis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		log.Fatal().Err(err).Str("addr", grpcAddr).Msg("listen gRPC")
	}

	// --- Policy hot-reload closure ---
	// reloadPolicy re-reads the YAML file and merges it with dynamic policies.
	// Called by both SIGHUP and the ReloadPolicy admin RPC.
	reloadPolicy := func() error {
		newPolicy, err := policy.LoadFile(policyPath)
		if err != nil {
			return err
		}
		ap.setBase(newPolicy.Policies())
		return ap.rebuild(store)
	}

	// --- Admin gRPC server ---
	// Separate listener on ADMIN_ADDR so it can be network-restricted
	// independently of the data-plane gRPC port.
	// Uses the same mTLS credentials as the data-plane server.
	adminServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	adminSvc := admin.New(store, ap.yamlPolicies, ap.swap, reloadPolicy)
	adminv1.RegisterPolicyAdminServer(adminServer, adminSvc)
	if os.Getenv("GRPC_REFLECTION") != "false" {
		reflection.Register(adminServer)
	}
	adminLis, err := net.Listen("tcp", adminAddr)
	if err != nil {
		log.Fatal().Err(err).Str("addr", adminAddr).Msg("listen admin gRPC")
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
	mux.HandleFunc("/jwks", newJWKSHandler(minter, log))
	mux.Handle("/metrics", newMetricsHandler())
	healthServer := &http.Server{
		Addr:    healthAddr,
		Handler: mux,
	}

	// --- Policy hot-reload ---
	// Send SIGHUP to reload the policy file without restarting the process.
	// If the new file is invalid the existing policy stays active.
	// Dynamic policies from the store are preserved across reloads.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-hup:
				if err := reloadPolicy(); err != nil {
					log.Error().Err(err).Str("path", policyPath).Msg("policy reload failed, keeping existing policy")
					continue
				}
				log.Info().Str("path", policyPath).Msg("policy reloaded")
			case <-rootCtx.Done():
				return
			}
		}
	}()

	// --- Start ---
	go func() {
		log.Info().Str("addr", grpcAddr).Msg("gRPC listening")
		if err := grpcServer.Serve(grpcLis); err != nil {
			log.Error().Err(err).Msg("gRPC serve error")
		}
	}()

	go func() {
		log.Info().Str("addr", adminAddr).Msg("admin gRPC listening")
		if err := adminServer.Serve(adminLis); err != nil {
			log.Error().Err(err).Msg("admin gRPC serve error")
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
	signal.Stop(hup)
	rootCancel()               // stop Workload API watcher + SIGHUP goroutine
	grpcServer.GracefulStop()  // drain in-flight RPCs (source still serves from cache)
	adminServer.GracefulStop() // drain in-flight admin RPCs
	if err := store.Close(); err != nil {
		log.Error().Err(err).Msg("close policy store")
	}
	if err := src.Close(); err != nil {
		log.Error().Err(err).Msg("close X509Source")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()
	if err := tracingShutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("flush traces")
	}
	if err := healthServer.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("health server shutdown error")
	}

	log.Info().Msg("stopped")
}
