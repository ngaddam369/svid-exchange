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
	"path/filepath"
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

const shutdownTimeout = 10 * time.Second

func main() {
	log := zerolog.New(os.Stdout).With().Timestamp().Str("service", "svid-exchange").Logger()

	cfg, err := loadConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("load config")
	}

	rootCtx, rootCancel := context.WithCancel(context.Background())
	defer rootCancel()

	// --- Policy ---
	pl, err := policy.LoadFile(cfg.PolicyFile)
	if err != nil {
		log.Fatal().Err(err).Str("path", cfg.PolicyFile).Msg("load policy")
	}
	log.Info().Str("path", cfg.PolicyFile).Msg("policy loaded")
	ap := newAtomicPolicy(pl)

	// --- Policy store (BoltDB) ---
	// Dynamic policies added via the admin API are persisted here and merged
	// with the YAML base on startup and after every ReloadPolicy call.
	if err = os.MkdirAll(filepath.Dir(cfg.PolicyDB), 0o700); err != nil {
		log.Fatal().Err(err).Str("path", cfg.PolicyDB).Msg("create policy db directory")
	}
	store, err := policy.OpenStore(cfg.PolicyDB)
	if err != nil {
		log.Fatal().Err(err).Str("path", cfg.PolicyDB).Msg("open policy store")
	}
	log.Info().Str("path", cfg.PolicyDB).Msg("policy store opened")
	// Merge YAML base with any dynamic policies persisted from a previous run.
	if err = ap.rebuild(store); err != nil {
		log.Fatal().Err(err).Msg("merge policy store")
	}

	// --- Token minter ---
	minter, err := token.NewMinter()
	if err != nil {
		log.Fatal().Err(err).Msg("init minter")
	}

	// --- Signing key rotation ---
	// key_rotation_interval controls how often a new signing key is generated.
	// The outgoing key is retained for one interval so that tokens signed just
	// before a rotation remain verifiable. Zero disables rotation.
	if cfg.KeyRotationInterval > 0 {
		log.Info().Dur("interval", cfg.KeyRotationInterval).Msg("signing key rotation enabled")
		go func() {
			ticker := time.NewTicker(cfg.KeyRotationInterval)
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
	if len(cfg.AuditHMACKey) > 0 {
		log.Info().Msg("audit log HMAC signing enabled")
	}
	auditLog := audit.NewWithHMAC(os.Stdout, cfg.AuditHMACKey)

	// --- Tracing ---
	tracingShutdown, err := initTracing(rootCtx, cfg.OTLPEndpoint)
	if err != nil {
		log.Fatal().Err(err).Msg("init tracing")
	}
	if cfg.OTLPEndpoint != "" {
		log.Info().Str("endpoint", cfg.OTLPEndpoint).Msg("OTLP tracing enabled")
	}

	// --- Rate limiting ---
	if cfg.RateLimitRPS > 0 {
		log.Info().Float64("rps", cfg.RateLimitRPS).Int("burst", cfg.RateLimitBurst).Msg("rate limiting enabled")
	}

	// --- gRPC server ---
	// mTLS is mandatory — the service is SPIFFE-native.
	// SPIFFE_ENDPOINT_SOCKET must point to the SPIRE Workload API socket.
	// X509Source fetches and rotates the SVID automatically; every TLS
	// handshake picks up the latest certificate without a process restart.
	log.Info().Str("socket", cfg.SpiffeSocket).Msg("mTLS via SPIRE Workload API")
	src, err := workloadapi.NewX509Source(
		rootCtx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(cfg.SpiffeSocket)),
	)
	if err != nil {
		log.Fatal().Err(err).Str("socket", cfg.SpiffeSocket).Msg("connect to SPIRE Workload API")
	}

	tlsCfg := tlsconfig.MTLSServerConfig(src, src, tlsconfig.AuthorizeAny())
	tlsCfg.MinVersion = tls.VersionTLS13

	metricsInterceptor := initMetrics()
	rateLimiter := newRateLimitInterceptor(rootCtx, cfg.RateLimitRPS, cfg.RateLimitBurst)
	serverOpts := []grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.UnaryInterceptor(chainUnary(metricsInterceptor, rateLimiter)),
		newTracingServerOption(),
	}

	grpcServer := grpc.NewServer(serverOpts...)
	svc := server.New(spiffe.Extractor{}, ap, minter, auditLog)
	exchangev1.RegisterTokenExchangeServer(grpcServer, svc)
	registerMetrics(grpcServer)

	if cfg.GRPCReflection {
		reflection.Register(grpcServer)
	}

	grpcLis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		log.Fatal().Err(err).Str("addr", cfg.GRPCAddr).Msg("listen gRPC")
	}

	// reloadPolicy re-reads the YAML file and merges it with dynamic policies.
	// Called by the ReloadPolicy admin RPC.
	reloadPolicy := func() error {
		newPolicy, err := policy.LoadFile(cfg.PolicyFile)
		if err != nil {
			return err
		}
		ap.setBase(newPolicy.Policies())
		return ap.rebuild(store)
	}

	// Restore persisted revocations into the in-memory list.
	revocations, err := store.ListRevocations()
	if err != nil {
		log.Fatal().Err(err).Msg("load revocations")
	}
	loaded := 0
	for _, r := range revocations {
		if r.ExpiresAt > time.Now().Unix() {
			svc.Revoke(r.JTI, time.Unix(r.ExpiresAt, 0))
			loaded++
		} else {
			if err := store.DeleteRevocation(r.JTI); err != nil {
				log.Warn().Err(err).Str("jti", r.JTI).Msg("cleanup expired revocation")
			}
		}
	}
	if loaded > 0 {
		log.Info().Int("count", loaded).Msg("revocations restored")
	}

	// --- Admin gRPC server ---
	// Separate listener on admin_addr so it can be network-restricted
	// independently of the data-plane gRPC port.
	// Uses the same mTLS credentials as the data-plane server.
	if len(cfg.AdminSubjects) == 0 {
		log.Warn().Msg("admin_subjects not configured — any authenticated SPIFFE peer may call admin endpoints")
	} else {
		log.Info().Strs("subjects", cfg.AdminSubjects).Msg("admin API RBAC allowlist active")
	}
	adminServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		grpc.UnaryInterceptor(newAdminAuthInterceptor(cfg.AdminSubjects, spiffe.Extractor{})),
	)
	adminSvc := admin.New(store, ap.yamlPolicies, ap.swap, reloadPolicy, svc.Revoke)
	adminv1.RegisterPolicyAdminServer(adminServer, adminSvc)
	if cfg.GRPCReflection {
		reflection.Register(adminServer)
	}
	adminLis, err := net.Listen("tcp", cfg.AdminAddr)
	if err != nil {
		log.Fatal().Err(err).Str("addr", cfg.AdminAddr).Msg("listen admin gRPC")
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
		Addr:              cfg.HealthAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// --- Start ---
	go func() {
		log.Info().Str("addr", cfg.GRPCAddr).Msg("gRPC listening")
		if err := grpcServer.Serve(grpcLis); err != nil {
			log.Error().Err(err).Msg("gRPC serve error")
		}
	}()

	go func() {
		log.Info().Str("addr", cfg.AdminAddr).Msg("admin gRPC listening")
		if err := adminServer.Serve(adminLis); err != nil {
			log.Error().Err(err).Msg("admin gRPC serve error")
		}
	}()

	go func() {
		log.Info().Str("addr", cfg.HealthAddr).Msg("health HTTP listening")
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
	rootCancel()               // stop Workload API watcher
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
