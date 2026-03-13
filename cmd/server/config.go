package main

import (
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultConfigFile = "config/server.yaml"
	defaultGRPCAddr   = ":8080"
	defaultHealthAddr = ":8081"
	defaultAdminAddr  = ":8082"
	defaultPolicyFile = "config/policy.example.yaml"
	defaultPolicyDB   = "data/policy.db"
)

// Config holds all resolved configuration values for the server.
// Non-secret values come from the YAML config file; secrets and
// deployment-specific paths come from environment variables only.
type Config struct {
	GRPCAddr            string
	HealthAddr          string
	AdminAddr           string
	PolicyFile          string
	PolicyDB            string
	GRPCReflection      bool
	OTLPEndpoint        string
	RateLimitRPS        float64
	RateLimitBurst      int
	KeyRotationInterval time.Duration
	SpiffeSocket        string
	AuditHMACKey        []byte
	AdminSubjects       []string
}

// configFile mirrors the YAML structure of config/server.yaml.
// KeyRotationInterval is kept as a string for parsing via time.ParseDuration.
type configFile struct {
	GRPCAddr            string   `yaml:"grpc_addr"`
	HealthAddr          string   `yaml:"health_addr"`
	AdminAddr           string   `yaml:"admin_addr"`
	GRPCReflection      bool     `yaml:"grpc_reflection"`
	OTLPEndpoint        string   `yaml:"otlp_endpoint"`
	RateLimitRPS        float64  `yaml:"rate_limit_rps"`
	RateLimitBurst      int      `yaml:"rate_limit_burst"`
	KeyRotationInterval string   `yaml:"key_rotation_interval"`
	AdminSubjects       []string `yaml:"admin_subjects"`
}

// loadConfig reads the YAML config file (path from CONFIG_FILE env var,
// default "config/server.yaml"), applies POLICY_FILE / POLICY_DB env var
// overrides, and reads secrets from environment variables only.
// Returns an error if the config file is missing or malformed, if
// SPIFFE_ENDPOINT_SOCKET is unset, or if AUDIT_HMAC_KEY is invalid.
func loadConfig() (Config, error) {
	cfgPath := os.Getenv("CONFIG_FILE")
	if cfgPath == "" {
		cfgPath = defaultConfigFile
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		return Config{}, fmt.Errorf("read config file %q: %w", cfgPath, err)
	}

	var f configFile
	if err = yaml.Unmarshal(data, &f); err != nil {
		return Config{}, fmt.Errorf("parse config file %q: %w", cfgPath, err)
	}

	cfg := Config{
		GRPCAddr:       f.GRPCAddr,
		HealthAddr:     f.HealthAddr,
		AdminAddr:      f.AdminAddr,
		GRPCReflection: f.GRPCReflection,
		OTLPEndpoint:   f.OTLPEndpoint,
		RateLimitRPS:   f.RateLimitRPS,
		RateLimitBurst: f.RateLimitBurst,
		AdminSubjects:  f.AdminSubjects,
		PolicyFile:     defaultPolicyFile,
		PolicyDB:       defaultPolicyDB,
	}

	if v := f.KeyRotationInterval; v != "" {
		cfg.KeyRotationInterval, err = time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid key_rotation_interval %q: %w", v, err)
		}
	}

	// Deployment-specific path overrides via env vars.
	if v := os.Getenv("POLICY_FILE"); v != "" {
		cfg.PolicyFile = v
	}
	if v := os.Getenv("POLICY_DB"); v != "" {
		cfg.PolicyDB = v
	}

	// Default burst to ceil(rps) when unset.
	if cfg.RateLimitBurst <= 0 && cfg.RateLimitRPS > 0 {
		cfg.RateLimitBurst = int(math.Ceil(cfg.RateLimitRPS))
	}

	// SPIFFE_ENDPOINT_SOCKET — required, infrastructure-specific.
	cfg.SpiffeSocket = os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	if cfg.SpiffeSocket == "" {
		return Config{}, fmt.Errorf("SPIFFE_ENDPOINT_SOCKET must be set")
	}

	// AUDIT_HMAC_KEY — optional secret, never in a config file.
	if v := os.Getenv("AUDIT_HMAC_KEY"); v != "" {
		cfg.AuditHMACKey, err = hex.DecodeString(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid AUDIT_HMAC_KEY: must be hex-encoded")
		}
		if len(cfg.AuditHMACKey) != 32 {
			return Config{}, fmt.Errorf("AUDIT_HMAC_KEY must be 32 bytes (64 hex chars), got %d bytes", len(cfg.AuditHMACKey))
		}
	}

	return cfg, nil
}
