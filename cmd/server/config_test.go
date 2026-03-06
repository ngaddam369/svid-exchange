package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeConfigFile writes content to a temp file and returns its path.
func writeConfigFile(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "server-*.yaml")
	if err != nil {
		t.Fatalf("create temp config file: %v", err)
	}
	if _, err = f.WriteString(content); err != nil {
		t.Fatalf("write temp config file: %v", err)
	}
	if err = f.Close(); err != nil {
		t.Fatalf("close temp config file: %v", err)
	}
	return f.Name()
}

func TestLoadConfig(t *testing.T) {
	validYAML := `
grpc_addr:             ":9090"
health_addr:           ":9091"
admin_addr:            ":9092"
grpc_reflection:       false
otlp_endpoint:         "otel:4317"
rate_limit_rps:        5.0
rate_limit_burst:      10
key_rotation_interval: "12h"
`
	minimalYAML := "grpc_reflection: true\n"

	tests := []struct {
		name     string
		yaml     string
		env      map[string]string
		wantErr  bool
		checkCfg func(t *testing.T, cfg Config)
	}{
		{
			name: "all fields parsed from YAML",
			yaml: validYAML,
			env:  map[string]string{"SPIFFE_ENDPOINT_SOCKET": "unix:///tmp/agent.sock"},
			checkCfg: func(t *testing.T, cfg Config) {
				t.Helper()
				if cfg.GRPCAddr != ":9090" {
					t.Errorf("GRPCAddr = %q, want :9090", cfg.GRPCAddr)
				}
				if cfg.HealthAddr != ":9091" {
					t.Errorf("HealthAddr = %q, want :9091", cfg.HealthAddr)
				}
				if cfg.AdminAddr != ":9092" {
					t.Errorf("AdminAddr = %q, want :9092", cfg.AdminAddr)
				}
				if cfg.GRPCReflection {
					t.Error("GRPCReflection = true, want false")
				}
				if cfg.OTLPEndpoint != "otel:4317" {
					t.Errorf("OTLPEndpoint = %q, want otel:4317", cfg.OTLPEndpoint)
				}
				if cfg.RateLimitRPS != 5.0 {
					t.Errorf("RateLimitRPS = %v, want 5.0", cfg.RateLimitRPS)
				}
				if cfg.RateLimitBurst != 10 {
					t.Errorf("RateLimitBurst = %d, want 10", cfg.RateLimitBurst)
				}
				if cfg.KeyRotationInterval != 12*time.Hour {
					t.Errorf("KeyRotationInterval = %v, want 12h", cfg.KeyRotationInterval)
				}
			},
		},
		{
			name: "default policy paths when env vars unset",
			yaml: minimalYAML,
			env: map[string]string{
				"SPIFFE_ENDPOINT_SOCKET": "unix:///tmp/agent.sock",
				"POLICY_FILE":            "",
				"POLICY_DB":              "",
			},
			checkCfg: func(t *testing.T, cfg Config) {
				t.Helper()
				if cfg.PolicyFile != defaultPolicyFile {
					t.Errorf("PolicyFile = %q, want %q", cfg.PolicyFile, defaultPolicyFile)
				}
				if cfg.PolicyDB != defaultPolicyDB {
					t.Errorf("PolicyDB = %q, want %q", cfg.PolicyDB, defaultPolicyDB)
				}
			},
		},
		{
			name: "POLICY_FILE and POLICY_DB env vars override defaults",
			yaml: minimalYAML,
			env: map[string]string{
				"SPIFFE_ENDPOINT_SOCKET": "unix:///tmp/agent.sock",
				"POLICY_FILE":            "/custom/policy.yaml",
				"POLICY_DB":              "/custom/policy.db",
			},
			checkCfg: func(t *testing.T, cfg Config) {
				t.Helper()
				if cfg.PolicyFile != "/custom/policy.yaml" {
					t.Errorf("PolicyFile = %q, want /custom/policy.yaml", cfg.PolicyFile)
				}
				if cfg.PolicyDB != "/custom/policy.db" {
					t.Errorf("PolicyDB = %q, want /custom/policy.db", cfg.PolicyDB)
				}
			},
		},
		{
			name: "burst defaults to ceil(rps) when unset",
			yaml: "rate_limit_rps: 3.5\n",
			env:  map[string]string{"SPIFFE_ENDPOINT_SOCKET": "unix:///tmp/agent.sock"},
			checkCfg: func(t *testing.T, cfg Config) {
				t.Helper()
				if cfg.RateLimitBurst != 4 {
					t.Errorf("RateLimitBurst = %d, want 4 (ceil(3.5))", cfg.RateLimitBurst)
				}
			},
		},
		{
			name: "valid AUDIT_HMAC_KEY is decoded",
			yaml: minimalYAML,
			env: map[string]string{
				"SPIFFE_ENDPOINT_SOCKET": "unix:///tmp/agent.sock",
				// 64 hex chars = 32 bytes
				"AUDIT_HMAC_KEY": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
			},
			checkCfg: func(t *testing.T, cfg Config) {
				t.Helper()
				if len(cfg.AuditHMACKey) != 32 {
					t.Errorf("AuditHMACKey len = %d, want 32", len(cfg.AuditHMACKey))
				}
			},
		},
		{
			name:    "missing SPIFFE_ENDPOINT_SOCKET returns error",
			yaml:    minimalYAML,
			env:     map[string]string{"SPIFFE_ENDPOINT_SOCKET": ""},
			wantErr: true,
		},
		{
			name:    "missing config file returns error",
			yaml:    "", // signal to use a nonexistent path
			env:     map[string]string{"SPIFFE_ENDPOINT_SOCKET": "unix:///tmp/agent.sock"},
			wantErr: true,
		},
		{
			name:    "invalid AUDIT_HMAC_KEY hex returns error",
			yaml:    minimalYAML,
			env:     map[string]string{"SPIFFE_ENDPOINT_SOCKET": "unix:///tmp/agent.sock", "AUDIT_HMAC_KEY": "notvalidhex!"},
			wantErr: true,
		},
		{
			name:    "wrong-length AUDIT_HMAC_KEY returns error",
			yaml:    minimalYAML,
			env:     map[string]string{"SPIFFE_ENDPOINT_SOCKET": "unix:///tmp/agent.sock", "AUDIT_HMAC_KEY": "deadbeef"},
			wantErr: true,
		},
		{
			name:    "invalid key_rotation_interval returns error",
			yaml:    "key_rotation_interval: \"notaduration\"\n",
			env:     map[string]string{"SPIFFE_ENDPOINT_SOCKET": "unix:///tmp/agent.sock"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var cfgPath string
			if tc.yaml == "" {
				cfgPath = filepath.Join(t.TempDir(), "nonexistent.yaml")
			} else {
				cfgPath = writeConfigFile(t, tc.yaml)
			}
			t.Setenv("CONFIG_FILE", cfgPath)

			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			cfg, err := loadConfig()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
			if tc.checkCfg != nil {
				tc.checkCfg(t, cfg)
			}
		})
	}
}
