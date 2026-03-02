package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInitMetrics(t *testing.T) {
	interceptor := initMetrics()
	if interceptor == nil {
		t.Fatal("initMetrics returned nil interceptor")
	}
}

func TestNewMetricsHandler(t *testing.T) {
	h := newMetricsHandler()
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}
}
