package main

import (
	"context"
	"errors"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	adminSubjectA = "spiffe://cluster.local/ns/admin/sa/operator"
	adminSubjectB = "spiffe://cluster.local/ns/admin/sa/other"
)

// mockIDExtractor implements server.IDExtractor for testing. It records how many
// times ExtractID was called and returns configurable id/err values.
type mockIDExtractor struct {
	mu    sync.Mutex
	calls int
	id    string
	err   error
}

func (m *mockIDExtractor) ExtractID(_ context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls++
	return m.id, m.err
}

func (m *mockIDExtractor) callCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

var nopHandler grpc.UnaryHandler = func(_ context.Context, _ any) (any, error) {
	return "ok", nil
}

func TestAdminAuthInterceptor(t *testing.T) {
	t.Run("empty allowlist allows any caller without extracting ID", func(t *testing.T) {
		ext := &mockIDExtractor{id: adminSubjectA}
		interceptor := newAdminAuthInterceptor(nil, ext)
		resp, err := interceptor(context.Background(), nil, nil, nopHandler)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if resp != "ok" {
			t.Errorf("expected handler response, got %v", resp)
		}
		if ext.callCount() != 0 {
			t.Errorf("expected ExtractID not called for empty allowlist, got %d calls", ext.callCount())
		}
	})

	t.Run("listed subject is allowed", func(t *testing.T) {
		ext := &mockIDExtractor{id: adminSubjectA}
		interceptor := newAdminAuthInterceptor([]string{adminSubjectA}, ext)
		_, err := interceptor(context.Background(), nil, nil, nopHandler)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if ext.callCount() != 1 {
			t.Errorf("expected ExtractID called once, got %d", ext.callCount())
		}
	})

	t.Run("unlisted subject is denied", func(t *testing.T) {
		ext := &mockIDExtractor{id: adminSubjectB}
		interceptor := newAdminAuthInterceptor([]string{adminSubjectA}, ext)
		_, err := interceptor(context.Background(), nil, nil, nopHandler)
		if code := status.Code(err); code != codes.PermissionDenied {
			t.Errorf("expected PermissionDenied, got %v: %v", code, err)
		}
	})

	t.Run("extraction failure is denied when allowlist is set", func(t *testing.T) {
		ext := &mockIDExtractor{err: errors.New("no cert")}
		interceptor := newAdminAuthInterceptor([]string{adminSubjectA}, ext)
		_, err := interceptor(context.Background(), nil, nil, nopHandler)
		if code := status.Code(err); code != codes.PermissionDenied {
			t.Errorf("expected PermissionDenied, got %v: %v", code, err)
		}
	})

	t.Run("second of multiple allowed subjects is permitted", func(t *testing.T) {
		ext := &mockIDExtractor{id: adminSubjectB}
		interceptor := newAdminAuthInterceptor([]string{adminSubjectA, adminSubjectB}, ext)
		_, err := interceptor(context.Background(), nil, nil, nopHandler)
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
	})
}
