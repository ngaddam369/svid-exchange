package server

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestRevocationList(t *testing.T) {
	t.Run("revoked JTI is detected", func(t *testing.T) {
		r := newRevocationList(5_000)
		r.Revoke("jti-1", time.Now().Add(time.Minute))
		if !r.isRevoked("jti-1") {
			t.Error("expected jti-1 to be revoked")
		}
	})

	t.Run("unknown JTI is not revoked", func(t *testing.T) {
		r := newRevocationList(5_000)
		if r.isRevoked("unknown") {
			t.Error("expected unknown JTI to not be revoked")
		}
	})

	t.Run("expired entry is evicted and no longer reported as revoked", func(t *testing.T) {
		r := newRevocationList(5_000)
		r.Revoke("jti-expired", time.Now().Add(50*time.Millisecond))
		if !r.isRevoked("jti-expired") {
			t.Fatal("expected entry to be revoked before expiry")
		}
		time.Sleep(100 * time.Millisecond)
		if r.isRevoked("jti-expired") {
			t.Error("expected expired entry to be evicted")
		}
		if len(r.set) != 0 {
			t.Errorf("expected empty set after eviction, got %d entries", len(r.set))
		}
	})

	t.Run("non-expired entries survive a sweep", func(t *testing.T) {
		r := newRevocationList(5_000)
		r.Revoke("jti-keep", time.Now().Add(time.Minute))
		r.Revoke("jti-expire", time.Now().Add(50*time.Millisecond))
		time.Sleep(100 * time.Millisecond)
		// trigger sweep via isRevoked
		r.isRevoked("any")
		if !r.isRevoked("jti-keep") {
			t.Error("expected non-expired entry to survive sweep")
		}
	})
}

func TestJTICache(t *testing.T) {
	t.Run("new jti is not replay", func(t *testing.T) {
		c := newJTICache(10_000)
		if c.alreadyIssued("jti-1", time.Now().Add(time.Minute)) {
			t.Error("expected false for a new JTI")
		}
	})

	t.Run("same jti within TTL is replay", func(t *testing.T) {
		c := newJTICache(10_000)
		c.alreadyIssued("jti-2", time.Now().Add(time.Minute))
		if !c.alreadyIssued("jti-2", time.Now().Add(time.Minute)) {
			t.Error("expected true for a duplicate JTI within TTL")
		}
	})

	t.Run("expired jti can be reissued", func(t *testing.T) {
		c := newJTICache(10_000)
		// Record with an already-past expiry so the next call sweeps it.
		c.alreadyIssued("jti-3", time.Now().Add(-time.Second))
		if c.alreadyIssued("jti-3", time.Now().Add(time.Minute)) {
			t.Error("expected false after expiry (entry should have been swept)")
		}
	})

	t.Run("concurrent alreadyIssued", func(t *testing.T) {
		c := newJTICache(10_000)
		const goroutines = 100
		var wg sync.WaitGroup
		wg.Add(goroutines)
		for i := range goroutines {
			go func(i int) {
				defer wg.Done()
				jti := fmt.Sprintf("concurrent-jti-%d", i)
				c.alreadyIssued(jti, time.Now().Add(time.Minute))
			}(i)
		}
		wg.Wait()
	})

	t.Run("cap is respected", func(t *testing.T) {
		const max = 10
		c := newJTICache(max)
		for i := range max + 5 {
			c.alreadyIssued(fmt.Sprintf("cap-jti-%d", i), time.Now().Add(time.Minute))
		}
		c.mu.Lock()
		n := len(c.entries)
		c.mu.Unlock()
		if n > max {
			t.Errorf("entries = %d, want <= %d", n, max)
		}
	})
}
