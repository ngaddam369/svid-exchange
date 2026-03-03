package server

import (
	"sync"
	"time"
)

// jtiCache is a thread-safe in-memory store of issued token IDs.
// Entries are lazily evicted after their expiry time passes.
type jtiCache struct {
	mu      sync.Mutex
	entries map[string]time.Time // JTI → expiry
}

func newJTICache() *jtiCache {
	return &jtiCache{entries: make(map[string]time.Time)}
}

// alreadyIssued records jti with the given expiry and returns false if jti is new.
// Returns true if jti was already present and not yet expired (replay detected).
func (c *jtiCache) alreadyIssued(jti string, expiry time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweep()
	if exp, ok := c.entries[jti]; ok && time.Now().Before(exp) {
		return true
	}
	c.entries[jti] = expiry
	return false
}

// sweep removes expired entries. Must be called with c.mu held.
func (c *jtiCache) sweep() {
	now := time.Now()
	for jti, exp := range c.entries {
		if now.After(exp) {
			delete(c.entries, jti)
		}
	}
}

// revocationList holds explicitly revoked JTIs that must not be honoured
// even if they have not expired yet.
type revocationList struct {
	mu  sync.RWMutex
	set map[string]struct{}
}

func newRevocationList() *revocationList {
	return &revocationList{set: make(map[string]struct{})}
}

// Revoke adds jti to the revocation list. Safe for concurrent use.
func (r *revocationList) Revoke(jti string) {
	r.mu.Lock()
	r.set[jti] = struct{}{}
	r.mu.Unlock()
}

// isRevoked returns true if jti has been explicitly revoked.
func (r *revocationList) isRevoked(jti string) bool {
	r.mu.RLock()
	_, ok := r.set[jti]
	r.mu.RUnlock()
	return ok
}
