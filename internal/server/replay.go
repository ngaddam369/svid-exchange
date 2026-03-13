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
// even if they have not expired yet. Entries are lazily evicted once their
// natural token expiry has passed — a revoked token that has expired can no
// longer be presented, so there is no need to keep it in the list.
type revocationList struct {
	mu  sync.Mutex
	set map[string]time.Time // JTI → token expiry
}

func newRevocationList() *revocationList {
	return &revocationList{set: make(map[string]time.Time)}
}

// Revoke adds jti to the revocation list with its natural token expiry.
// Once expiresAt passes the entry is swept on the next isRevoked call.
func (r *revocationList) Revoke(jti string, expiresAt time.Time) {
	r.mu.Lock()
	r.set[jti] = expiresAt
	r.mu.Unlock()
}

// isRevoked returns true if jti has been explicitly revoked and has not yet
// expired naturally. Expired entries are evicted on each call.
func (r *revocationList) isRevoked(jti string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sweep()
	_, ok := r.set[jti]
	return ok
}

// sweep removes entries whose token expiry has passed. Must be called with r.mu held.
func (r *revocationList) sweep() {
	now := time.Now()
	for jti, exp := range r.set {
		if now.After(exp) {
			delete(r.set, jti)
		}
	}
}
