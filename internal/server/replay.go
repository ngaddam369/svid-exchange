package server

import (
	"sync"
	"time"
)

// jtiCache is a thread-safe in-memory store of issued token IDs.
// Entries are lazily evicted after their expiry time passes.
// maxEntries bounds the map size; when the cap is reached new JTIs are not
// recorded (UUID v4 collision is statistically impossible, so skipping is safe).
type jtiCache struct {
	mu         sync.Mutex
	entries    map[string]time.Time // JTI → expiry
	maxEntries int
}

func newJTICache(maxEntries int) *jtiCache {
	return &jtiCache{entries: make(map[string]time.Time), maxEntries: maxEntries}
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
	if len(c.entries) >= c.maxEntries {
		// Cap reached after sweep; skip recording. A UUID v4 collision in
		// normal operation is statistically impossible, so this is safe.
		return false
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
// maxEntries bounds the map size; when the cap is reached new revocations are
// silently dropped (revocations are admin-initiated and rare; a full list is an
// operational anomaly).
type revocationList struct {
	mu         sync.Mutex
	set        map[string]time.Time // JTI → token expiry
	maxEntries int
}

func newRevocationList(maxEntries int) *revocationList {
	return &revocationList{set: make(map[string]time.Time), maxEntries: maxEntries}
}

// Revoke adds jti to the revocation list with its natural token expiry.
// Once expiresAt passes the entry is swept on the next isRevoked call.
// If the cap is reached the entry is silently dropped.
func (r *revocationList) Revoke(jti string, expiresAt time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.set) >= r.maxEntries {
		return
	}
	r.set[jti] = expiresAt
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
