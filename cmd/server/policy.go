package main

import (
	"sync"
	"sync/atomic"

	"github.com/ngaddam369/svid-exchange/internal/policy"
)

// atomicPolicy is a PolicyEvaluator whose underlying policy can be swapped
// atomically at runtime without disrupting in-flight requests.
// It also tracks the YAML-sourced base policies separately from dynamic
// policies so that the ReloadPolicy RPC and the admin API can merge them correctly.
type atomicPolicy struct {
	ptr  atomic.Pointer[policy.Loader]
	mu   sync.RWMutex
	base []policy.Policy // YAML-sourced policies; updated on ReloadPolicy
}

func newAtomicPolicy(initial *policy.Loader) *atomicPolicy {
	ap := &atomicPolicy{base: initial.Policies()}
	ap.ptr.Store(initial)
	return ap
}

// Evaluate delegates to the currently loaded policy. Safe for concurrent use.
func (ap *atomicPolicy) Evaluate(subject, target string, scopes []string, ttlSeconds int32) policy.EvalResult {
	return ap.ptr.Load().Evaluate(subject, target, scopes, ttlSeconds)
}

// swap replaces the active policy atomically.
func (ap *atomicPolicy) swap(p *policy.Loader) {
	ap.ptr.Store(p)
}

// setBase updates the YAML-sourced base policies. Called after a successful
// file reload, before rebuilding the merged loader.
func (ap *atomicPolicy) setBase(ps []policy.Policy) {
	ap.mu.Lock()
	ap.base = ps
	ap.mu.Unlock()
}

// yamlPolicies returns a copy of the current YAML-sourced base policies.
func (ap *atomicPolicy) yamlPolicies() []policy.Policy {
	ap.mu.RLock()
	defer ap.mu.RUnlock()
	out := make([]policy.Policy, len(ap.base))
	copy(out, ap.base)
	return out
}

// rebuild merges the current YAML base with all dynamic store policies and
// swaps the result in atomically.
func (ap *atomicPolicy) rebuild(store *policy.Store) error {
	dynamic, err := store.List()
	if err != nil {
		return err
	}
	yaml := ap.yamlPolicies()
	merged := make([]policy.Policy, 0, len(yaml)+len(dynamic))
	merged = append(merged, yaml...)
	merged = append(merged, dynamic...)
	loader, err := policy.NewLoader(merged)
	if err != nil {
		return err
	}
	ap.swap(loader)
	return nil
}
