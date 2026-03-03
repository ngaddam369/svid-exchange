package main

import (
	"sync/atomic"

	"github.com/ngaddam369/svid-exchange/internal/policy"
)

// atomicPolicy is a PolicyEvaluator whose underlying policy can be swapped
// atomically at runtime without disrupting in-flight requests.
type atomicPolicy struct {
	ptr atomic.Pointer[policy.Loader]
}

func newAtomicPolicy(initial *policy.Loader) *atomicPolicy {
	ap := &atomicPolicy{}
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
