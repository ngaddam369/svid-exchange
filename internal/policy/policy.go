// Package policy loads and evaluates YAML-based exchange policies.
// Each policy grants a subject SPIFFE ID permission to obtain a token
// targeting a specific service with a bounded scope set and TTL.
package policy

import (
	"fmt"
	"os"
	"slices"

	"gopkg.in/yaml.v3"
)

// Policy defines what a specific subject is allowed to request.
type Policy struct {
	Name          string   `yaml:"name"`
	Subject       string   `yaml:"subject"`
	Target        string   `yaml:"target"`
	AllowedScopes []string `yaml:"allowed_scopes"`
	MaxTTL        int32    `yaml:"max_ttl"`
}

// File is the top-level YAML structure.
type File struct {
	Policies []Policy `yaml:"policies"`
}

// Loader holds the loaded policy set.
type Loader struct {
	policies []Policy
}

// LoadFile reads and parses the policy YAML at path.
func LoadFile(path string) (*Loader, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse policy file: %w", err)
	}
	return &Loader{policies: f.Policies}, nil
}

// EvalResult is returned by Evaluate.
type EvalResult struct {
	Allowed       bool
	GrantedScopes []string
	GrantedTTL    int32
}

// Evaluate checks whether subject may exchange for target with the given
// scopes and TTL. It returns the intersection of requested and allowed
// scopes, capped to max_ttl.
func (l *Loader) Evaluate(subject, target string, scopes []string, ttlSeconds int32) EvalResult {
	for _, p := range l.policies {
		if p.Subject != subject || p.Target != target {
			continue
		}
		granted := intersect(scopes, p.AllowedScopes)
		if len(granted) == 0 {
			return EvalResult{Allowed: false}
		}
		grantedTTL := ttlSeconds
		if grantedTTL <= 0 || grantedTTL > p.MaxTTL {
			grantedTTL = p.MaxTTL
		}
		return EvalResult{
			Allowed:       true,
			GrantedScopes: granted,
			GrantedTTL:    grantedTTL,
		}
	}
	return EvalResult{Allowed: false}
}

// intersect returns elements present in both a and b, preserving order of a.
func intersect(a, b []string) []string {
	var out []string
	for _, v := range a {
		if slices.Contains(b, v) {
			out = append(out, v)
		}
	}
	return out
}
