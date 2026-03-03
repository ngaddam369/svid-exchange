// Package policy loads and evaluates YAML-based exchange policies.
// Each policy grants a subject SPIFFE ID permission to obtain a token
// targeting a specific service with a bounded scope set and TTL.
package policy

import (
	"errors"
	"fmt"
	"net/url"
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
	if len(f.Policies) == 0 {
		return nil, errors.New("policy file contains no policies")
	}
	return NewLoader(f.Policies)
}

// NewLoader validates policies and returns a Loader backed by them.
// Unlike LoadFile it accepts an empty slice (all requests will be denied).
func NewLoader(policies []Policy) (*Loader, error) {
	seen := make(map[string]int) // "subject\x00target" → first index
	for i, p := range policies {
		if err := ValidateOne(p); err != nil {
			return nil, fmt.Errorf("policy %d (%q): %w", i, p.Name, err)
		}
		key := p.Subject + "\x00" + p.Target
		if first, dup := seen[key]; dup {
			return nil, fmt.Errorf("policy %d (%q): duplicate (subject, target) pair already defined by policy %d", i, p.Name, first)
		}
		seen[key] = i
	}
	return &Loader{policies: policies}, nil
}

// ValidateOne checks that a single policy has valid fields.
// It does not check for duplicates across a set of policies.
func ValidateOne(p Policy) error {
	if p.Name == "" {
		return errors.New("name must not be empty")
	}
	if err := validateSPIFFEID(p.Subject); err != nil {
		return fmt.Errorf("invalid subject: %w", err)
	}
	if err := validateSPIFFEID(p.Target); err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}
	if len(p.AllowedScopes) == 0 {
		return errors.New("allowed_scopes must not be empty")
	}
	if p.MaxTTL <= 0 {
		return errors.New("max_ttl must be greater than zero")
	}
	return nil
}

// Policies returns a copy of the loaded policy slice.
func (l *Loader) Policies() []Policy {
	out := make([]Policy, len(l.policies))
	copy(out, l.policies)
	return out
}

// validateSPIFFEID checks that id is a well-formed SPIFFE ID (spiffe://<trust-domain>/...).
func validateSPIFFEID(id string) error {
	u, err := url.Parse(id)
	if err != nil {
		return fmt.Errorf("parse URI: %w", err)
	}
	if u.Scheme != "spiffe" {
		return fmt.Errorf("scheme must be \"spiffe\", got %q", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("missing trust domain")
	}
	return nil
}

// EvalResult is returned by Evaluate.
type EvalResult struct {
	Allowed       bool
	GrantedScopes []string
	GrantedTTL    int32
}

// Evaluate checks whether subject may exchange for target with the given
// scopes and TTL. It returns the permitted subset of the requested scopes,
// capped to max_ttl.
func (l *Loader) Evaluate(subject, target string, scopes []string, ttlSeconds int32) EvalResult {
	for _, p := range l.policies {
		if p.Subject != subject || p.Target != target {
			continue
		}
		granted := allowedSubset(scopes, p.AllowedScopes)
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

// allowedSubset returns the scopes from requested that the policy permits,
// preserving the order of requested.
func allowedSubset(requested, allowed []string) []string {
	var out []string
	for _, scope := range requested {
		if slices.Contains(allowed, scope) {
			out = append(out, scope)
		}
	}
	return out
}
