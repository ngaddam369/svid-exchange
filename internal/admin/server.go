// Package admin implements the PolicyAdmin gRPC service.
// It allows dynamic creation and deletion of exchange policies at runtime.
// Changes are persisted to BoltDB and take effect immediately.
package admin

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ngaddam369/svid-exchange/internal/policy"
	adminv1 "github.com/ngaddam369/svid-exchange/proto/admin/v1"
)

// Server implements the PolicyAdmin gRPC service.
type Server struct {
	adminv1.UnimplementedPolicyAdminServer
	store        *policy.Store
	yamlPolicies func() []policy.Policy
	swap         func(*policy.Loader)
	reload       func() error
	revoke       func(jti string, expiresAt time.Time) bool
}

// New returns a Server. yamlPolicies must return the current YAML-sourced
// policies (used for conflict detection). swap is called with the rebuilt
// Loader after every store mutation. reload is called by ReloadPolicy to
// re-read the YAML file and merge it with dynamic policies. revoke is called
// to add a JTI to the in-memory revocation list on the exchange server.
func New(
	store *policy.Store,
	yamlPolicies func() []policy.Policy,
	swap func(*policy.Loader),
	reload func() error,
	revoke func(jti string, expiresAt time.Time) bool,
) *Server {
	return &Server{store: store, yamlPolicies: yamlPolicies, swap: swap, reload: reload, revoke: revoke}
}

// CreatePolicy adds a new dynamic policy. It fails with ALREADY_EXISTS if the
// name or (subject, target) pair conflicts with any existing policy.
func (s *Server) CreatePolicy(_ context.Context, req *adminv1.CreatePolicyRequest) (*adminv1.CreatePolicyResponse, error) {
	if req.Rule == nil {
		return nil, status.Error(codes.InvalidArgument, "rule is required")
	}
	p := protoToPolicy(req.Rule)

	if err := policy.ValidateOne(p); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	yaml := s.yamlPolicies()
	key := p.Subject + "\x00" + p.Target
	for _, yp := range yaml {
		if yp.Name == p.Name {
			return nil, status.Errorf(codes.AlreadyExists, "policy %q is already defined in the YAML file", p.Name)
		}
		if yp.Subject+"\x00"+yp.Target == key {
			return nil, status.Errorf(codes.AlreadyExists, "a policy for this subject+target pair already exists in the YAML file: %q", yp.Name)
		}
	}

	dynamic, err := s.store.List()
	if err != nil {
		return nil, status.Error(codes.Internal, "list store: "+err.Error())
	}
	for _, dp := range dynamic {
		if dp.Name == p.Name {
			return nil, status.Errorf(codes.AlreadyExists, "policy %q already exists", p.Name)
		}
		if dp.Subject+"\x00"+dp.Target == key {
			return nil, status.Errorf(codes.AlreadyExists, "a policy for this subject+target pair already exists: %q", dp.Name)
		}
	}

	// Build and validate the merged loader before persisting.
	merged := make([]policy.Policy, 0, len(yaml)+len(dynamic)+1)
	merged = append(merged, yaml...)
	merged = append(merged, dynamic...)
	merged = append(merged, p)
	loader, err := policy.NewLoader(merged)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := s.store.Save(p); err != nil {
		return nil, status.Error(codes.Internal, "save: "+err.Error())
	}
	s.swap(loader)

	return &adminv1.CreatePolicyResponse{Rule: req.Rule}, nil
}

// DeletePolicy removes a dynamic policy by name. It fails with
// FAILED_PRECONDITION for YAML policies and NOT_FOUND for unknown names.
func (s *Server) DeletePolicy(_ context.Context, req *adminv1.DeletePolicyRequest) (*adminv1.DeletePolicyResponse, error) {
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	yaml := s.yamlPolicies()
	for _, yp := range yaml {
		if yp.Name == req.Name {
			return nil, status.Errorf(codes.FailedPrecondition,
				"policy %q is defined in the YAML file and cannot be deleted via the API; edit the file and call ReloadPolicy", req.Name)
		}
	}

	dynamic, err := s.store.List()
	if err != nil {
		return nil, status.Error(codes.Internal, "list store: "+err.Error())
	}

	remaining := make([]policy.Policy, 0, len(dynamic))
	found := false
	for _, dp := range dynamic {
		if dp.Name == req.Name {
			found = true
		} else {
			remaining = append(remaining, dp)
		}
	}
	if !found {
		return nil, status.Errorf(codes.NotFound, "policy %q not found", req.Name)
	}

	// Build merged loader before deleting (validates the resulting set).
	merged := append(yaml, remaining...)
	loader, err := policy.NewLoader(merged)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	if err := s.store.Delete(req.Name); err != nil {
		return nil, status.Error(codes.Internal, "delete: "+err.Error())
	}
	s.swap(loader)

	return &adminv1.DeletePolicyResponse{}, nil
}

// ReloadPolicy re-reads the YAML policy file from disk and merges it with all
// dynamic policies atomically. If the file is invalid the active policy is
// unchanged and an Internal error is returned.
func (s *Server) ReloadPolicy(_ context.Context, _ *adminv1.ReloadPolicyRequest) (*adminv1.ReloadPolicyResponse, error) {
	if err := s.reload(); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &adminv1.ReloadPolicyResponse{}, nil
}

// ListPolicies returns all active policies with their source ("yaml" or "dynamic").
func (s *Server) ListPolicies(_ context.Context, _ *adminv1.ListPoliciesRequest) (*adminv1.ListPoliciesResponse, error) {
	dynamic, err := s.store.List()
	if err != nil {
		return nil, status.Error(codes.Internal, "list store: "+err.Error())
	}

	yaml := s.yamlPolicies()
	entries := make([]*adminv1.PolicyEntry, 0, len(yaml)+len(dynamic))
	for _, p := range yaml {
		entries = append(entries, &adminv1.PolicyEntry{Rule: policyToProto(p), Source: "yaml"})
	}
	for _, p := range dynamic {
		entries = append(entries, &adminv1.PolicyEntry{Rule: policyToProto(p), Source: "dynamic"})
	}

	return &adminv1.ListPoliciesResponse{Policies: entries}, nil
}

// RevokeToken permanently denies a token ID. The revocation is persisted in
// BoltDB and the in-memory revocation list on the exchange server is updated
// immediately so in-flight calls are rejected without waiting for a restart.
func (s *Server) RevokeToken(_ context.Context, req *adminv1.RevokeTokenRequest) (*adminv1.RevokeTokenResponse, error) {
	if req.TokenId == "" {
		return nil, status.Error(codes.InvalidArgument, "token_id is required")
	}
	if req.ExpiresAt <= 0 {
		return nil, status.Error(codes.InvalidArgument, "expires_at is required")
	}
	if err := s.store.SaveRevocation(req.TokenId, req.ExpiresAt); err != nil {
		return nil, status.Errorf(codes.Internal, "save revocation: %v", err)
	}
	if !s.revoke(req.TokenId, time.Unix(req.ExpiresAt, 0)) {
		return nil, status.Error(codes.ResourceExhausted, "revocation list is full; token was persisted but not applied in-memory — restart the server to rebuild the list")
	}
	return &adminv1.RevokeTokenResponse{}, nil
}

// ListRevokedTokens returns all tokens that have been explicitly revoked and
// have not yet expired naturally. Expired entries are excluded from the
// response but are not deleted from the store; they are cleaned up on startup.
func (s *Server) ListRevokedTokens(_ context.Context, _ *adminv1.ListRevokedTokensRequest) (*adminv1.ListRevokedTokensResponse, error) {
	entries, err := s.store.ListRevocations()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list revocations: %v", err)
	}
	now := time.Now().Unix()
	var tokens []*adminv1.RevokedToken
	for _, e := range entries {
		if e.ExpiresAt > now {
			tokens = append(tokens, &adminv1.RevokedToken{
				TokenId:   e.JTI,
				ExpiresAt: e.ExpiresAt,
			})
		}
	}
	return &adminv1.ListRevokedTokensResponse{Tokens: tokens}, nil
}

func protoToPolicy(r *adminv1.PolicyRule) policy.Policy {
	return policy.Policy{
		Name:          r.Name,
		Subject:       r.Subject,
		Target:        r.Target,
		AllowedScopes: r.AllowedScopes,
		MaxTTL:        r.MaxTtl,
	}
}

func policyToProto(p policy.Policy) *adminv1.PolicyRule {
	return &adminv1.PolicyRule{
		Name:          p.Name,
		Subject:       p.Subject,
		Target:        p.Target,
		AllowedScopes: p.AllowedScopes,
		MaxTtl:        p.MaxTTL,
	}
}
