// Package server implements the TokenExchange gRPC service handler.
package server

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ngaddam369/svid-exchange/internal/audit"
	"github.com/ngaddam369/svid-exchange/internal/policy"
	"github.com/ngaddam369/svid-exchange/internal/spiffe"
	"github.com/ngaddam369/svid-exchange/internal/token"
	exchangev1 "github.com/ngaddam369/svid-exchange/proto/exchange/v1"
)

// TokenExchangeServer implements the exchangev1.TokenExchangeServer interface.
type TokenExchangeServer struct {
	exchangev1.UnimplementedTokenExchangeServer
	policy *policy.Loader
	minter *token.Minter
	audit  *audit.Logger
}

// New creates a TokenExchangeServer.
func New(p *policy.Loader, m *token.Minter, a *audit.Logger) *TokenExchangeServer {
	return &TokenExchangeServer{policy: p, minter: m, audit: a}
}

// Exchange validates the caller's SVID, applies policy, and mints a token.
func (s *TokenExchangeServer) Exchange(ctx context.Context, req *exchangev1.ExchangeRequest) (*exchangev1.ExchangeResponse, error) {
	subjectID, err := spiffe.ExtractID(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "extract SPIFFE ID: %v", err)
	}

	if req.TargetService == "" {
		return nil, status.Error(codes.InvalidArgument, "target_service is required")
	}
	if len(req.Scopes) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one scope is required")
	}

	result := s.policy.Evaluate(subjectID, req.TargetService, req.Scopes, req.TtlSeconds)
	if !result.Allowed {
		s.audit.LogExchange(audit.ExchangeEvent{
			Subject:         subjectID,
			Target:          req.TargetService,
			ScopesRequested: req.Scopes,
			Granted:         false,
			DenialReason:    fmt.Sprintf("no policy permits %s → %s", subjectID, req.TargetService),
		})
		return nil, status.Errorf(codes.PermissionDenied, "no policy permits %s to access %s", subjectID, req.TargetService)
	}

	minted, err := s.minter.Mint(subjectID, req.TargetService, result.GrantedScopes, result.GrantedTTL)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "mint token: %v", err)
	}

	s.audit.LogExchange(audit.ExchangeEvent{
		Subject:         subjectID,
		Target:          req.TargetService,
		ScopesRequested: req.Scopes,
		ScopesGranted:   result.GrantedScopes,
		Granted:         true,
		TTL:             result.GrantedTTL,
		TokenID:         minted.TokenID,
	})

	return &exchangev1.ExchangeResponse{
		Token:         minted.Token,
		ExpiresAt:     minted.ExpiresAt.Unix(),
		GrantedScopes: result.GrantedScopes,
		TokenId:       minted.TokenID,
	}, nil
}
