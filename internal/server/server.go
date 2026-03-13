// Package server implements the TokenExchange gRPC service handler.
package server

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ngaddam369/svid-exchange/internal/audit"
	"github.com/ngaddam369/svid-exchange/internal/policy"
	"github.com/ngaddam369/svid-exchange/internal/token"
	exchangev1 "github.com/ngaddam369/svid-exchange/proto/exchange/v1"
)

// IDExtractor extracts the caller's SPIFFE ID from the request context.
type IDExtractor interface {
	ExtractID(ctx context.Context) (string, error)
}

// PolicyEvaluator evaluates whether an exchange is permitted and returns the
// granted scopes and TTL.
type PolicyEvaluator interface {
	Evaluate(subject, target string, scopes []string, ttlSeconds int32) policy.EvalResult
}

// TokenMinter mints a signed JWT for an authorised exchange and exposes the
// active public keys so that on_behalf_of tokens can be verified.
type TokenMinter interface {
	Mint(subject, target string, scopes []string, ttlSeconds int32, actSubject string) (token.MintResult, error)
	PublicKeys() []*ecdsa.PublicKey
}

// AuditLogger records exchange events for the audit trail.
type AuditLogger interface {
	LogExchange(e audit.ExchangeEvent)
}

// TokenExchangeServer implements the exchangev1.TokenExchangeServer interface.
type TokenExchangeServer struct {
	exchangev1.UnimplementedTokenExchangeServer
	extractor IDExtractor
	policy    PolicyEvaluator
	minter    TokenMinter
	audit     AuditLogger
	cache     *jtiCache
	revoked   *revocationList
}

// New creates a TokenExchangeServer from its dependencies.
func New(e IDExtractor, p PolicyEvaluator, m TokenMinter, a AuditLogger) *TokenExchangeServer {
	return &TokenExchangeServer{
		extractor: e,
		policy:    p,
		minter:    m,
		audit:     a,
		cache:     newJTICache(),
		revoked:   newRevocationList(),
	}
}

// Revoke adds jti to the server's revocation list with its natural token expiry.
// Any subsequent exchange that produces the same token ID is rejected with
// codes.PermissionDenied. Once expiresAt passes the entry is evicted automatically.
func (s *TokenExchangeServer) Revoke(jti string, expiresAt time.Time) {
	s.revoked.Revoke(jti, expiresAt)
}

// Exchange validates the caller's SVID, applies policy, and mints a token.
func (s *TokenExchangeServer) Exchange(ctx context.Context, req *exchangev1.ExchangeRequest) (*exchangev1.ExchangeResponse, error) {
	subjectID, err := s.extractor.ExtractID(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "extract SPIFFE ID: %v", err)
	}

	if req.TargetService == "" {
		return nil, status.Error(codes.InvalidArgument, "target_service is required")
	}
	if len(req.Scopes) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one scope is required")
	}

	var actSubject string
	if req.OnBehalfOf != "" {
		actSubject, err = token.VerifyJWT(req.OnBehalfOf, s.minter.PublicKeys())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "on_behalf_of: %v", err)
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
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
		return nil, status.Errorf(codes.PermissionDenied, "no policy permits %s → %s", subjectID, req.TargetService)
	}

	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}

	minted, err := s.minter.Mint(subjectID, req.TargetService, result.GrantedScopes, result.GrantedTTL, actSubject)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "mint token: %v", err)
	}

	if s.revoked.isRevoked(minted.TokenID) {
		return nil, status.Error(codes.PermissionDenied, "token id has been revoked")
	}
	// alreadyIssued is belt-and-suspenders: Mint() generates a UUID v4 JTI on
	// every call so a collision is statistically impossible in normal operation.
	// The check guards against hypothetical minter bugs or future non-UUID JTI
	// schemes that might reuse IDs.
	if s.cache.alreadyIssued(minted.TokenID, minted.ExpiresAt) {
		return nil, status.Error(codes.AlreadyExists, "token id already issued")
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
