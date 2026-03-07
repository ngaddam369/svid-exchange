package client

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/externalaccount"
)

// GCPToken holds a GCP access token obtained via workload identity federation.
type GCPToken struct {
	AccessToken string
	Expiry      time.Time
}

// staticJWTSupplier implements [externalaccount.SubjectTokenSupplier] for a
// fixed JWT string.
type staticJWTSupplier struct{ jwt string }

func (s staticJWTSupplier) SubjectToken(_ context.Context, _ externalaccount.SupplierOptions) (string, error) {
	return s.jwt, nil
}

// ExchangeForGCPToken exchanges jwt for a GCP access token using workload
// identity federation. audience is the workload identity pool provider
// resource name (//iam.googleapis.com/projects/…/providers/…). scopes are
// the requested OAuth2 scopes (e.g. "https://www.googleapis.com/auth/cloud-platform").
// If serviceAccount is non-empty, the federated token is used to impersonate
// that service account and its access token is returned; otherwise the
// federated token itself is returned.
func ExchangeForGCPToken(ctx context.Context, jwt, audience, serviceAccount string, scopes []string) (*GCPToken, error) {
	saURL := ""
	if serviceAccount != "" {
		saURL = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + serviceAccount + ":generateAccessToken"
	}
	ts, err := externalaccount.NewTokenSource(ctx, externalaccount.Config{
		Audience:                       audience,
		SubjectTokenType:               "urn:ietf:params:oauth:token-type:jwt",
		SubjectTokenSupplier:           staticJWTSupplier{jwt: jwt},
		Scopes:                         scopes,
		ServiceAccountImpersonationURL: saURL,
	})
	if err != nil {
		return nil, fmt.Errorf("gcp: new token source: %w", err)
	}
	return gcpTokenFromSource(ts)
}

func gcpTokenFromSource(ts oauth2.TokenSource) (*GCPToken, error) {
	tok, err := ts.Token()
	if err != nil {
		return nil, fmt.Errorf("gcp: token exchange: %w", err)
	}
	return &GCPToken{
		AccessToken: tok.AccessToken,
		Expiry:      tok.Expiry,
	}, nil
}
