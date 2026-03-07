package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

type mockSTSClient struct {
	out *sts.AssumeRoleWithWebIdentityOutput
	err error
}

func (m *mockSTSClient) AssumeRoleWithWebIdentity(_ context.Context, _ *sts.AssumeRoleWithWebIdentityInput, _ ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error) {
	return m.out, m.err
}

func TestAssumeRoleWithJWT(t *testing.T) {
	expiry := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		mock    *mockSTSClient
		wantErr bool
		check   func(t *testing.T, got *AWSCredentials)
	}{
		{
			name: "returns credentials on success",
			mock: &mockSTSClient{
				out: &sts.AssumeRoleWithWebIdentityOutput{
					Credentials: &types.Credentials{
						AccessKeyId:     aws.String("AKIAIOSFODNN7EXAMPLE"),
						SecretAccessKey: aws.String("secret"),
						SessionToken:    aws.String("token"),
						Expiration:      &expiry,
					},
				},
			},
			check: func(t *testing.T, got *AWSCredentials) {
				t.Helper()
				if got.AccessKeyID != "AKIAIOSFODNN7EXAMPLE" {
					t.Errorf("AccessKeyID = %q, want %q", got.AccessKeyID, "AKIAIOSFODNN7EXAMPLE")
				}
				if got.SecretAccessKey != "secret" {
					t.Errorf("SecretAccessKey = %q, want %q", got.SecretAccessKey, "secret")
				}
				if got.SessionToken != "token" {
					t.Errorf("SessionToken = %q, want %q", got.SessionToken, "token")
				}
				if !got.Expiration.Equal(expiry) {
					t.Errorf("Expiration = %v, want %v", got.Expiration, expiry)
				}
			},
		},
		{
			name:    "STS error propagates",
			mock:    &mockSTSClient{err: errors.New("sts unavailable")},
			wantErr: true,
		},
		{
			name: "nil expiration handled gracefully",
			mock: &mockSTSClient{
				out: &sts.AssumeRoleWithWebIdentityOutput{
					Credentials: &types.Credentials{
						AccessKeyId:     aws.String("KEY"),
						SecretAccessKey: aws.String("secret"),
						SessionToken:    aws.String("token"),
						Expiration:      nil,
					},
				},
			},
			check: func(t *testing.T, got *AWSCredentials) {
				t.Helper()
				if !got.Expiration.IsZero() {
					t.Errorf("Expiration = %v, want zero time", got.Expiration)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := assumeRoleWithJWT(context.Background(), tc.mock, "jwt", "arn:aws:iam::123:role/test", "session")
			if (err != nil) != tc.wantErr {
				t.Fatalf("assumeRoleWithJWT() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.check != nil && got != nil {
				tc.check(t, got)
			}
		})
	}
}
