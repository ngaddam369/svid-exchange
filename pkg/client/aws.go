package client

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// AWSCredentials holds temporary AWS credentials returned by STS.
type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
}

// stsClientIface is the subset of [*sts.Client] used by [assumeRoleWithJWT].
// Satisfied by [*sts.Client] in production and by a test double in tests.
type stsClientIface interface {
	AssumeRoleWithWebIdentity(ctx context.Context, params *sts.AssumeRoleWithWebIdentityInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleWithWebIdentityOutput, error)
}

// AssumeRoleWithJWT exchanges jwt for temporary AWS credentials by calling
// STS AssumeRoleWithWebIdentity. roleARN is the IAM role to assume;
// sessionName identifies the session in CloudTrail logs.
// No long-term AWS credentials are required — the JWT is the credential.
func AssumeRoleWithJWT(ctx context.Context, jwt, roleARN, sessionName string) (*AWSCredentials, error) {
	cfg := aws.Config{
		Region:      "us-east-1",
		Credentials: aws.AnonymousCredentials{},
	}
	return assumeRoleWithJWT(ctx, sts.NewFromConfig(cfg), jwt, roleARN, sessionName)
}

func assumeRoleWithJWT(ctx context.Context, client stsClientIface, jwt, roleARN, sessionName string) (*AWSCredentials, error) {
	out, err := client.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(roleARN),
		RoleSessionName:  aws.String(sessionName),
		WebIdentityToken: aws.String(jwt),
	})
	if err != nil {
		return nil, fmt.Errorf("aws: AssumeRoleWithWebIdentity: %w", err)
	}
	creds := out.Credentials
	var exp time.Time
	if creds.Expiration != nil {
		exp = *creds.Expiration
	}
	return &AWSCredentials{
		AccessKeyID:     aws.ToString(creds.AccessKeyId),
		SecretAccessKey: aws.ToString(creds.SecretAccessKey),
		SessionToken:    aws.ToString(creds.SessionToken),
		Expiration:      exp,
	}, nil
}
