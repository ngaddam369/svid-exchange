package main

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ngaddam369/svid-exchange/internal/server"
)

// newAdminAuthInterceptor returns a gRPC unary interceptor that enforces an
// allowlist of SPIFFE IDs on the admin API. When allowedSubjects is empty the
// interceptor is a no-op and any authenticated peer may call admin endpoints.
func newAdminAuthInterceptor(allowedSubjects []string, ext server.IDExtractor) grpc.UnaryServerInterceptor {
	allowed := make(map[string]struct{}, len(allowedSubjects))
	for _, s := range allowedSubjects {
		allowed[s] = struct{}{}
	}
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if len(allowed) == 0 {
			return handler(ctx, req)
		}
		id, err := ext.ExtractID(ctx)
		if err != nil {
			return nil, status.Error(codes.PermissionDenied, "no SPIFFE identity")
		}
		if _, ok := allowed[id]; !ok {
			return nil, status.Errorf(codes.PermissionDenied, "caller %q is not an authorized admin subject", id)
		}
		return handler(ctx, req)
	}
}
