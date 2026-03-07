# syntax=docker/dockerfile:1
# Build context must be the module root so the binaries can import the module.

# --- Builder stage ---
FROM golang:1.26-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /e2e-caller   ./test/e2e/cmd/caller
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /e2e-validator ./test/e2e/cmd/validator

# --- Runtime stage ---
# Both binaries are statically linked; scratch is sufficient.
# The caller uses SPIFFE trust bundles for gRPC mTLS (not system CAs)
# and plain HTTP for the validator call. No CA certs needed.
FROM scratch

COPY --from=builder /e2e-caller   /e2e-caller
COPY --from=builder /e2e-validator /e2e-validator
