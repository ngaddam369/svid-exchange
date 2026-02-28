# syntax=docker/dockerfile:1

# --- Builder stage ---
FROM golang:1.23-alpine AS builder

WORKDIR /build

# Cache module downloads separately from source
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /svid-exchange ./cmd/server

# --- Runtime stage ---
FROM scratch

# Copy CA certificates for outbound TLS (e.g. SPIRE workload API)
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY --from=builder /svid-exchange /svid-exchange

# Copy example policy so the image is runnable out of the box
COPY config/policy.example.yaml /config/policy.example.yaml

ENV POLICY_FILE=/config/policy.example.yaml
ENV GRPC_ADDR=:8080
ENV HEALTH_ADDR=:8081

EXPOSE 8080 8081

ENTRYPOINT ["/svid-exchange"]
