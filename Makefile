BINARY     := svid-exchange
MODULE     := github.com/ngaddam369/svid-exchange
PROTO_DIR  := proto/exchange/v1
GEN_DIR    := proto/exchange/v1

.PHONY: all build test lint vet fmt proto run-local dev-certs dev-certs-clean clean

all: build

## build: compile the server binary
build:
	go build -o bin/$(BINARY) ./cmd/server

## test: run all tests with race detector and show coverage summary
test:
	go test -v -race -count=1 -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | grep -E "^total|^github"

## fmt: check gofmt formatting (fail if unformatted files exist)
fmt:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "unformatted files:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

## vet: run go vet
vet:
	go vet ./...

## lint: run golangci-lint
lint:
	golangci-lint run ./...

## proto: regenerate Go code from .proto files
## Requires: protoc + protoc-gen-go + protoc-gen-go-grpc
proto:
	protoc \
		--go_out=. \
		--go_opt=paths=source_relative \
		--go-grpc_out=. \
		--go-grpc_opt=paths=source_relative \
		$(PROTO_DIR)/exchange.proto

## dev-certs: generate self-signed dev certs for local mTLS testing (skips if already present)
dev-certs:
	@bash scripts/gen-dev-certs.sh

## dev-certs-clean: force regeneration of dev certs
dev-certs-clean:
	@rm -rf dev/certs/
	@bash scripts/gen-dev-certs.sh

## run-local: start the server with mTLS using dev certs (standard dev mode)
run-local: dev-certs
	POLICY_FILE=config/policy.example.yaml \
	TLS_CERT_FILE=dev/certs/server.crt \
	TLS_KEY_FILE=dev/certs/server.key \
	TLS_CA_FILE=dev/certs/ca.crt \
	go run ./cmd/server


## clean: remove build artifacts
clean:
	rm -rf bin/

## tidy: tidy and verify go modules
tidy:
	go mod tidy
	go mod verify
