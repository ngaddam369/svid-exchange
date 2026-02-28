BINARY     := svid-exchange
MODULE     := github.com/ngaddam369/svid-exchange
PROTO_DIR  := proto/exchange/v1
GEN_DIR    := proto/exchange/v1

.PHONY: all build test lint vet fmt proto run-local clean

all: build

## build: compile the server binary
build:
	go build -o bin/$(BINARY) ./cmd/server

## test: run all tests with race detector
test:
	go test -race -count=1 ./...

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

## run-local: start the server using the example policy file
run-local:
	POLICY_FILE=config/policy.example.yaml go run ./cmd/server

## clean: remove build artifacts
clean:
	rm -rf bin/

## tidy: tidy and verify go modules
tidy:
	go mod tidy
	go mod verify
