BINARY     := svid-exchange
MODULE     := github.com/ngaddam369/svid-exchange
PROTO_DIR  := proto/exchange/v1
GEN_DIR    := proto/exchange/v1

.PHONY: build test lint vet fmt proto verify validate-policy compose-up compose-down clean

## build: compile the server binary and validate tool
build:
	go build -o bin/$(BINARY) ./cmd/server
	go build -o bin/$(BINARY)-validate ./cmd/validate

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

## verify: run the full checklist (build → lint → test)
verify: build lint test

## validate-policy: lint the policy file before deploying (uses POLICY_FILE env var or default)
validate-policy: build
	./bin/svid-exchange-validate

## compose-up: run verify + policy lint, then start SPIRE + svid-exchange in Docker Compose
compose-up: verify validate-policy
	docker compose up --build

## compose-down: stop all services and remove named volumes (clean slate)
compose-down:
	docker compose down -v

## clean: remove build artifacts
clean:
	rm -rf bin/

## tidy: tidy and verify go modules
tidy:
	go mod tidy
	go mod verify
