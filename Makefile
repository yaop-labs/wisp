.PHONY: build test bench lint fmt fmt-check tidy tidy-check clean run hooks

BINARY := wisp
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/yaop-labs/wisp/internal/buildinfo.Version=$(VERSION) \
	-X github.com/yaop-labs/wisp/internal/buildinfo.Commit=$(COMMIT) \
	-X github.com/yaop-labs/wisp/internal/buildinfo.Date=$(BUILD_DATE)
BUILD_FLAGS := -ldflags="$(LDFLAGS)"

build:
	go build $(BUILD_FLAGS) -o $(BINARY) ./cmd/wisp

run: build
	./$(BINARY) -config configs/wisp.example.yaml

test:
	go test ./... -race -count=1

bench:
	go test ./... -bench=. -benchtime=2s -run=^$$ -timeout=30m

lint:
	go vet ./...
	golangci-lint run ./...

fmt:
	gofmt -w .
	@which goimports >/dev/null 2>&1 && goimports -w -local github.com/yaop-labs/wisp . || true

fmt-check:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

tidy:
	go mod tidy

tidy-check:
	go mod tidy
	git diff --exit-code -- go.mod go.sum

clean:
	rm -f $(BINARY)
	go clean -testcache

hooks:
	@which lefthook >/dev/null 2>&1 || go install github.com/evilmartians/lefthook@latest
	lefthook install
