.PHONY: build test bench lint fmt tidy clean run hooks

BINARY := wisp
BUILD_FLAGS := -ldflags="-s -w"

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

tidy:
	go mod tidy

clean:
	rm -f $(BINARY)
	go clean -testcache

hooks:
	@which lefthook >/dev/null 2>&1 || go install github.com/evilmartians/lefthook@latest
	lefthook install
