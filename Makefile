BINARY := skycloak-mcp
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test test-race lint run inspector tidy docker generate

build: ## Build the server binary
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/skycloak-mcp

test: ## Unit tests
	go test ./...

test-race: ## Unit tests with the race detector + coverage
	go test -race -coverprofile=coverage.out ./...

lint: ## Lint (golangci-lint must be installed)
	golangci-lint run ./...

run: build ## Run on stdio for local MCP Inspector / client testing
	./bin/$(BINARY) --transport stdio

inspector: build ## Launch the MCP Inspector against the local binary
	npx @modelcontextprotocol/inspector ./bin/$(BINARY) --transport stdio

tidy: ## Tidy modules
	go mod tidy

docker: ## Build the container image
	docker build -t ghcr.io/sky-cloak/skycloak-mcp:$(VERSION) .

generate: ## Regenerate the API client from internal/apiclient/openapi.yaml
	go generate ./internal/apiclient/...
