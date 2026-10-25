# Variables
BINARY_NAME=sbx
GO=go

# Build variables. Release builds set VERSION to X.Y.Z from the tag.
VERSION?=dev-$(shell git rev-parse --short HEAD)
LDFLAGS=-ldflags "-X main.version=$(VERSION)"
# The ssh config runs sbx from here
OUT?=$(HOME)/.local/bin/$(BINARY_NAME)

.PHONY: build test lint vuln

## build: Build sbx into ~/.local/bin
build:
	$(GO) build -trimpath $(LDFLAGS) -o $(OUT) ./cmd/sbx

## test: Run all tests
test:
	$(GO) test -race -shuffle=on ./...

## lint: Run linter
lint:
	golangci-lint run ./...

## vuln: Check dependencies for known vulnerabilities
vuln:
	govulncheck ./...
