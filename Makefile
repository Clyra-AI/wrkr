SHELL := /bin/bash

GO ?= go
PKGS := ./...
GOFILES := $(shell git ls-files '*.go')

.PHONY: fmt lint lint-fast test test-fast test-integration test-e2e test-contracts \
	build hooks prepush prepush-full codeql lint-ci test-docs-consistency test-docs-storyline \
	test-adapter-parity

fmt:
	@if [[ -n "$(GOFILES)" ]]; then \
		gofmt -w $(GOFILES); \
	fi

lint-fast:
	@scripts/check_toolchain_pins.sh
	@scripts/check_no_latest.sh
	@scripts/check_repo_hygiene.sh
	@scripts/check_branch_protection_contract.sh
	@$(GO) vet $(PKGS)

lint: lint-fast

test-fast:
	@$(GO) test ./... -count=1

test: test-fast

test-integration:
	@$(GO) test ./... -run Integration -count=1

test-e2e:
	@$(GO) test ./... -run E2E -count=1

test-contracts:
	@$(GO) test ./testinfra/... -count=1

test-docs-consistency:
	@echo "docs consistency checks are not yet implemented"

test-docs-storyline:
	@echo "docs storyline checks are not yet implemented"

test-adapter-parity:
	@echo "adapter parity checks are not yet implemented"

build:
	@mkdir -p .tmp
	@$(GO) build -o .tmp/wrkr ./cmd/wrkr

hooks:
	@pre-commit install

prepush: fmt lint-fast test-fast test-contracts build

prepush-full: prepush lint test test-integration test-e2e codeql

codeql:
	@scripts/run_codeql.sh
