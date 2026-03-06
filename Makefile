SHELL := /bin/bash

GO ?= go
PKGS := ./...
GOFILES := $(shell git ls-files '*.go')
DOCS_SITE_NPM_CACHE ?= $(CURDIR)/.tmp/npm-cache

.PHONY: fmt lint lint-fast test test-fast test-integration test-e2e test-contracts test-scenarios \
	test-hardening test-chaos test-perf test-agent-benchmarks test-risk-lane build hooks prepush prepush-full codeql lint-ci \
	test-docs-consistency test-docs-storyline test-adapter-parity test-v1-acceptance test-uat-local test-release-smoke \
	docs-site-install docs-site-lint docs-site-build docs-site-check docs-site-audit-prod

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

test-scenarios:
	@scripts/validate_scenarios.sh
	@$(GO) test ./internal/scenarios -count=1 -tags=scenario

test-hardening:
	@scripts/test_hardening_all.sh

test-chaos:
	@scripts/test_chaos_all.sh

test-perf:
	@scripts/test_perf_budgets.sh

test-agent-benchmarks:
	@scripts/run_agent_benchmarks.sh --output .tmp/agent-benchmarks.json

test-risk-lane: test-contracts test-scenarios test-hardening test-chaos test-perf test-agent-benchmarks

test-docs-consistency:
	@scripts/check_docs_cli_parity.sh
	@scripts/check_docs_storyline.sh
	@scripts/check_docs_consistency.sh

test-docs-storyline:
	@scripts/run_docs_smoke.sh --subset

docs-site-install:
	@mkdir -p "$(DOCS_SITE_NPM_CACHE)"
	@cd docs-site && NPM_CONFIG_CACHE="$(DOCS_SITE_NPM_CACHE)" npm ci

docs-site-lint:
	@mkdir -p "$(DOCS_SITE_NPM_CACHE)"
	@cd docs-site && NPM_CONFIG_CACHE="$(DOCS_SITE_NPM_CACHE)" npm run lint

docs-site-build:
	@mkdir -p "$(DOCS_SITE_NPM_CACHE)"
	@cd docs-site && NPM_CONFIG_CACHE="$(DOCS_SITE_NPM_CACHE)" npm run build

docs-site-check:
	@python3 scripts/check_docs_site_validation.py --report wrkr-out/docs_site_validation_report.json

docs-site-audit-prod:
	@mkdir -p "$(DOCS_SITE_NPM_CACHE)"
	@cd docs-site && NPM_CONFIG_CACHE="$(DOCS_SITE_NPM_CACHE)" npm audit --omit=dev --audit-level=high

test-adapter-parity:
	@scripts/test_adapter_parity.sh

build:
	@mkdir -p .tmp
	@$(GO) build -o .tmp/wrkr ./cmd/wrkr

hooks:
	@pre-commit install

prepush: fmt lint-fast test-fast test-contracts build

test-v1-acceptance:
	@scripts/run_v1_acceptance.sh

test-uat-local:
	@scripts/test_uat_local.sh

test-release-smoke:
	@scripts/test_uat_local.sh --skip-global-gates

prepush-full: prepush lint test test-integration test-e2e test-scenarios codeql

codeql:
	@scripts/run_codeql.sh
