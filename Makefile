SHELL := /bin/bash

GO ?= go
PKG_LIST := scripts/first_party_go_packages.sh
GOFILES := $(shell git ls-files '*.go')
DOCS_SITE_NPM_CACHE ?= $(CURDIR)/.tmp/npm-cache
GO_TEST_TIMEOUT ?= 20m
COVERAGE_DIR ?= .tmp/coverage
COVERAGE_CORE_MIN ?= 85
COVERAGE_PACKAGE_MIN ?= 75
FREEZE_GATE_REQUIRE_CLEAN ?=

.PHONY: fmt lint lint-fast test test-fast test-coverage test-freeze-gate test-integration test-e2e test-contracts test-scenarios \
	test-hardening test-chaos test-perf test-agent-benchmarks test-risk-lane build hooks prepush prepush-full codeql lint-ci \
	test-docs-consistency test-docs-storyline test-focused-docs test-focused-scan test-adapter-parity test-v1-acceptance test-uat-local test-release-smoke \
	docs-site-install docs-site-lint docs-site-build docs-site-check docs-site-audit-prod

fmt:
	@if [[ -n "$(GOFILES)" ]]; then \
		gofmt -w $(GOFILES); \
	fi

lint-fast:
	@scripts/check_toolchain_pins.sh
	@scripts/check_no_latest.sh
	@scripts/check_repo_hygiene.sh
	@scripts/check_actions_runtime.sh
	@scripts/check_branch_protection_contract.sh
	@$(GO) vet $$($(PKG_LIST))

lint: lint-fast

test-fast:
	@$(GO) test $$($(PKG_LIST)) -count=1 -timeout=$(GO_TEST_TIMEOUT)

test: test-fast

test-coverage:
	@mkdir -p "$(COVERAGE_DIR)"
	@set -o pipefail; $(GO) test $$($(PKG_LIST)) -covermode=atomic -coverprofile="$(COVERAGE_DIR)/all.out" -count=1 -timeout=$(GO_TEST_TIMEOUT) | tee "$(COVERAGE_DIR)/packages.txt"
	@python3 scripts/check_go_coverage.py "$(COVERAGE_DIR)/all.out" "$(COVERAGE_CORE_MIN)" \
		--include-prefix github.com/Clyra-AI/wrkr/core/ \
		--include-prefix github.com/Clyra-AI/wrkr/cmd/ \
		--exceptions .github/coverage-exceptions.json \
		--scope go_core_and_command_packages
	@python3 scripts/check_go_package_coverage.py "$(COVERAGE_DIR)/packages.txt" "$(COVERAGE_PACKAGE_MIN)" .github/coverage-exceptions.json

test-freeze-gate:
	@python3 scripts/run_freeze_gate.py \
		--repo-root . \
		--receipt testinfra/contracts/fixtures/freeze-gate/story-0.1-receipt.json \
		--output .tmp/freeze-gate-runtime-receipt.json \
		$(FREEZE_GATE_REQUIRE_CLEAN)

test-integration:
	@$(GO) test $$($(PKG_LIST)) -run Integration -count=1

test-e2e:
	@$(GO) test $$($(PKG_LIST)) -run E2E -count=1

test-contracts:
	@$(GO) test ./testinfra/... -count=1

test-scenarios:
	@scripts/validate_scenarios.sh
	@$(GO) test ./internal/scenarios -count=1 -tags=scenario -timeout=$(GO_TEST_TIMEOUT)

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

test-focused-docs:
	@$(GO) test ./testinfra/hygiene -run 'TestInstallDocsSmokeGoOnlyPath|TestInstallDocsPinnedVersionSupportsCurrentReadmeCommands|TestMinimalDependenciesReleaseSmokeVersionIsCurrent' -count=1
	@$(MAKE) test-docs-consistency

test-focused-scan:
	@$(GO) test ./core/cli -run 'TestScan.*Partial|TestScanStatus|TestScan.*Progress|TestHostedProgress.*' -count=1
	@$(GO) test ./core/state -run TestScanStatus -count=1
	@$(GO) test ./core/source/org -run 'Test.*Progress|Test.*Resume|Test.*Failure' -count=1

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
	@cd docs-site && NPM_CONFIG_CACHE="$(DOCS_SITE_NPM_CACHE)" npm run test:smoke
	@python3 scripts/check_docs_site_validation.py --report wrkr-out/docs_site_validation_report.json

docs-site-audit-prod:
	@mkdir -p "$(DOCS_SITE_NPM_CACHE)"
	@NPM_CONFIG_CACHE="$(DOCS_SITE_NPM_CACHE)" python3 scripts/validate_docs_site_audit.py --repo-root . --json

test-adapter-parity:
	@scripts/test_adapter_parity.sh

build:
	@mkdir -p .tmp
	@$(GO) build -o .tmp/wrkr ./cmd/wrkr

hooks:
	@pre-commit install

prepush: fmt lint-fast build test-fast test-contracts

test-v1-acceptance:
	@scripts/run_v1_acceptance.sh

test-uat-local:
	@scripts/test_uat_local.sh

test-release-smoke:
	@scripts/test_uat_local.sh --skip-global-gates

prepush-full: prepush lint test test-coverage test-freeze-gate test-integration test-e2e test-scenarios codeql

codeql:
	@scripts/run_codeql.sh
