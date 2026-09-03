# Warden — developer entry points.
#
# The contract from task M0-1: on a clean clone with only Go, Node and Python
# installed, `make build test lint` is green. Everything else a target needs, it
# installs into ./bin at a pinned version.

SHELL := /bin/bash
.DEFAULT_GOAL := help

GO              ?= go
MODULE          := github.com/warden-project/warden
BIN             := $(CURDIR)/bin
VERSION         ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo devel)
LDFLAGS         := -X main.version=$(VERSION)

# Pinned tool versions. Bump deliberately; CI uses these same pins, so a tool
# upgrade is a reviewable commit rather than a surprise on someone's machine.
GOLANGCI_VERSION    := v2.13.2
MIGRATE_VERSION     := v4.19.0

# Python 3.10+ is required by the SDK (SPEC §12.2). macOS ships 3.9, so look for a
# usable interpreter rather than assuming `python3` is new enough.
PYTHON ?= $(shell for p in python3.13 python3.12 python3.11 python3.10 python3; do \
	if command -v $$p >/dev/null 2>&1 && $$p -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then \
		echo $$p; break; \
	fi; \
done)

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

## -- Build -----------------------------------------------------------------------

.PHONY: build
build: ## Build the warden binary into ./bin
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN)/warden ./cmd/warden

.PHONY: install
install: ## Install warden into GOBIN
	$(GO) install -trimpath -ldflags "$(LDFLAGS)" ./cmd/warden

## -- Test ------------------------------------------------------------------------

.PHONY: test
test: test-go ## Run every test suite

# -p 1 runs one package at a time. The integration packages each rebuild the schema
# of the same database, so running them concurrently has one dropping the schema out
# from under the other — which surfaces as an unrelated-looking "type citext does not
# exist". Per-package databases would also work; serialising is cheaper and the suite
# is seconds long.
.PHONY: test-go
test-go: ## Run the Go tests with the race detector
	$(GO) test -race -shuffle=on -count=1 -p 1 ./...

# The tenant-isolation suite needs a real PostgreSQL; without one it skips rather
# than fails, so `make test` stays useful on a machine with no database. CI always
# provides one, so the isolation guarantees are never merely optional.
.PHONY: test-integration
test-integration: ## Run the tests that need PostgreSQL (starts it if needed)
	@docker compose -f deploy/docker-compose.yml up -d postgres >/dev/null
	@until docker compose -f deploy/docker-compose.yml exec -T postgres pg_isready -U warden -d warden >/dev/null 2>&1; do :; done
	WARDEN_TEST_DATABASE_URL="$(DATABASE_URL)" $(GO) test -race -count=1 -p 1 ./internal/...

.PHONY: test-isolation
test-isolation: ## Run only the tenant-isolation suite, verbosely
	WARDEN_TEST_DATABASE_URL="$(DATABASE_URL)" $(GO) test -count=1 -v -run 'Tenant|Isolation|Classified|Protected' ./internal/store/...

.PHONY: test-cover
test-cover: ## Run the Go tests and write a coverage profile
	$(GO) test -race -count=1 -p 1 -coverprofile=coverage.out -covermode=atomic ./...
	$(GO) tool cover -func=coverage.out | tail -1

.PHONY: conformance
conformance: ## Run the conformance corpus against every registered evaluator
	$(GO) test -count=1 -v ./conformance/...

.PHONY: bench
bench: ## Run Go benchmarks
	$(GO) test -run='^$$' -bench=. -benchmem ./...

## -- Lint and format -------------------------------------------------------------

.PHONY: lint
lint: lint-go ## Run every linter

.PHONY: lint-go
lint-go: $(BIN)/golangci-lint ## Lint the Go code
	$(BIN)/golangci-lint run ./...
	$(GO) vet ./...

.PHONY: fmt
fmt: $(BIN)/golangci-lint ## Format the Go code in place
	$(BIN)/golangci-lint fmt ./...

.PHONY: fmt-check
fmt-check: $(BIN)/golangci-lint ## Fail if the Go code is not formatted
	@$(BIN)/golangci-lint fmt --diff ./... 2>&1 | tee /dev/stderr | (! grep -q .)

.PHONY: tidy
tidy: ## Tidy go.mod and fail if it was not already tidy
	$(GO) mod tidy
	@git diff --exit-code go.mod go.sum

## -- Database --------------------------------------------------------------------

# Migrations arrive with task M0-5; the tooling is wired now so that the target
# exists from the first commit and CI can exercise the up/down round trip.
DATABASE_URL ?= postgres://warden:warden@localhost:5432/warden?sslmode=disable
MIGRATIONS   := internal/store/migrations

.PHONY: migrate-up
migrate-up: $(BIN)/migrate ## Apply all pending migrations
	$(BIN)/migrate -path $(MIGRATIONS) -database "$(DATABASE_URL)" up

.PHONY: migrate-down
migrate-down: $(BIN)/migrate ## Roll back one migration
	$(BIN)/migrate -path $(MIGRATIONS) -database "$(DATABASE_URL)" down 1

.PHONY: migrate-new
migrate-new: $(BIN)/migrate ## Create a migration: make migrate-new NAME=add_widgets
	@test -n "$(NAME)" || { echo "usage: make migrate-new NAME=add_widgets" >&2; exit 2; }
	$(BIN)/migrate create -ext sql -dir $(MIGRATIONS) -seq $(NAME)

.PHONY: migrate-redo
migrate-redo: $(BIN)/migrate ## Roll every migration back and re-apply it
	$(BIN)/migrate -path $(MIGRATIONS) -database "$(DATABASE_URL)" down -all
	$(BIN)/migrate -path $(MIGRATIONS) -database "$(DATABASE_URL)" up

# The committed schema is the reviewable artefact. A migration whose effect on the
# schema is not what its author intended shows up as an unexpected diff here, in the
# pull request, rather than as a surprise in production.
#
# pg_dump runs inside the container so its version always matches the server's, and
# the non-deterministic header lines are stripped so the file only changes when the
# schema does.
SCHEMA_FILE := internal/store/schema.sql
PG_CONTAINER ?= warden-dev-postgres-1

# Note: the integration tests rebuild the schema in place, so run migrate-up (or
# migrate-redo) before dumping if they have run since.
.PHONY: schema-dump
schema-dump: ## Regenerate internal/store/schema.sql from a migrated database
	@docker exec $(PG_CONTAINER) pg_dump -U warden -d warden \
		--schema-only --no-owner --no-privileges --schema=public \
		| grep -vE '^(\\restrict|\\unrestrict|-- Dumped (from database|by pg_dump) version)' \
		| cat -s > $(SCHEMA_FILE)
	@echo "wrote $(SCHEMA_FILE)"

.PHONY: schema-check
schema-check: schema-dump ## Fail if the committed schema does not match the migrations
	@git diff --exit-code $(SCHEMA_FILE) || { \
		echo ""; \
		echo "The committed schema does not match the migrations."; \
		echo "Run 'make migrate-up schema-dump' and commit $(SCHEMA_FILE)."; \
		exit 1; \
	}

## -- Local environment -----------------------------------------------------------

.PHONY: dev-up
dev-up: ## Start Postgres, Redis and Mailpit for local development
	docker compose -f deploy/docker-compose.yml up -d

.PHONY: dev-roles
dev-roles: ## Create the local warden_app and warden_system roles (idempotent)
	@docker compose -f deploy/docker-compose.yml exec -T postgres \
		psql -U warden -d warden -q -v ON_ERROR_STOP=1 < deploy/dev-roles.sql
	@echo "warden_app and warden_system are ready"

.PHONY: dev-setup
dev-setup: dev-up migrate-up dev-roles ## Start the dependencies, migrate, and create the roles
	@echo "the development database is ready"

# The integration tests rebuild the schema by applying the migration files directly,
# which leaves no schema_migrations row and no grants — so a later `migrate-up` fails
# on objects that already exist. This puts the database back to a known state.
.PHONY: dev-reset-db
dev-reset-db: dev-up ## Drop and rebuild the development schema, then re-grant the roles
	@docker compose -f deploy/docker-compose.yml exec -T postgres \
		psql -U warden -d warden -q -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
	@$(MAKE) --no-print-directory migrate-up dev-roles

.PHONY: dev-down
dev-down: ## Stop the local development dependencies
	docker compose -f deploy/docker-compose.yml down

.PHONY: dev-reset
dev-reset: ## Stop the local dependencies and delete their data
	docker compose -f deploy/docker-compose.yml down -v

## -- Security --------------------------------------------------------------------

.PHONY: audit
audit: audit-go ## Run every dependency audit

.PHONY: audit-go
audit-go: $(BIN)/govulncheck ## Check Go dependencies for known vulnerabilities
	$(BIN)/govulncheck ./...

.PHONY: kek
kek: ## Print a fresh key-encryption key, for local use only
	@openssl rand -base64 32

## -- Housekeeping ----------------------------------------------------------------

.PHONY: clean
clean: ## Remove build output
	rm -rf $(BIN) coverage.out

.PHONY: ci
ci: fmt-check lint test tidy ## Everything CI runs, in the order CI runs it

## -- Tools -----------------------------------------------------------------------

$(BIN)/golangci-lint:
	GOBIN=$(BIN) $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)

$(BIN)/migrate:
	GOBIN=$(BIN) $(GO) install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@$(MIGRATE_VERSION)

$(BIN)/govulncheck:
	GOBIN=$(BIN) $(GO) install golang.org/x/vuln/cmd/govulncheck@latest

.PHONY: tools
tools: $(BIN)/golangci-lint $(BIN)/migrate $(BIN)/govulncheck ## Install every pinned development tool
