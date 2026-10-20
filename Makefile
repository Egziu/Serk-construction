# SERK Construction — financial kernel vertical slice
GO      ?= go
PKGS    := ./...
ADMIN_DSN ?= postgres://postgres:postgres@localhost:5432/serk_construction?sslmode=disable
APP_DSN   ?= postgres://serk_api:serk_api@localhost:5432/serk_construction?sslmode=disable

.PHONY: all build test test-unit test-integration vet fmt lint migrate run db-up db-down token clean

all: fmt vet test build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o bin/serk-api ./cmd/serk-api
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o bin/serk-migrate ./cmd/serk-migrate

fmt:
	gofmt -l . | tee /dev/stderr | test -z "$$(cat)"

vet:
	$(GO) vet $(PKGS)

test-unit:
	$(GO) test -race -count=1 ./pkg/...

# Integration tests need PostgreSQL 16 (make db-up) and the two DSNs.
test-integration:
	SERK_TEST_ADMIN_DSN="$(ADMIN_DSN)" SERK_TEST_APP_DSN="$(APP_DSN)" $(GO) test -race -count=1 ./internal/...

test: test-unit test-integration

migrate:
	SERK_ADMIN_DSN="$(ADMIN_DSN)" $(GO) run ./cmd/serk-migrate

run:
	SERK_APP_DSN="$(APP_DSN)" $(GO) run ./cmd/serk-api

db-up:
	docker compose -f deploy/docker-compose.yml up -d db
	@echo "waiting for postgres..."; sleep 4
	docker compose -f deploy/docker-compose.yml exec -T db psql -U postgres -d serk_construction -v ON_ERROR_STOP=1 -f /docker-entrypoint-initdb.d/00-roles.sql

db-down:
	docker compose -f deploy/docker-compose.yml down -v

clean:
	rm -rf bin
