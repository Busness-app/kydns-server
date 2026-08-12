.PHONY: test build setup up
test:
	CGO_ENABLED=0 go test ./...
build:
	CGO_ENABLED=0 go build -o bin/kydns ./cmd/kydns

# Fill in .env from the host default route. Safe to re-run: it only adds
# keys that are missing.
setup:
	./scripts/setup-env.sh

up: setup
	docker compose up -d
