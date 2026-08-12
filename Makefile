.PHONY: test build network up
test:
	CGO_ENABLED=0 go test ./...
build:
	CGO_ENABLED=0 go build -o bin/kydns ./cmd/kydns

# Create the LAN network KyDNS joins, if it is not already there. Safe to
# re-run: it never touches an existing network.
network:
	./scripts/create-network.sh

up: network
	docker compose up -d
