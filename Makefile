.PHONY: test build setup up dist package clean
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

# Debian versions must start with a digit, so a tag's leading "v" is stripped
# by the caller. This default is what a local build gets.
VERSION ?= 0.0.0-dev
ARCHES := amd64 arm64
DIST := dist

# The staging directory is also the tarball's one top-level entry, so
# extracting does not scatter kydns, LICENSE, and the example config across
# whoever's current directory.
dist:
	rm -rf dist
	for arch in $(ARCHES); do \
		stage=kydns_$(VERSION)_linux_$$arch; \
		mkdir -p $(DIST)/$$stage; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath \
			-ldflags "-s -w -X main.version=$(VERSION)" \
			-o $(DIST)/$$stage/kydns ./cmd/kydns || exit 1; \
		cp kydns.example.yaml LICENSE $(DIST)/$$stage/ || exit 1; \
		tar -czf $(DIST)/$$stage.tar.gz -C $(DIST) $$stage || exit 1; \
	done

package: dist
	for arch in $(ARCHES); do \
		ARCH=$$arch VERSION=$(VERSION) \
			go tool nfpm package -f nfpm.yaml -p deb \
				-t $(DIST)/kydns_$(VERSION)_$$arch.deb || exit 1; \
	done

clean:
	rm -rf dist
