.PHONY: test build setup up dist package rpi-image clean
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

# rpm forbids "-" in a version and nfpm rewrites it to "~", so the file name
# has to be built from the same substitution or it disagrees with the metadata
# inside the package.
RPMVERSION = $(subst -,~,$(VERSION))
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
		case $$arch in \
		amd64) rpmarch=x86_64 ;; \
		arm64) rpmarch=aarch64 ;; \
		*) echo "no rpm arch known for $$arch"; exit 1 ;; \
		esac; \
		ARCH=$$arch VERSION=$(VERSION) \
			go tool nfpm package -f nfpm.yaml -p rpm \
				-t $(DIST)/kydns-$(RPMVERSION)-1.$$rpmarch.rpm || exit 1; \
	done

# Raspberry Pi OS Lite supplies the bootloader, kernel, and Debian userspace;
# the image builder stages the arm64 package and installs it on first boot.
#
# The base is pinned to one release and its published checksum, in
# packaging/rpi-base.pin. A release is signed and attested, so what it was
# built on top of has to be a reviewed decision and not a moving download.
# .github/workflows/rpi-base.yml proposes the next one.
RPI_PIN := packaging/rpi-base.pin
RPI_BASE_URL ?= $(word 1,$(shell cat $(RPI_PIN)))
RPI_BASE_SHA256 ?= $(word 2,$(shell cat $(RPI_PIN)))
RPI_IMAGE ?= $(DIST)/kydns_$(VERSION)_rpi64.img
SUDO ?= sudo

rpi-image: package
	$(SUDO) ./scripts/build-rpi-image.sh \
		$(DIST)/kydns_$(VERSION)_arm64.deb \
		$(RPI_IMAGE) \
		$(RPI_BASE_URL) \
		$(RPI_BASE_SHA256)

clean:
	rm -rf dist
