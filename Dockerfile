# syntax=docker/dockerfile:1

# Build stage. CGO stays off so the pure-Go SQLite driver is used and the
# binary runs on a distroless base with no libc.
FROM golang:1.26-alpine AS build

WORKDIR /src

# Dependencies first, so a source-only change does not re-download them.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kydns ./cmd/kydns

# Runtime stage. distroless/static carries CA certificates, which HTTPS health
# checks need, and nothing else — no shell, no package manager.
FROM gcr.io/distroless/static-debian12:latest

COPY --from=build /out/kydns /usr/local/bin/kydns
COPY kydns.example.yaml /usr/share/kydns/kydns.example.yaml

# The database and the first-run tokens live here. Mount a volume over it.
VOLUME ["/var/lib/kydns"]

# Documentation only: with host networking these are not published, they are
# simply the ports the process binds.
EXPOSE 53/udp 53/tcp 8053/tcp

ENTRYPOINT ["/usr/local/bin/kydns"]
CMD ["serve", "--config", "/etc/kydns/kydns.yaml"]
