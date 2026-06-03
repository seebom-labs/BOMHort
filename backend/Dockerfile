# ---- Build stage ----
FROM golang:1.25-alpine@sha256:c05ba4b73604069d376c4f41346b05374335b5ca0c46fb6dfede5a59f5196931 AS builder

RUN apk add --no-cache git ca-certificates

# Allow Go to auto-download the toolchain version specified in go.mod.
ENV GOTOOLCHAIN=auto

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build all binaries.
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/ingestion-watcher ./cmd/ingestion-watcher/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/parsing-worker    ./cmd/parsing-worker/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/api-gateway       ./cmd/api-gateway/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/cve-refresher     ./cmd/cve-refresher/

# ---- Ingestion Watcher ----
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d AS ingestion-watcher
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/ingestion-watcher /usr/local/bin/ingestion-watcher
USER nobody:nobody
ENTRYPOINT ["ingestion-watcher"]

# ---- Parsing Worker ----
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d AS parsing-worker
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/parsing-worker /usr/local/bin/parsing-worker
USER nobody:nobody
ENTRYPOINT ["parsing-worker"]

# ---- API Gateway ----
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d AS api-gateway
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/api-gateway /usr/local/bin/api-gateway
USER nobody:nobody
EXPOSE 8080
ENTRYPOINT ["api-gateway"]

# ---- CVE Refresher ----
FROM alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d AS cve-refresher
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/cve-refresher /usr/local/bin/cve-refresher
USER nobody:nobody
ENTRYPOINT ["cve-refresher"]

