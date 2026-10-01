# ---- Build stage ----
FROM golang:1.27-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS builder

RUN apk add --no-cache git ca-certificates

# Allow Go to auto-download the toolchain version specified in go.mod.
ENV GOTOOLCHAIN=auto

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build all binaries.
# VERSION is stamped into the MCP server only: it is the one binary whose
# version an external client sees, in the MCP initialize handshake.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/ingestion-watcher ./cmd/ingestion-watcher/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/parsing-worker    ./cmd/parsing-worker/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/api-gateway       ./cmd/api-gateway/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/cve-refresher     ./cmd/cve-refresher/
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=${VERSION}" -o /bin/mcp-server ./cmd/mcp-server/

# ---- Ingestion Watcher ----
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS ingestion-watcher
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/ingestion-watcher /usr/local/bin/ingestion-watcher
USER nobody:nobody
ENTRYPOINT ["ingestion-watcher"]

# ---- Parsing Worker ----
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS parsing-worker
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/parsing-worker /usr/local/bin/parsing-worker
USER nobody:nobody
ENTRYPOINT ["parsing-worker"]

# ---- API Gateway ----
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS api-gateway
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/api-gateway /usr/local/bin/api-gateway
USER nobody:nobody
EXPOSE 8080
ENTRYPOINT ["api-gateway"]

# ---- CVE Refresher ----
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS cve-refresher
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/cve-refresher /usr/local/bin/cve-refresher
USER nobody:nobody
ENTRYPOINT ["cve-refresher"]

# ---- MCP Server (#399) ----
# No EXPOSE: the default transport is stdio, and the HTTP transport is opt-in
# (MCP_TRANSPORT=http) and refuses to start without a token and an explicit
# Origin allow-list. Declaring a port here would suggest the opposite default.
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS mcp-server
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/mcp-server /usr/local/bin/mcp-server
USER nobody:nobody
ENTRYPOINT ["mcp-server"]

