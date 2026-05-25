# syntax=docker/dockerfile:1.3

FROM golang:1-trixie AS builder

WORKDIR /app

# Use cache for go mod download
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
# Use cache for go build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -o controller ./cmd/controller

FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/controller .

ENTRYPOINT ["/app/controller"]
