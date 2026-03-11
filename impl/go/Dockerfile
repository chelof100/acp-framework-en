# ─── Stage 1: Build ───────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

# Install build dependencies.
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Cache dependencies layer.
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /acp-server ./cmd/acp-server

# ─── Stage 2: Runtime ─────────────────────────────────────────────────────────
# Use distroless for minimal attack surface.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /acp-server /acp-server
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 8080

# Environment defaults (override at runtime).
ENV ACP_ADDR=:8080

ENTRYPOINT ["/acp-server"]
