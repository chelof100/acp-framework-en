# Multi-stage Dockerfile for the ACP multi-org demo.
# Build context MUST be the repo root (ACP-PROTOCOL-EN/).
# The ARG ORG selects which binary to build: "org-a" or "org-b".
#
# Usage (from repo root):
#   docker build --build-arg ORG=org-a -f examples/multi-org-demo/Dockerfile -t acp-org-a .
#   docker build --build-arg ORG=org-b -f examples/multi-org-demo/Dockerfile -t acp-org-b .
#
# Or simply: docker compose up  (from examples/multi-org-demo/)

ARG ORG=org-a

# ── Builder ──────────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /src

# Copy the impl/go packages (policyctx, reputation) — needed by replace directive.
COPY impl/go ./impl/go

# Copy the demo module.
COPY examples/multi-org-demo ./examples/multi-org-demo

WORKDIR /src/examples/multi-org-demo

# Use the pre-committed go.sum; download modules from the module proxy.
ARG ORG
RUN go build -trimpath -o /app ./${ORG}

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM alpine:3.19

COPY --from=builder /app /app

# org-a listens on 8080, org-b on 8081 — the correct port is set in docker-compose.
EXPOSE 8080 8081

ENTRYPOINT ["/app"]
