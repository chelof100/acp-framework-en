# ACP Framework — Makefile
#
# Targets:
#   make demo          — start the ACP server with the RFC 8037 dev key, run health check
#   make build         — build the Go server binary
#   make test          — run all Go tests
#   make vectors       — run conformance test vectors
#   make python-demo   — run the Python admission control demo (offline)
#   make docker-build  — build the Docker image locally
#   make docker-push   — push to GHCR (requires docker login ghcr.io)
#   make clean         — remove build artifacts

.PHONY: demo build test vectors python-demo docker-build docker-push clean

# RFC 8037 Test Key A — for development only
DEV_PUBKEY := cA4s58S2dEJ-qye6EpJaJKKaVfvPT8mAQf97Vo8TInk
GO_DIR     := impl/go
PY_DIR     := impl/python
IMAGE      := ghcr.io/chelof100/acp-server

# ─── demo ─────────────────────────────────────────────────────────────────────
demo:
	@echo "=== Starting ACP reference server (dev mode) ==="
	@echo "Institution key: $(DEV_PUBKEY) (RFC 8037 Test Key A)"
	@echo ""
	@cd $(GO_DIR) && ACP_INSTITUTION_PUBLIC_KEY=$(DEV_PUBKEY) go run ./cmd/acp-server &
	@sleep 2
	@echo "=== Health check ==="
	@curl -s http://localhost:8080/acp/v1/health | python3 -m json.tool 2>/dev/null || curl -s http://localhost:8080/acp/v1/health
	@echo ""
	@echo "Server running on http://localhost:8080"
	@echo "Press Ctrl+C to stop."
	@wait

# ─── build ────────────────────────────────────────────────────────────────────
build:
	@echo "=== Building ACP server ==="
	cd $(GO_DIR) && go build -ldflags="-s -w" -o acp-server ./cmd/acp-server
	@echo "Binary: $(GO_DIR)/acp-server"

# ─── test ─────────────────────────────────────────────────────────────────────
test:
	@echo "=== Running Go tests ==="
	cd $(GO_DIR) && go test ./...

# ─── vectors ──────────────────────────────────────────────────────────────────
vectors: build
	@echo "=== Running conformance test vectors ==="
	cd $(GO_DIR) && go build ./cmd/acp-evaluate
	cd $(GO_DIR) && go run ./cmd/acp-runner \
		--impl ./acp-evaluate \
		--suite ../../compliance/test-vectors
	@echo "Expected: 42/42 PASS"

# ─── python-demo ──────────────────────────────────────────────────────────────
python-demo:
	@echo "=== ACP Python admission control demo (offline) ==="
	cd $(PY_DIR) && pip install -e . -q && python examples/admission_control_demo.py

# ─── docker-build ─────────────────────────────────────────────────────────────
docker-build:
	@echo "=== Building Docker image: $(IMAGE):latest ==="
	docker build -t $(IMAGE):latest $(GO_DIR)/

# ─── docker-push ──────────────────────────────────────────────────────────────
docker-push: docker-build
	@echo "=== Pushing to GHCR ==="
	docker push $(IMAGE):latest

# ─── clean ────────────────────────────────────────────────────────────────────
clean:
	cd $(GO_DIR) && rm -f acp-server acp-server.exe acp-evaluate acp-evaluate.exe \
		acp-runner acp-runner.exe acp-sign-vectors acp-sign-vectors.exe \
		gen-ledger-vectors gen-ledger-vectors.exe gen-exec-vectors gen-exec-vectors.exe
	@echo "Clean complete."
