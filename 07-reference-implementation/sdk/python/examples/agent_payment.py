"""
Example: AI Agent executing a payment using ACP (ACP-HP-1.0).

Full end-to-end demonstration:
  1. Generate institution key pair (or load from ACP_INSTITUTION_SEED)
  2. Generate agent identity
  3. Build + sign capability token (institution signs, agent is subject)
  4. Register agent with ACP server
  5. Run full PoP handshake: challenge → sign → verify via HTTP headers

To test with the Go reference server:
    cd acp-go && go build -o acp-server.exe ./cmd/acp-server

    # Run this script ONCE with --print-pubkey to get the institution pubkey:
    python examples/agent_payment.py --print-pubkey

    # Start server with that pubkey:
    ACP_INSTITUTION_PUBLIC_KEY=<output_above> ./acp-server.exe

    # Run the full demo:
    python examples/agent_payment.py

Environment variables:
    ACP_SERVER_URL        default: http://localhost:8080
    ACP_AGENT_SEED        hex(32 bytes) — deterministic agent identity
    ACP_INSTITUTION_SEED  hex(32 bytes) — deterministic institution key
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sys
import time

from acp.identity import AgentIdentity
from acp.signer import ACPSigner
from acp.client import ACPClient, ACPError


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _load_identity(env_var: str) -> AgentIdentity:
    """Load identity from <env_var> hex seed, or generate a new ephemeral one."""
    seed_hex = os.getenv(env_var, "")
    if seed_hex:
        return AgentIdentity.from_private_bytes(bytes.fromhex(seed_hex))
    return AgentIdentity.generate()


def _build_payment_token(
    issuer: AgentIdentity,
    subject: AgentIdentity,
) -> dict:
    """
    Build and sign a financial.payment capability token.

    Token fields follow ACP-CT-1.0 CapabilityToken schema exactly:
      ver, iss, sub, cap, resource, iat, exp, nonce, sig

    In production: the institutional issuer creates and signs tokens.
    This demo uses a local issuer key — match it to ACP_INSTITUTION_PUBLIC_KEY.
    """
    now = int(time.time())
    capability = {
        "ver": "1.0",
        "iss": issuer.did,
        "sub": subject.agent_id,           # must match X-ACP-Agent-ID header
        "cap": ["acp:cap:financial.payment"],
        "resource": "org.banco-soberano/accounts/ACC-001",
        "iat": now,
        "exp": now + 3600,
        "nonce": secrets.token_urlsafe(16),
    }
    signer = ACPSigner(issuer)
    return signer.sign_capability(capability)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    # --print-pubkey mode: just print the institution public key and exit
    if "--print-pubkey" in sys.argv:
        institution = _load_identity("ACP_INSTITUTION_SEED")
        pubkey_b64 = base64.urlsafe_b64encode(
            institution.public_key_bytes
        ).rstrip(b"=").decode()
        print(pubkey_b64)
        return

    print("=== ACP Python SDK — Agent Payment Example (ACP-HP-1.0) ===\n")

    # Step 1 — Identities
    institution = _load_identity("ACP_INSTITUTION_SEED")
    if not os.getenv("ACP_INSTITUTION_SEED"):
        print("[INFO] ACP_INSTITUTION_SEED not set — generating ephemeral institution key")
        print("[INFO] To test against Go server, run with --print-pubkey first\n")

    agent = _load_identity("ACP_AGENT_SEED")
    if not os.getenv("ACP_AGENT_SEED"):
        print("[INFO] ACP_AGENT_SEED not set — generating ephemeral agent identity\n")

    agent_signer = ACPSigner(agent)

    pubkey_b64 = base64.urlsafe_b64encode(
        institution.public_key_bytes
    ).rstrip(b"=").decode()

    print(f"Institution pubkey : {pubkey_b64[:32]}...")
    print(f"Agent ID           : {agent.agent_id}")
    print(f"Agent DID          : {agent.did}")
    print(f"Agent pubkey       : {agent.public_key_bytes.hex()[:24]}...\n")

    # Step 2 — Issue + sign capability token (institution signs)
    token = _build_payment_token(institution, agent)
    print("Capability token:")
    print(f"  sub      : {token['sub']}")
    print(f"  cap      : {token['cap']}")
    print(f"  resource : {token['resource']}")
    print(f"  exp      : {token['exp']} (now+1h)")
    print(f"  sig      : {token['sig'][:32]}...\n")

    # Step 3 — Verify signature locally (no server needed)
    is_valid = ACPSigner.verify_capability(token, institution.public_key_bytes)
    print(f"Local signature valid: {is_valid}\n")

    # Step 4 — Connect to ACP server
    server_url = os.getenv("ACP_SERVER_URL", "http://localhost:8080")
    client = ACPClient(server_url=server_url, identity=agent, signer=agent_signer)

    print(f"Connecting to ACP server: {server_url}")
    try:
        health = client.health()
        print(f"Server health: {health}\n")
    except ACPError as e:
        print(f"[Server not reachable — {e}]")
        print("Continuing with offline PoP demo.\n")
        _show_offline_demo(agent, agent_signer)
        return

    # Step 5 — Register agent
    print("Registering agent...")
    try:
        reg = client.register()
        print(f"Registration: {reg}\n")
    except ACPError as e:
        print(f"Registration failed (status={e.status_code}): {e}\n")
        return

    # Step 6 — Full ACP-HP-1.0 verification (challenge → PoP headers → verify)
    print("Running full ACP-HP-1.0 verification flow...")
    try:
        result = client.verify(capability_token=token)
        print(f"Full response: {json.dumps(result, indent=2)}")
    except ACPError as e:
        print(f"ACP error (status={e.status_code}): {e}")


def _show_offline_demo(agent: AgentIdentity, signer: ACPSigner) -> None:
    """Show what the PoP payload would look like without a live server."""
    fake_challenge = base64.urlsafe_b64encode(b"demo-challenge-nonce").rstrip(b"=").decode()
    method, path = "POST", "/acp/v1/verify"
    body = b""
    body_hash = hashlib.sha256(body).digest()
    body_hash_b64 = base64.urlsafe_b64encode(body_hash).rstrip(b"=").decode()
    signed_payload = f"{method}|{path}|{fake_challenge}|{body_hash_b64}"
    payload_hash = hashlib.sha256(signed_payload.encode()).digest()
    sig_bytes = signer.sign_bytes(payload_hash)
    sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()

    print("--- Offline PoP demo (ACP-HP-1.0 channel binding) ---")
    print(f"  signed_payload : {signed_payload}")
    print(f"  X-ACP-Signature: {sig_b64[:40]}...")
    print("\nTo run the full flow:")
    print("  1. Get institution pubkey:")
    print("       python examples/agent_payment.py --print-pubkey")
    print("  2. Start Go server:")
    print("       ACP_INSTITUTION_PUBLIC_KEY=<pubkey> ./acp-server.exe")
    print("  3. Run demo:")
    print("       python examples/agent_payment.py")


if __name__ == "__main__":
    main()
