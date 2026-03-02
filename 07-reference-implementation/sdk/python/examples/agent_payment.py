"""
Example: AI Agent executing a payment using ACP (ACP-HP-1.0).

Demonstrates the full verification flow:
  1. Generate agent identity (Ed25519)
  2. Issue + sign a capability token (in production: done by institutional issuer)
  3. Connect to an ACP server and call client.verify()

Requirements:
    pip install acp-sdk           # or: pip install cryptography
    Optional: set ACP_AGENT_SEED  # 32 bytes hex — for deterministic identity
    Optional: set ACP_SERVER_URL  # default: http://localhost:8080

Run:
    python examples/agent_payment.py

To test with the Go reference server:
    cd acp-go && go build -o acp-server.exe ./cmd/acp-server
    ./acp-server.exe &
    python examples/agent_payment.py
"""
from __future__ import annotations

import json
import os
import secrets
import time

from acp.identity import AgentIdentity
from acp.signer import ACPSigner
from acp.client import ACPClient, ACPError


def _load_identity() -> AgentIdentity:
    """Load from ACP_AGENT_SEED env var, or generate a new ephemeral identity."""
    seed_hex = os.getenv("ACP_AGENT_SEED", "")
    if seed_hex:
        return AgentIdentity.from_private_bytes(bytes.fromhex(seed_hex))
    print("[INFO] ACP_AGENT_SEED not set — generating ephemeral identity")
    return AgentIdentity.generate()


def _build_payment_token(
    issuer: AgentIdentity,
    subject: AgentIdentity,
) -> dict:
    """
    Build and sign a financial.payment capability token.

    NOTE: In production, the institutional issuer creates and signs tokens.
          This local demo uses a freshly generated issuer for illustration.
    """
    now = int(time.time())
    nonce = secrets.token_urlsafe(16)

    capability = {
        "ver": "1.0",
        "jti": secrets.token_urlsafe(16),
        "iss": issuer.did,
        "sub": subject.agent_id,
        "iat": now,
        "exp": now + 3600,
        "nonce": nonce,
        "capabilities": ["acp:cap:financial.payment"],
        "constraints": {
            "max_amount_usd": 10000,
            "allowed_accounts": ["ACC-001", "ACC-002"],
        },
    }

    signer = ACPSigner(issuer)
    return signer.sign_capability(capability)


def main() -> None:
    print("=== ACP Python SDK — Agent Payment Example (ACP-HP-1.0) ===\n")

    # Step 1 — Agent identity
    agent = _load_identity()
    signer = ACPSigner(agent)
    print(f"Agent ID  : {agent.agent_id}")
    print(f"Agent DID : {agent.did}")
    print(f"Pubkey    : {agent.public_key_bytes.hex()[:24]}...\n")

    # Step 2 — Issuer (separate identity; in production: institutional system)
    issuer = AgentIdentity.generate()
    print(f"Issuer DID: {issuer.did}\n")

    # Step 3 — Signed capability token
    token = _build_payment_token(issuer, agent)
    print("Capability token (summary):")
    print(f"  jti         : {token['jti']}")
    print(f"  capabilities: {token['capabilities']}")
    print(f"  exp         : {token['exp']} (now+1h)")
    print(f"  signature   : {token['proof']['signature'][:32]}...\n")

    # Step 4 — Verify signature locally (no server needed)
    is_valid = ACPSigner.verify_capability(token, issuer.public_key_bytes)
    print(f"Local signature valid : {is_valid}")

    # Step 5 — Connect to ACP server and run full PoP handshake
    server_url = os.getenv("ACP_SERVER_URL", "http://localhost:8080")
    client = ACPClient(
        server_url=server_url,
        identity=agent,
        signer=signer,
    )

    print(f"\nConnecting to ACP server: {server_url}")
    try:
        health = client.health()
        print(f"Server health: {health}\n")
    except ACPError as e:
        print(f"[Server not reachable — {e}]")
        print("Continuing with local verification only.\n")
        _show_offline_demo(agent, signer, token)
        return

    # Full ACP-HP-1.0 verification (challenge → PoP → verify)
    print("Running full ACP-HP-1.0 verification flow...")
    try:
        result = client.verify(
            capability_token=token,
            requested_capability="acp:cap:financial.payment",
            requested_resource="org.banco-soberano/accounts/ACC-001",
        )
        print(f"Decision  : {result.get('decision')}")
        print(f"Full response: {json.dumps(result, indent=2)}")
    except ACPError as e:
        print(f"ACP error (status={e.status_code}): {e}")


def _show_offline_demo(
    agent: AgentIdentity,
    signer: ACPSigner,
    token: dict,
) -> None:
    """Show what the PoP payload would look like without a live server."""
    import base64
    import hashlib

    fake_challenge = base64.urlsafe_b64encode(b"demo-challenge-nonce").rstrip(b"=").decode()
    capability_id = "acp:cap:financial.payment"
    binding = f"{fake_challenge}.{agent.agent_id}.{capability_id}".encode()
    digest = hashlib.sha256(binding).digest()
    sig_bytes = signer.sign_bytes(digest)
    sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()

    print("--- Offline PoP demo ---")
    print(f"Challenge : {fake_challenge}")
    print(f"Agent ID  : {agent.agent_id}")
    print(f"Capability: {capability_id}")
    print(f"PoP sig   : {sig_b64[:40]}...")
    print("\nTo run the full flow, start the Go reference server:")
    print("  cd acp-go && go build -o acp-server.exe ./cmd/acp-server && ./acp-server.exe")
    print("  ACP_SERVER_URL=http://localhost:8080 python examples/agent_payment.py")


if __name__ == "__main__":
    main()
