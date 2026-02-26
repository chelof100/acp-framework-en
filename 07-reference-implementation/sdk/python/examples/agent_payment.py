"""
Example: AI Agent executing a payment using ACP.
Demonstrates the full ACP-HP-1.0 flow for an autonomous agent.

Requirements:
    pip install acp-sdk
    Environment: ACP_AGENT_SEED (32 bytes hex-encoded)
"""

import os
import json
import base64
import secrets
import time

from acp import ACPIdentity, ACPClient, sign_token


def load_or_generate_identity() -> ACPIdentity:
    """Load agent identity from env, or generate a new one."""
    seed_hex = os.getenv("ACP_AGENT_SEED")
    if seed_hex:
        seed = bytes.fromhex(seed_hex)
        return ACPIdentity.from_seed(seed)
    else:
        print("[WARNING] ACP_AGENT_SEED not set — generating ephemeral identity")
        return ACPIdentity.generate()


def create_example_token(
    issuer_identity: ACPIdentity,
    agent_identity: ACPIdentity,
) -> str:
    """Create a signed capability token for demonstration.

    In production, tokens are issued by the institutional issuer,
    NOT by the agent itself. This is for local testing only.
    """
    now = int(time.time())
    payload = {
        "ver": "1.0",
        "iss": issuer_identity.agent_id,
        "sub": agent_identity.agent_id,
        "cap": ["acp:cap:financial.payment"],
        "res": "org.banco-soberano/accounts/ACC-001",
        "iat": now,
        "exp": now + 3600,  # 1 hour
        "nonce": base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode(),
        "deleg": {"allowed": False, "max_depth": 0},
        "parent_hash": None,
        "constraints": {"max_amount_usd": 10000},
        "rev": {
            "type": "endpoint",
            "uri": "https://acp.banco-soberano.com/acp/v1/rev/check",
        },
    }
    signed = sign_token(payload, issuer_identity)
    return json.dumps(signed)


def main() -> None:
    print("=== ACP Reference Implementation — Agent Payment Example ===\n")

    # 1. Load agent identity.
    agent = load_or_generate_identity()
    print(f"Agent AgentID : {agent.agent_id}")
    print(f"Agent PubKey  : {agent.public_key_bytes.hex()[:16]}...\n")

    # 2. For this example, the issuer is a separate identity.
    #    In production: the token is issued by the institution's system.
    issuer = ACPIdentity.generate()
    print(f"Issuer AgentID: {issuer.agent_id}\n")

    # 3. Create a capability token (issuer signs it).
    token_json = create_example_token(issuer, agent)
    print("Capability Token (truncated):")
    print(f"  {token_json[:80]}...\n")

    # 4. Initialize ACP client.
    #    Point to your ACP server (e.g., the Go reference implementation).
    base_url = os.getenv("ACP_SERVER_URL", "http://localhost:8080")
    client = ACPClient(agent, base_url=base_url)

    # 5. Execute the action — handshake happens automatically.
    transfer_payload = {
        "to_account": "ACC-999",
        "amount": 500,
        "currency": "USD",
        "memo": "Invoice payment #2024-001",
    }

    print(f"Executing payment: {transfer_payload}")
    print(f"Server: {base_url}\n")

    try:
        response = client.execute(
            method="POST",
            path="/api/v1/payments/transfer",
            capability_token=token_json,
            payload=transfer_payload,
        )
        print(f"Response status : {response.status_code}")
        print(f"Response body   : {response.text[:200]}")
    except Exception as e:
        print(f"[Expected in demo without server] {type(e).__name__}: {e}")
        print("\nTo test with the Go server:")
        print("  cd acp-go && go run ./cmd/acp-server")
        print("  ACP_SERVER_URL=http://localhost:8080 python examples/agent_payment.py")


if __name__ == "__main__":
    main()
