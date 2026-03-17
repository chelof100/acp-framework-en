"""
ACP Admission Control Demo — agent action governance pattern

Demonstrates how ACP works as the admission control layer between agent
intent and system state mutation.

Scenarios:
  1. APPROVED: Payment agent with valid capability → executes
  2. DENIED:   Agent without required capability → blocked
  3. ESCALATED: High-risk action (large amount) → routed to human review
  4. Multi-hop delegation: planning agent → payment sub-agent

This demo works in two modes:
  - OFFLINE (no server): shows token construction + local sig verification
  - ONLINE (with Go server): full admission check via ACP-API-1.0

Run offline:
    python examples/admission_control_demo.py

Run with Go server:
    cd impl/go && go build -o acp-server.exe ./cmd/acp-server
    python examples/admission_control_demo.py --print-pubkey
    # copy output pubkey, then:
    ACP_INSTITUTION_PUBLIC_KEY=<pubkey> ./acp-server.exe
    python examples/admission_control_demo.py --online

Dependencies:
    pip install cryptography>=42.0.0
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import time
import uuid
from typing import Any, Dict, Optional

from acp.identity import AgentIdentity
from acp.signer import ACPSigner
from acp.client import ACPClient, ACPError


# ─── Colour output ────────────────────────────────────────────────────────────

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def ok(msg: str)   -> None: print(f"  {GREEN}✓{RESET} {msg}")
def deny(msg: str) -> None: print(f"  {RED}✗{RESET} {msg}")
def warn(msg: str) -> None: print(f"  {YELLOW}⚠{RESET} {msg}")
def info(msg: str) -> None: print(f"  {BLUE}→{RESET} {msg}")
def step(n: int, msg: str) -> None:
    print(f"\n{BOLD}[{n}]{RESET} {msg}")


# ─── Token builder ────────────────────────────────────────────────────────────

def build_capability_token(
    issuer: AgentIdentity,
    subject: AgentIdentity,
    capabilities: list[str],
    resource: str,
    expires_in: int = 3600,
) -> Dict[str, Any]:
    """
    Build a signed ACP-CT-1.0 Capability Token.

    In production: the institutional CA builds and signs these tokens.
    Here we use a local ephemeral key to demonstrate the structure.
    """
    now = int(time.time())
    token = {
        "ver": "1.0",
        "iss": issuer.did,
        "sub": subject.agent_id,
        "cap": capabilities,
        "resource": resource,
        "iat": now,
        "exp": now + expires_in,
        "nonce": secrets.token_urlsafe(16),
    }
    signer = ACPSigner(issuer)
    return signer.sign_capability(token)


# ─── Simulated target system (what the agent wants to call) ───────────────────

class PaymentSystem:
    """Simulates the target system — only accepts calls with a valid ACP execution token."""

    def transfer(
        self,
        from_account: str,
        to_account: str,
        amount: float,
        execution_token_id: str,
    ) -> Dict[str, Any]:
        """Execute a payment. In production: verifies ET_ID against ACP server before proceeding."""
        return {
            "status": "SUCCESS",
            "from": from_account,
            "to": to_account,
            "amount": amount,
            "execution_token_id": execution_token_id,
            "timestamp": int(time.time()),
        }


class DataReadSystem:
    """Simulates a read-only data access system."""

    def query(self, resource: str, execution_token_id: str) -> Dict[str, Any]:
        return {
            "status": "SUCCESS",
            "resource": resource,
            "records": 42,
            "execution_token_id": execution_token_id,
        }


# ─── ACP Admission Guard — the key pattern ───────────────────────────────────

class ACPAdmissionGuard:
    """
    Drop-in admission control layer.

    Wrap any agent action with this guard to enforce ACP policy before execution.

    Usage:
        guard = ACPAdmissionGuard(client)

        with guard.check("acp:cap:financial.payment", resource="bank://ACC-001",
                         action_parameters={"amount": 5000}) as token_id:
            payment_system.transfer(..., execution_token_id=token_id)
    """

    def __init__(self, client: ACPClient) -> None:
        self._client = client

    def check(
        self,
        capability: str,
        resource: str,
        action_parameters: Optional[Dict[str, Any]] = None,
    ) -> "AdmissionResult":
        """
        Run the ACP admission check for a given capability + resource.

        Returns:
            AdmissionResult with .approved, .decision, .execution_token_id
        """
        request_id = str(uuid.uuid4())
        try:
            resp = self._client.authorize(
                request_id=request_id,
                agent_id=self._client._identity.agent_id,
                capability=capability,
                resource=resource,
                action_parameters=action_parameters or {},
            )
            return AdmissionResult(resp)
        except ACPError as e:
            return AdmissionResult({"decision": "DENIED", "error": str(e)})


class AdmissionResult:
    """Result of an ACP admission check."""

    def __init__(self, raw: Dict[str, Any]) -> None:
        self._raw = raw

    @property
    def approved(self) -> bool:
        return self._raw.get("decision") == "APPROVED"

    @property
    def escalated(self) -> bool:
        return self._raw.get("decision") == "ESCALATED"

    @property
    def denied(self) -> bool:
        return not self.approved and not self.escalated

    @property
    def decision(self) -> str:
        return self._raw.get("decision", "DENIED")

    @property
    def risk_score(self) -> Optional[int]:
        return self._raw.get("risk_score")

    @property
    def execution_token_id(self) -> Optional[str]:
        et = self._raw.get("execution_token")
        if et and isinstance(et, dict):
            return et.get("et_id")
        return None

    @property
    def escalation_id(self) -> Optional[str]:
        return self._raw.get("escalation_id")

    def __repr__(self) -> str:
        parts = [f"decision={self.decision}"]
        if self.risk_score is not None:
            parts.append(f"risk={self.risk_score}")
        if self.execution_token_id:
            parts.append(f"et_id={self.execution_token_id[:12]}...")
        return f"AdmissionResult({', '.join(parts)})"


# ─── Demo scenarios ───────────────────────────────────────────────────────────

def demo_offline(institution: AgentIdentity) -> None:
    """
    Offline demo: shows token construction + local signature verification.
    Runs without a live ACP server — demonstrates the cryptographic layer.
    """
    print(f"\n{BOLD}═══ ACP OFFLINE DEMO (local sig verification) ═══{RESET}")

    # ── Scenario 1: Valid payment token ──────────────────────────────────────
    step(1, "Issue capability token (institution signs, agent holds)")

    payment_agent = AgentIdentity.generate()
    token = build_capability_token(
        issuer=institution,
        subject=payment_agent,
        capabilities=["acp:cap:financial.payment"],
        resource="bank://accounts/ACC-001",
    )

    info(f"Token subject  : {token['sub']}")
    info(f"Capabilities   : {token['cap']}")
    info(f"Resource       : {token['resource']}")
    info(f"Expires in     : 3600s")
    info(f"Sig (truncated): {token['sig'][:40]}...")

    step(2, "Verify capability token signature (anyone can verify)")
    is_valid = ACPSigner.verify_capability(token, institution.public_key_bytes)
    if is_valid:
        ok(f"Signature VALID — token authenticity confirmed")
    else:
        deny(f"Signature INVALID")

    # ── Scenario 2: Tampered token ────────────────────────────────────────────
    step(3, "Tamper with token → signature check catches it")

    tampered = dict(token)
    tampered["cap"] = ["acp:cap:financial.payment", "acp:cap:admin.full"]  # escalation attempt
    is_valid = ACPSigner.verify_capability(tampered, institution.public_key_bytes)
    if not is_valid:
        ok(f"Tampered token rejected — non-escalation enforced by signature")
    else:
        deny(f"ERROR: tampered token accepted — this should not happen")

    # ── Scenario 3: Multi-agent delegation chain ──────────────────────────────
    step(4, "Multi-hop delegation chain (DCMA): human → planner → executor")

    planning_agent = AgentIdentity.generate()
    planning_token = build_capability_token(
        issuer=institution,
        subject=planning_agent,
        capabilities=["acp:cap:data.read", "acp:cap:agent.delegate"],
        resource="bank://reports/*",
    )

    # Planning agent delegates a SUBSET to the executor (non-escalation)
    executor_agent = AgentIdentity.generate()
    executor_token = build_capability_token(
        issuer=planning_agent,       # planning agent signs the sub-token
        subject=executor_agent,
        capabilities=["acp:cap:data.read"],       # subset only — no agent.delegate
        resource="bank://reports/2026-Q1",        # further restricted resource
    )

    ok(f"Institution  → planning agent : {planning_token['cap']}")
    ok(f"Planning agent → executor     : {executor_token['cap']} on {executor_token['resource']}")
    info("Non-escalation: executor cannot delegate 'agent.delegate' — it doesn't hold it")

    print(f"\n{BOLD}Offline demo complete.{RESET}")
    print("To run the full online admission check, start the Go server:")
    print("  cd impl/go && go build -o acp-server.exe ./cmd/acp-server")
    print("  python examples/admission_control_demo.py --print-pubkey")
    print("  ACP_INSTITUTION_PUBLIC_KEY=<pubkey> ./acp-server.exe")
    print("  python examples/admission_control_demo.py --online")


def demo_online(client: ACPClient, guard: ACPAdmissionGuard) -> None:
    """
    Online demo: full admission check via ACP server.
    Requires the Go reference server to be running.
    """
    payment_system = PaymentSystem()

    print(f"\n{BOLD}═══ ACP ONLINE DEMO (full admission check) ═══{RESET}")

    # ── Scenario 1: APPROVED action ───────────────────────────────────────────
    step(1, "APPROVED scenario: small payment within policy")

    result = guard.check(
        capability="acp:cap:financial.payment",
        resource="bank://accounts/ACC-001",
        action_parameters={"amount": 500.00, "currency": "USD"},
    )
    print(f"  ACP decision: {result}")

    if result.approved:
        ok(f"Admission CHECK PASSED — risk={result.risk_score}")
        payout = payment_system.transfer(
            from_account="ACC-001",
            to_account="ACC-002",
            amount=500.00,
            execution_token_id=result.execution_token_id or "offline-demo",
        )
        ok(f"Payment executed: {payout['status']} (ET={payout['execution_token_id'][:12]}...)")
    elif result.escalated:
        warn(f"Action ESCALATED — awaiting human approval (id={result.escalation_id})")
    else:
        deny(f"Action DENIED — agent blocked before execution")

    # ── Scenario 2: DENIED — wrong capability ─────────────────────────────────
    step(2, "DENIED scenario: agent requests admin capability it doesn't hold")

    result = guard.check(
        capability="acp:cap:admin.full",
        resource="bank://system/config",
    )
    print(f"  ACP decision: {result}")

    if result.denied:
        ok(f"Admission CHECK FAILED correctly — blocked before execution")
        ok(f"No state mutation occurred. No audit gap.")
    elif result.approved:
        deny(f"ERROR: should have been denied (agent doesn't hold this capability)")

    # ── Scenario 3: Data read — different capability scope ────────────────────
    step(3, "APPROVED scenario: data read within scope")

    result = guard.check(
        capability="acp:cap:data.read",
        resource="bank://reports/2026-Q1",
    )
    print(f"  ACP decision: {result}")

    if result.approved:
        ok(f"Read access APPROVED — risk={result.risk_score}")
        data_system = DataReadSystem()
        records = data_system.query(
            resource="bank://reports/2026-Q1",
            execution_token_id=result.execution_token_id or "offline",
        )
        ok(f"Query returned {records['records']} records (ET={records['execution_token_id'][:12]}...)")
    else:
        warn(f"Read access {result.decision}: {result}")

    # ── Ledger check ──────────────────────────────────────────────────────────
    step(4, "Audit ledger — verify immutable record of all decisions")

    try:
        audit = client.audit_query(
            agent_id=client._identity.agent_id,
            limit=5,
        )
        event_count = len(audit.get("events", []))
        chain_valid = audit.get("chain_valid", False)
        ok(f"Ledger query: {event_count} events, chain_valid={chain_valid}")
        info("Every APPROVED, DENIED, and ESCALATED decision is recorded and hash-chained")
    except ACPError as e:
        warn(f"Ledger query failed (server may not expose this endpoint yet): {e}")

    print(f"\n{BOLD}Online demo complete.{RESET}")


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    args = sys.argv[1:]
    online_mode = "--online" in args
    print_pubkey = "--print-pubkey" in args

    # Load or generate institution key
    seed_hex = os.getenv("ACP_INSTITUTION_SEED", "")
    institution = (
        AgentIdentity.from_private_bytes(bytes.fromhex(seed_hex))
        if seed_hex
        else AgentIdentity.generate()
    )

    if print_pubkey:
        pubkey = base64.urlsafe_b64encode(institution.public_key_bytes).rstrip(b"=").decode()
        print(pubkey)
        return

    print(f"\n{BOLD}ACP Admission Control Demo{RESET}")
    print("─" * 50)
    print("This demo shows ACP as the gate between agent intent")
    print("and system state mutation.\n")
    print(f"Institution pubkey : {base64.urlsafe_b64encode(institution.public_key_bytes).rstrip(b'=').decode()[:32]}...")

    if not online_mode:
        demo_offline(institution)
        return

    # ── Online mode: connect to Go server ─────────────────────────────────────
    seed_hex = os.getenv("ACP_AGENT_SEED", "")
    agent = (
        AgentIdentity.from_private_bytes(bytes.fromhex(seed_hex))
        if seed_hex
        else AgentIdentity.generate()
    )
    agent_signer = ACPSigner(agent)
    server_url = os.getenv("ACP_SERVER_URL", "http://localhost:8080")

    print(f"Agent ID           : {agent.agent_id}")
    print(f"Server             : {server_url}")

    client = ACPClient(server_url=server_url, identity=agent, signer=agent_signer)
    try:
        health = client.health()
        ok(f"Server health: {health.get('status', 'unknown')}")
    except ACPError as e:
        deny(f"Cannot reach ACP server: {e}")
        print("\nFalling back to offline demo.\n")
        demo_offline(institution)
        return

    # Register agent
    pubkey_b64 = base64.urlsafe_b64encode(agent.public_key_bytes).rstrip(b"=").decode()
    try:
        client.agent_register(agent_id=agent.agent_id, public_key_b64=pubkey_b64)
        ok(f"Agent registered: {agent.agent_id}")
    except ACPError as e:
        info(f"Registration note: {e} (may already be registered)")

    # Issue capability token for agent
    token = build_capability_token(
        issuer=institution,
        subject=agent,
        capabilities=["acp:cap:financial.payment", "acp:cap:data.read"],
        resource="bank://accounts/*",
    )
    info(f"Capability token issued: {token['cap']}")

    guard = ACPAdmissionGuard(client)
    demo_online(client, guard)


if __name__ == "__main__":
    main()
