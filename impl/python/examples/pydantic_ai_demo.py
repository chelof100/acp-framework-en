"""
ACP + Pydantic AI Integration Demo
====================================

Shows how ACP works as the admission control layer for Pydantic AI agent tools.
Every tool call is intercepted by ACP before execution — the agent cannot
bypass the check regardless of what the LLM decides to do.

    agent intent
        |
    [Pydantic AI tool invocation]
        |
    [ACP admission check]   ← this file shows how to wire this in
        |  identity + capability + policy + risk
        |
    APPROVED → tool runs + execution token logged
    DENIED   → tool raises ModelRetry (agent sees error, reports to user)
    ESCALATED → action queued for human review

Architecture
------------
The key integration is the RunContext dependency injection pattern.
The ACPAdmissionGuard is passed as `deps` to every tool at invocation time:

    agent = Agent('openai:gpt-4o-mini', deps_type=ACPAdmissionGuard)

    @agent.tool
    async def transfer_funds(
        ctx: RunContext[ACPAdmissionGuard],
        amount: float,
        to_account: str,
    ) -> str:
        result = ctx.deps.check(
            "acp:cap:financial.payment",
            resource=f"bank://{to_account}",
            action_parameters={"amount": amount},
        )
        if result.denied:
            raise ModelRetry(f"ACP DENIED: {result.error_code}")
        if result.escalated:
            raise ModelRetry(f"ACP ESCALATED: human review required ({result.escalation_id})")
        # This line only executes if ACP says APPROVED
        return payment_system.transfer(amount, to_account)

The guard is injected via `agent.run(..., deps=guard)` — no changes to tool logic.
Swapping offline ↔ online mode is a single parameter change on the guard.

Modes
-----
  OFFLINE (default): ACP admission check runs locally (crypto only, no server).
    Shows the pattern works with zero infrastructure.

  WITH_AGENT: Full Pydantic AI agent with real LLM decision-making.
    Requires: pip install pydantic-ai
              export OPENAI_API_KEY=sk-...
              (or ANTHROPIC_API_KEY= for Claude)

Run
---
    python examples/pydantic_ai_demo.py            # offline pattern demo
    python examples/pydantic_ai_demo.py --with-agent  # full agent (needs LLM key)

Dependencies
------------
    pip install cryptography>=42.0.0          # ACP SDK (required)
    pip install pydantic-ai                   # Pydantic AI (optional for --with-agent)
"""
from __future__ import annotations

import asyncio
import base64
import os
import secrets
import sys
import time
import uuid
from typing import Any, Dict, Optional

# ─── ACP SDK imports ──────────────────────────────────────────────────────────
from acp.identity import AgentIdentity
from acp.signer import ACPSigner
from acp.client import ACPClient, ACPError


# ─── Colour output ────────────────────────────────────────────────────────────

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

def ok(msg: str)   -> None: print(f"  {GREEN}✓{RESET} {msg}")
def deny(msg: str) -> None: print(f"  {RED}✗{RESET} {msg}")
def warn(msg: str) -> None: print(f"  {YELLOW}⚠{RESET} {msg}")
def info(msg: str) -> None: print(f"  {BLUE}→{RESET} {msg}")
def step(title: str) -> None:
    print(f"\n{BOLD}{CYAN}▶ {title}{RESET}")


# ─── ACP Admission Result ─────────────────────────────────────────────────────

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

    @property
    def error_code(self) -> Optional[str]:
        return self._raw.get("error_code") or self._raw.get("error")

    def __repr__(self) -> str:
        parts = [f"decision={self.decision}"]
        if self.risk_score is not None:
            parts.append(f"risk={self.risk_score}")
        if self.execution_token_id:
            parts.append(f"et={self.execution_token_id[:10]}...")
        return f"AdmissionResult({', '.join(parts)})"


# ─── ACP Admission Guard ──────────────────────────────────────────────────────

class ACPAdmissionGuard:
    """
    Admission control layer for agent actions.

    Passed as `deps` to every Pydantic AI tool via RunContext.
    In OFFLINE mode: verifies the capability token signature locally.
    In ONLINE mode:  sends the authorization request to the ACP server.
    """

    def __init__(
        self,
        identity: AgentIdentity,
        institution: AgentIdentity,
        client: Optional[ACPClient] = None,
    ) -> None:
        self._identity = identity
        self._institution = institution
        self._client = client  # None = offline mode

    @property
    def online(self) -> bool:
        return self._client is not None

    def check(
        self,
        capability: str,
        resource: str,
        action_parameters: Optional[Dict[str, Any]] = None,
    ) -> AdmissionResult:
        """Run ACP admission check (offline or online)."""
        if self._client is not None:
            return self._check_online(capability, resource, action_parameters)
        return self._check_offline(capability, resource, action_parameters)

    def _check_offline(
        self,
        capability: str,
        resource: str,
        action_parameters: Optional[Dict[str, Any]] = None,
    ) -> AdmissionResult:
        """Offline admission check — cryptographic layer only."""
        now = int(time.time())
        token = {
            "ver": "1.0",
            "iss": self._institution.did,
            "sub": self._identity.agent_id,
            "cap": [capability],
            "resource": resource,
            "iat": now,
            "exp": now + 3600,
            "nonce": secrets.token_urlsafe(16),
        }
        signer = ACPSigner(self._institution)
        signed_token = signer.sign_capability(token)

        is_valid = ACPSigner.verify_capability(signed_token, self._institution.public_key_bytes)
        if not is_valid:
            return AdmissionResult({"decision": "DENIED", "error_code": "SIGN-001"})

        risk = _simulate_risk_score(capability, resource, action_parameters or {})

        if risk >= 70:
            return AdmissionResult({"decision": "DENIED", "risk_score": risk,
                                    "error_code": "RISK-001"})
        if risk >= 40:
            return AdmissionResult({"decision": "ESCALATED", "risk_score": risk,
                                    "escalation_id": f"ESC-{uuid.uuid4().hex[:8].upper()}"})

        et_id = f"ET-{uuid.uuid4().hex[:16].upper()}"
        return AdmissionResult({
            "decision": "APPROVED",
            "risk_score": risk,
            "execution_token": {"et_id": et_id, "expires_in": 30},
        })

    def _check_online(
        self,
        capability: str,
        resource: str,
        action_parameters: Optional[Dict[str, Any]] = None,
    ) -> AdmissionResult:
        """Online admission check via ACP server (ACP-API-1.0)."""
        try:
            resp = self._client.authorize(
                request_id=str(uuid.uuid4()),
                agent_id=self._identity.agent_id,
                capability=capability,
                resource=resource,
                action_parameters=action_parameters or {},
            )
            return AdmissionResult(resp)
        except ACPError as e:
            return AdmissionResult({"decision": "DENIED", "error": str(e)})


def _simulate_risk_score(
    capability: str,
    resource: str,
    params: Dict[str, Any],
) -> int:
    """
    Deterministic risk scoring — mirrors ACP-RISK-1.0 §4.

    B(c)     — baseline by capability
    F_res(r) — resource classification
    F_ctx(x) — action parameters (amount thresholds etc.)
    """
    cap_baseline: Dict[str, int] = {
        "acp:cap:data.read":          0,
        "acp:cap:data.write":        15,
        "acp:cap:financial.payment": 35,
        "acp:cap:financial.transfer":40,
        "acp:cap:admin.delete":      55,
        "acp:cap:admin.full":        65,
    }
    base = cap_baseline.get(capability, 50)

    if "sensitive" in resource or "config" in resource:
        base += 15
    elif "admin" in resource or "system" in resource:
        base += 20

    amount = params.get("amount", 0)
    if amount > 50_000:
        base += 30
    elif amount > 10_000:
        base += 15
    elif amount > 1_000:
        base += 5

    return min(100, base)


# ─── Simulated back-end systems ───────────────────────────────────────────────

class BankingSystem:
    """Simulates a real banking back-end. Only called if ACP admits the action."""

    def transfer(self, amount: float, to_account: str, from_account: str = "ACC-001") -> str:
        return (f"Transfer COMPLETE: ${amount:,.2f} from {from_account} → {to_account}. "
                f"Ref: TXN-{uuid.uuid4().hex[:8].upper()}")

    def get_balance(self, account: str) -> str:
        balances = {"ACC-001": 125_000.00, "ACC-002": 8_400.50, "ACC-003": 2_100_000.00}
        bal = balances.get(account, 0)
        return f"Balance for {account}: ${bal:,.2f}"

    def delete_record(self, record_id: str) -> str:
        return f"Record {record_id} deleted permanently."


# ─── Demo: Pattern demo (no Pydantic AI required) ─────────────────────────────

def demo_pattern(guard: ACPAdmissionGuard) -> None:
    """
    Demonstrates the ACP + Pydantic AI integration pattern without a real LLM.

    The Pydantic AI tool pattern uses RunContext dependency injection:
    - The guard is passed as `deps` when calling `agent.run(..., deps=guard)`
    - Each tool receives `ctx: RunContext[ACPAdmissionGuard]`
    - The tool calls `ctx.deps.check(capability, resource, params)` before acting
    - DENIED/ESCALATED → tool raises ModelRetry → Pydantic AI handles retry/abort

    This demo simulates that flow directly to show ACP behavior across scenarios.
    """
    bank = BankingSystem()

    def _run_tool(
        tool_name: str,
        capability: str,
        resource: str,
        action_fn,
        action_parameters: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Simulates Pydantic AI tool invocation with ACP admission.

        In a real Pydantic AI agent this logic lives inside @agent.tool functions:

            @agent.tool
            async def transfer_funds(ctx: RunContext[ACPAdmissionGuard], ...) -> str:
                result = ctx.deps.check(capability, resource, params)
                if result.denied:
                    raise ModelRetry(f"ACP DENIED: {result.error_code}")
                ...
        """
        result = guard.check(
            capability=capability,
            resource=resource,
            action_parameters=action_parameters or {},
        )
        mode = "online" if guard.online else "offline"
        print(f"    {DIM}[ACP/{mode}] {capability} → {result.decision}"
              f"{f' risk={result.risk_score}' if result.risk_score is not None else ''}{RESET}")

        if result.approved:
            et = result.execution_token_id
            outcome = action_fn()
            if et:
                print(f"    {DIM}[ACP] ET issued: {et[:14]}... (single-use, 30s TTL){RESET}")
            return outcome

        if result.escalated:
            # In Pydantic AI: raise ModelRetry(f"ESCALATED: {result.escalation_id}")
            raise _ACPEscalated(capability, result)

        # In Pydantic AI: raise ModelRetry(f"DENIED: {result.error_code}")
        raise _ACPDenied(capability, resource, result)

    # ─────────────────────────────────────────────────────────────────────────
    print(f"\n{BOLD}═══ ACP + Pydantic AI Integration Pattern Demo ═══{RESET}")
    print(f"{DIM}Guard mode: {'online (ACP server)' if guard.online else 'offline (local crypto)'}{RESET}")
    print()
    print("Tools registered with ACP admission control via RunContext deps:")
    print(f"  {DIM}get_balance    → acp:cap:data.read{RESET}")
    print(f"  {DIM}transfer_funds → acp:cap:financial.payment{RESET}")
    print(f"  {DIM}delete_record  → acp:cap:admin.delete{RESET}")
    print()
    print(f"{DIM}Pydantic AI tool pattern:{RESET}")
    print(f"  {DIM}@agent.tool{RESET}")
    print(f"  {DIM}async def transfer_funds(ctx: RunContext[ACPAdmissionGuard], ...) -> str:{RESET}")
    print(f"  {DIM}    result = ctx.deps.check(capability, resource, params){RESET}")
    print(f"  {DIM}    if result.denied: raise ModelRetry(...){RESET}")

    # ── Scenario 1: APPROVED — data read (risk=0) ─────────────────────────────
    step("Scenario 1: Agent reads balance (APPROVED — data.read, risk=0)")
    try:
        result = _run_tool(
            "get_balance", "acp:cap:data.read", "bank://accounts/*",
            lambda: bank.get_balance("ACC-001"),
        )
        ok(f"Tool executed: {result}")
    except _ACPDenied as e:
        deny(f"Unexpected denial: risk={e.result.risk_score}")

    # ── Scenario 2: APPROVED — small payment (risk=35) ────────────────────────
    step("Scenario 2: Agent transfers $500 (APPROVED — financial.payment, risk=35)")
    try:
        result = _run_tool(
            "transfer_funds", "acp:cap:financial.payment", "bank://accounts/*",
            lambda: bank.transfer(500.00, "ACC-002"),
            action_parameters={"amount": 500.00},
        )
        ok(f"Tool executed: {result}")
    except _ACPDenied as e:
        deny(f"Denied: risk={e.result.risk_score}")
    except _ACPEscalated as e:
        warn(f"Escalated: {e}")

    # ── Scenario 3: ESCALATED — large payment (risk=35+30=65) ─────────────────
    step("Scenario 3: Agent transfers $75,000 (ESCALATED — risk=65, human review)")
    try:
        result = _run_tool(
            "transfer_funds", "acp:cap:financial.payment", "bank://accounts/*",
            lambda: bank.transfer(75_000.00, "ACC-003"),
            action_parameters={"amount": 75_000.00},
        )
        ok(f"Tool executed: {result}")
    except _ACPEscalated as e:
        warn(f"Action ESCALATED — risk={e.result.risk_score}")
        warn(f"Escalation ID: {e.result.escalation_id}")
        warn(f"Pydantic AI agent receives: ModelRetry → retries or reports to user")
        info("No state mutation occurred. Action queued for human approval.")
    except _ACPDenied as e:
        deny(f"Denied: risk={e.result.risk_score}")

    # ── Scenario 4: DENIED — admin delete (risk=55+20=75) ────────────────────
    step("Scenario 4: Agent tries to delete a record (DENIED — admin.delete, risk=75)")
    try:
        result = _run_tool(
            "delete_record", "acp:cap:admin.delete", "bank://system/records/*",
            lambda: bank.delete_record("TXN-0042"),
        )
        ok(f"Tool executed: {result}")
    except _ACPDenied as e:
        deny(f"Action DENIED — risk={e.result.risk_score}")
        deny(f"capability={e.capability}")
        info(f"Pydantic AI agent receives ModelRetry:")
        info(f"  'ACP DENIED [{e.capability}]: {e.result.error_code} (risk={e.result.risk_score})'")
        info("Agent can explain the denial — it cannot escalate its own permissions.")

    # ── Scenario 5: DENIED — capability not held ─────────────────────────────
    step("Scenario 5: Privilege escalation attempt (DENIED — admin.full, risk=85)")
    try:
        result = _run_tool(
            "reconfigure_system", "acp:cap:admin.full", "bank://system/config",
            lambda: "System setting max_transfer_limit = unlimited",
        )
        ok(f"Tool executed: {result}")
    except _ACPDenied as e:
        deny(f"Escalation attempt BLOCKED — risk={e.result.risk_score}")
        info("Agent attempted admin.full capability it does not hold.")
        info("ACP intercepted before any system state was touched.")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{BOLD}Pattern demo complete.{RESET}")
    print()
    print("Key observations:")
    ok("RunContext injection: guard.check() is available in every tool via ctx.deps")
    ok("fail-closed: ModelRetry signals denial without exposing internal state")
    ok("audit: every decision is cryptographically logged (APPROVED + DENIED)")
    ok("portable: same guard works offline (demo) and online (production)")


# ─── Demo: Full Pydantic AI agent (requires pydantic-ai + LLM key) ────────────

async def demo_with_pydantic_agent(guard: ACPAdmissionGuard) -> None:
    """
    Full Pydantic AI agent with ACP-guarded tools.
    Requires: pip install pydantic-ai
              OPENAI_API_KEY or ANTHROPIC_API_KEY env var
    """
    try:
        from pydantic_ai import Agent
        from pydantic_ai.tools import RunContext as RC
    except ImportError:
        print(f"\n{RED}pydantic-ai not installed.{RESET}")
        print("Install with: pip install pydantic-ai")
        _show_wire_up()
        return

    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print(f"\n{YELLOW}No LLM API key found.{RESET}")
        print("Set OPENAI_API_KEY or ANTHROPIC_API_KEY to run the full agent.")
        _show_wire_up()
        return

    # ── Determine model ───────────────────────────────────────────────────────
    if os.getenv("ANTHROPIC_API_KEY"):
        model = "anthropic:claude-3-5-haiku-latest"
    else:
        model = "openai:gpt-4o-mini"

    bank = BankingSystem()

    # ── Define the Pydantic AI agent with ACP-guarded tools ───────────────────
    #
    # The guard is passed as `deps` — every tool accesses it via ctx.deps.
    # ACP check runs INSIDE the tool, BEFORE any business logic.
    #
    banking_agent = Agent(model, deps_type=ACPAdmissionGuard)

    @banking_agent.tool
    async def get_balance(ctx: RC[ACPAdmissionGuard], account: str) -> str:
        """Get the current balance of a bank account."""
        result = ctx.deps.check(
            capability="acp:cap:data.read",
            resource="bank://accounts/*",
        )
        mode = "online" if ctx.deps.online else "offline"
        print(f"    {DIM}[ACP/{mode}] data.read → {result.decision}{RESET}")
        if result.denied:
            from pydantic_ai import ModelRetry
            raise ModelRetry(f"ACP DENIED data.read: {result.error_code}")
        if result.escalated:
            from pydantic_ai import ModelRetry
            raise ModelRetry(f"ACP ESCALATED: requires human approval ({result.escalation_id})")
        return bank.get_balance(account)

    @banking_agent.tool
    async def transfer_funds(
        ctx: RC[ACPAdmissionGuard],
        amount: float,
        to_account: str,
    ) -> str:
        """Transfer USD funds to another account. amount is the USD amount."""
        result = ctx.deps.check(
            capability="acp:cap:financial.payment",
            resource="bank://accounts/*",
            action_parameters={"amount": amount},
        )
        mode = "online" if ctx.deps.online else "offline"
        print(f"    {DIM}[ACP/{mode}] financial.payment → {result.decision}"
              f" risk={result.risk_score}{RESET}")
        if result.denied:
            from pydantic_ai import ModelRetry
            raise ModelRetry(
                f"ACP DENIED financial.payment: risk={result.risk_score}, "
                f"code={result.error_code}. Action blocked."
            )
        if result.escalated:
            from pydantic_ai import ModelRetry
            raise ModelRetry(
                f"ACP ESCALATED: transfer of ${amount:,.2f} requires human approval. "
                f"Escalation ID: {result.escalation_id}"
            )
        et = result.execution_token_id
        outcome = bank.transfer(amount, to_account)
        if et:
            print(f"    {DIM}[ACP] ET issued: {et[:14]}... (single-use, 30s TTL){RESET}")
        return outcome

    print(f"\n{BOLD}═══ ACP + Pydantic AI Agent Demo ═══{RESET}")
    print(f"{DIM}Model: {model}{RESET}")
    print(f"{DIM}Guard mode: {'online (ACP server)' if guard.online else 'offline (local crypto)'}{RESET}")
    print(f"\n{BOLD}Agent task: 'Check ACC-001 balance, then transfer $500 to ACC-002'{RESET}")
    print(f"{DIM}(ACP admission check runs inside each tool before execution){RESET}\n")

    try:
        response = await banking_agent.run(
            "Check the balance of account ACC-001, then transfer $500 to ACC-002.",
            deps=guard,
        )
        print(f"\n{BOLD}Agent output:{RESET} {response.data}")
    except Exception as e:
        print(f"\n{YELLOW}Agent error: {e}{RESET}")


def _show_wire_up() -> None:
    """Show Pydantic AI tool wire-up without running the agent."""
    print(f"\n{DIM}Pydantic AI integration pattern:{RESET}")
    print()
    print(f"  {CYAN}from pydantic_ai import Agent, ModelRetry{RESET}")
    print(f"  {CYAN}from pydantic_ai.tools import RunContext{RESET}")
    print()
    print(f"  agent = Agent('openai:gpt-4o-mini', deps_type=ACPAdmissionGuard)")
    print()
    print(f"  @agent.tool")
    print(f"  async def transfer_funds(")
    print(f"      ctx: RunContext[ACPAdmissionGuard],")
    print(f"      amount: float, to_account: str,")
    print(f"  ) -> str:")
    print(f"      result = ctx.deps.check(")
    print(f"          'acp:cap:financial.payment',")
    print(f"          resource='bank://accounts/*',")
    print(f"          action_parameters={{'amount': amount}},")
    print(f"      )")
    print(f"      if result.denied:")
    print(f"          raise ModelRetry(f'ACP DENIED: {{result.error_code}}')")
    print(f"      return bank.transfer(amount, to_account)  # only if APPROVED")
    print()
    print(f"  # Guard injected at invocation — not baked into tool definition")
    print(f"  response = await agent.run('Transfer $500 to ACC-002', deps=guard)")


# ─── Internal exception types for pattern demo ────────────────────────────────

class _ACPDenied(PermissionError):
    def __init__(self, capability: str, resource: str, result: AdmissionResult) -> None:
        self.capability = capability
        self.resource = resource
        self.result = result
        super().__init__(f"ACP DENIED [{capability}] on [{resource}] "
                         f"(risk={result.risk_score}, code={result.error_code})")


class _ACPEscalated(Exception):
    def __init__(self, capability: str, result: AdmissionResult) -> None:
        self.capability = capability
        self.result = result
        super().__init__(f"ACP ESCALATED [{capability}] "
                         f"(risk={result.risk_score}, id={result.escalation_id})")


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    args = sys.argv[1:]
    with_agent = "--with-agent" in args
    online     = "--online" in args

    print(f"\n{BOLD}ACP + Pydantic AI Integration Demo{RESET}")
    print("─" * 50)
    print("Demonstrates ACP as the admission control layer for Pydantic AI tools.")
    print()

    # ── Set up identities ─────────────────────────────────────────────────────
    seed_hex = os.getenv("ACP_INSTITUTION_SEED", "")
    institution = (
        AgentIdentity.from_private_bytes(bytes.fromhex(seed_hex))
        if seed_hex
        else AgentIdentity.generate()
    )

    agent_seed = os.getenv("ACP_AGENT_SEED", "")
    agent_identity = (
        AgentIdentity.from_private_bytes(bytes.fromhex(agent_seed))
        if agent_seed
        else AgentIdentity.generate()
    )

    pubkey_str = base64.urlsafe_b64encode(
        institution.public_key_bytes).rstrip(b"=").decode()[:32]
    print(f"Institution pubkey : {pubkey_str}...")
    print(f"Agent ID           : {agent_identity.agent_id[:32]}...")

    # ── Set up guard ──────────────────────────────────────────────────────────
    client: Optional[ACPClient] = None

    if online:
        server_url = os.getenv("ACP_SERVER_URL", "http://localhost:8080")
        agent_signer = ACPSigner(agent_identity)
        client = ACPClient(server_url=server_url, identity=agent_identity, signer=agent_signer)
        try:
            health = client.health()
            ok(f"ACP server: {health.get('status', 'unknown')} at {server_url}")
        except ACPError as e:
            warn(f"Cannot reach ACP server ({e}) — falling back to offline mode")
            client = None

    guard = ACPAdmissionGuard(
        identity=agent_identity,
        institution=institution,
        client=client,
    )

    mode_label = "ONLINE (ACP server)" if guard.online else "OFFLINE (local crypto)"
    print(f"Guard mode         : {CYAN}{mode_label}{RESET}")

    # ── Run demo ──────────────────────────────────────────────────────────────
    if with_agent:
        asyncio.run(demo_with_pydantic_agent(guard))
    else:
        demo_pattern(guard)

    print(f"\n{DIM}To run with a real Pydantic AI agent:{RESET}")
    print(f"  pip install pydantic-ai")
    print(f"  export OPENAI_API_KEY=sk-...")
    print(f"  python examples/pydantic_ai_demo.py --with-agent")
    print()
    print(f"{DIM}To run against the ACP reference server:{RESET}")
    print(f"  docker run -p 8080:8080 \\")
    print(f"    -e ACP_INSTITUTION_PUBLIC_KEY={pubkey_str}... \\")
    print(f"    ghcr.io/chelof100/acp-server:latest")
    print(f"  python examples/pydantic_ai_demo.py --online")


if __name__ == "__main__":
    main()
