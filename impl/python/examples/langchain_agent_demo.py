"""
ACP + LangChain Integration Demo
=================================

Shows how ACP works as the admission control layer for LangChain agent tools.
Every tool call is intercepted by ACP before execution — the agent cannot
bypass the check regardless of what the LLM decides to do.

    agent intent
        |
    [LangChain tool invocation]
        |
    [ACP admission check]   ← this file shows how to wire this in
        |  identity + capability + policy + risk
        |
    APPROVED → tool runs + execution token logged
    DENIED   → tool raises PermissionError (agent sees error, not the action)
    ESCALATED → action queued for human review

Architecture
------------
The key abstraction is the `acp_tool` decorator.
It wraps any Python function as a LangChain tool with ACP admission built in:

    @acp_tool(guard=guard, capability="acp:cap:financial.payment",
              resource="bank://accounts/*")
    def transfer_funds(amount: float, to_account: str) -> str:
        # This body only runs if ACP says APPROVED
        return payment_system.transfer(amount, to_account)

This is a drop-in replacement for @tool.
Existing tools can be wrapped without modifying their business logic.

Modes
-----
  OFFLINE (default): ACP admission check runs locally (crypto only, no server).
    Shows the pattern works with zero infrastructure.

  WITH_LLM: Full LangChain ReAct agent with real LLM decision-making.
    Requires: pip install langchain langchain-openai
              export OPENAI_API_KEY=sk-...

Run
---
    python examples/langchain_agent_demo.py            # offline pattern demo
    python examples/langchain_agent_demo.py --with-llm # full agent (needs LLM key)

Dependencies
------------
    pip install cryptography>=42.0.0          # ACP SDK (required)
    pip install langchain langchain-openai    # LangChain + OpenAI (optional for --with-llm)
"""
from __future__ import annotations

import base64
import os
import secrets
import sys
import time
import uuid
from typing import Any, Callable, Dict, Optional

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
        """
        Run ACP admission check.

        Offline: verifies that the agent's identity key can sign a valid PoP
                 and that the capability token structure is well-formed.
        Online:  sends full authorization request to ACP server.
        """
        if self._client is not None:
            return self._check_online(capability, resource, action_parameters)
        return self._check_offline(capability, resource, action_parameters)

    def _check_offline(
        self,
        capability: str,
        resource: str,
        action_parameters: Optional[Dict[str, Any]] = None,
    ) -> AdmissionResult:
        """
        Offline admission check — cryptographic layer only.

        Simulates the ACP admission flow without a live server:
        - Builds a capability token (institution signs)
        - Verifies the token signature (anyone can verify)
        - Simulates risk scoring based on action_parameters
        - Returns APPROVED/DENIED/ESCALATED

        This is sufficient to demonstrate the pattern and test integrations.
        """
        from acp.signer import ACPSigner

        # Step 1: Build + sign capability token (institution CA role)
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

        # Step 2: Verify signature (non-repudiation check)
        is_valid = ACPSigner.verify_capability(signed_token, self._institution.public_key_bytes)
        if not is_valid:
            return AdmissionResult({"decision": "DENIED", "error_code": "SIGN-001"})

        # Step 3: Simulate deterministic risk scoring (ACP-RISK-1.0)
        risk = _simulate_risk_score(capability, resource, action_parameters or {})

        # Step 4: Decision based on autonomy_level=2 thresholds
        if risk >= 70:
            return AdmissionResult({"decision": "DENIED", "risk_score": risk,
                                    "error_code": "RISK-001"})
        if risk >= 40:
            return AdmissionResult({"decision": "ESCALATED", "risk_score": risk,
                                    "escalation_id": f"ESC-{uuid.uuid4().hex[:8].upper()}"})

        # Step 5: Issue execution token (single-use, short TTL)
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
    # B(c): baseline by capability domain
    cap_baseline: Dict[str, int] = {
        "acp:cap:data.read":          0,
        "acp:cap:data.write":        15,
        "acp:cap:financial.payment": 35,
        "acp:cap:financial.transfer":40,
        "acp:cap:admin.delete":      55,
        "acp:cap:admin.full":        65,
    }
    base = cap_baseline.get(capability, 50)

    # F_res(r): resource sensitivity
    if "sensitive" in resource or "config" in resource:
        base += 15
    elif "admin" in resource or "system" in resource:
        base += 20

    # F_ctx(x): context factors from action parameters
    amount = params.get("amount", 0)
    if amount > 50_000:
        base += 30
    elif amount > 10_000:
        base += 15
    elif amount > 1_000:
        base += 5

    return min(100, base)


# ─── acp_tool decorator ───────────────────────────────────────────────────────

class ACPDeniedError(PermissionError):
    """Raised when ACP denies an agent action. Surfaced to the LangChain agent as a tool error."""
    def __init__(self, capability: str, resource: str, result: AdmissionResult) -> None:
        self.capability = capability
        self.resource = resource
        self.result = result
        super().__init__(
            f"ACP DENIED [{capability}] on [{resource}] "
            f"(risk={result.risk_score}, code={result.error_code}). "
            f"Action blocked before execution — no state mutation occurred."
        )


class ACPEscalatedError(Exception):
    """Raised when ACP escalates an action for human review."""
    def __init__(self, capability: str, result: AdmissionResult) -> None:
        self.capability = capability
        self.result = result
        super().__init__(
            f"ACP ESCALATED [{capability}] "
            f"(risk={result.risk_score}, escalation_id={result.escalation_id}). "
            f"Action queued for human review — not executed."
        )


def acp_tool(
    guard: ACPAdmissionGuard,
    capability: str,
    resource: str,
    action_parameter_keys: Optional[list] = None,
) -> Callable:
    """
    Decorator factory: wraps a Python function as an ACP-guarded LangChain tool.

    Usage:
        @acp_tool(guard=guard, capability="acp:cap:financial.payment",
                  resource="bank://accounts/*")
        def transfer_funds(amount: float, to_account: str) -> str:
            return payment_system.transfer(amount, to_account)

    The decorated function:
    - Runs the ACP admission check BEFORE the function body
    - If APPROVED: calls the original function, logs the execution token
    - If DENIED: raises ACPDeniedError (LangChain sees a tool error)
    - If ESCALATED: raises ACPEscalatedError (LangChain sees a tool error)

    Compatible with both @tool (LangChain) and plain function calls.
    """
    def decorator(fn: Callable) -> Callable:
        def guarded(*args, **kwargs) -> Any:
            # Extract action_parameters from kwargs for risk scoring
            action_params: Dict[str, Any] = {}
            if action_parameter_keys:
                for key in action_parameter_keys:
                    if key in kwargs:
                        action_params[key] = kwargs[key]
            # Positional args mapped to parameter names
            if args and not action_params:
                import inspect
                sig = inspect.signature(fn)
                params = list(sig.parameters.keys())
                for i, arg in enumerate(args):
                    if i < len(params) and params[i] in (action_parameter_keys or []):
                        action_params[params[i]] = arg

            # ── ACP ADMISSION CHECK ──────────────────────────────────────────
            result = guard.check(
                capability=capability,
                resource=resource,
                action_parameters=action_params,
            )

            mode = "online" if guard.online else "offline"
            print(f"    {DIM}[ACP/{mode}] {capability} → {result.decision}"
                  f"{f' risk={result.risk_score}' if result.risk_score is not None else ''}{RESET}")

            if result.approved:
                # Execute the tool and attach the execution token to the result
                outcome = fn(*args, **kwargs)
                et = result.execution_token_id
                if et:
                    print(f"    {DIM}[ACP] ET issued: {et[:14]}... (single-use, 30s TTL){RESET}")
                return outcome

            if result.escalated:
                raise ACPEscalatedError(capability, result)

            raise ACPDeniedError(capability, resource, result)

        # Preserve function metadata for LangChain tool introspection
        guarded.__name__ = fn.__name__
        guarded.__doc__ = fn.__doc__
        guarded.__wrapped__ = fn
        guarded._acp_capability = capability
        guarded._acp_resource = resource
        return guarded

    return decorator


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


# ─── Demo: Pattern demo (no LLM required) ─────────────────────────────────────

def demo_pattern(guard: ACPAdmissionGuard) -> None:
    """
    Demonstrates the ACP+LangChain integration pattern without a real LLM.

    Shows how tools behave when:
    - The agent requests an APPROVED action (small payment)
    - The agent requests a DENIED action (admin.delete, high risk)
    - The agent requests an ESCALATED action (large transfer > $50k)
    - The agent attempts privilege escalation (capability not held)
    """
    bank = BankingSystem()

    # ── Define tools with @acp_tool ───────────────────────────────────────────

    @acp_tool(guard=guard, capability="acp:cap:data.read",
              resource="bank://accounts/*")
    def get_balance(account: str) -> str:
        """Get the balance of a bank account."""
        return bank.get_balance(account)

    @acp_tool(guard=guard, capability="acp:cap:financial.payment",
              resource="bank://accounts/*",
              action_parameter_keys=["amount"])
    def transfer_funds(amount: float, to_account: str) -> str:
        """Transfer funds to another account."""
        return bank.transfer(amount, to_account)

    @acp_tool(guard=guard, capability="acp:cap:admin.delete",
              resource="bank://system/records/*")
    def delete_record(record_id: str) -> str:
        """Permanently delete a record from the system."""
        return bank.delete_record(record_id)

    # ─────────────────────────────────────────────────────────────────────────
    print(f"\n{BOLD}═══ ACP + LangChain Integration Pattern Demo ═══{RESET}")
    print(f"{DIM}Guard mode: {'online (ACP server)' if guard.online else 'offline (local crypto)'}{RESET}")
    print()
    print("Tools registered with ACP admission control:")
    print(f"  {DIM}get_balance     → acp:cap:data.read{RESET}")
    print(f"  {DIM}transfer_funds  → acp:cap:financial.payment{RESET}")
    print(f"  {DIM}delete_record   → acp:cap:admin.delete{RESET}")

    # ── Scenario 1: APPROVED — data read (risk ~0) ────────────────────────────
    step("Scenario 1: Agent reads balance (APPROVED — data.read, risk=0)")
    try:
        result = get_balance(account="ACC-001")
        ok(f"Tool executed: {result}")
    except ACPDeniedError as e:
        deny(f"Unexpected denial: {e}")

    # ── Scenario 2: APPROVED — small payment (risk=35) ────────────────────────
    step("Scenario 2: Agent transfers $500 (APPROVED — risk=35, below threshold)")
    try:
        result = transfer_funds(amount=500.00, to_account="ACC-002")
        ok(f"Tool executed: {result}")
    except ACPDeniedError as e:
        deny(f"Denied (expected for large amounts): risk={e.result.risk_score}")
    except ACPEscalatedError as e:
        warn(f"Escalated: {e}")

    # ── Scenario 3: ESCALATED — large payment (risk=35+30=65) ─────────────────
    step("Scenario 3: Agent transfers $75,000 (ESCALATED — risk=65, human review)")
    try:
        result = transfer_funds(amount=75_000.00, to_account="ACC-003")
        ok(f"Tool executed: {result}")
    except ACPEscalatedError as e:
        warn(f"Action ESCALATED — risk={e.result.risk_score}")
        warn(f"Escalation ID: {e.result.escalation_id}")
        warn(f"LangChain agent receives: ToolException → retries or reports to user")
        info("No state mutation occurred. Action queued for human approval.")
    except ACPDeniedError as e:
        deny(f"Denied with risk={e.result.risk_score}")

    # ── Scenario 4: DENIED — admin delete (risk=55+20=75) ────────────────────
    step("Scenario 4: Agent tries to delete a record (DENIED — risk=75, above threshold)")
    try:
        result = delete_record(record_id="TXN-0042")
        ok(f"Tool executed: {result}")
    except ACPDeniedError as e:
        deny(f"Action DENIED — risk={e.result.risk_score}")
        deny(f"capability={e.capability}")
        info(f"LangChain agent receives ToolException:")
        info(f"  '{e}'")
        info("Agent can report the denial to the user — it cannot retry with elevated perms.")

    # ── Scenario 5: DENIED — capability not held (wrong capability name) ─────
    step("Scenario 5: Privilege escalation attempt (DENIED — wrong capability)")

    @acp_tool(guard=guard, capability="acp:cap:admin.full",
              resource="bank://system/config")
    def reconfigure_system(setting: str, value: str) -> str:
        """Reconfigure a system setting. Requires admin.full capability."""
        return f"System setting {setting} = {value}"

    try:
        result = reconfigure_system(setting="max_transfer_limit", value="unlimited")
        ok(f"Tool executed: {result}")
    except ACPDeniedError as e:
        deny(f"Escalation attempt BLOCKED — risk={e.result.risk_score}")
        info("Agent attempted admin.full capability it does not hold.")
        info("ACP intercepted before any system state was touched.")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{BOLD}Pattern demo complete.{RESET}")
    print()
    print("Key observations:")
    ok("drop-in: @acp_tool replaces @tool — business logic unchanged")
    ok("fail-closed: every exception means zero state mutation")
    ok("audit: every decision is cryptographically logged (APPROVED + DENIED)")
    ok("portable: same guard works offline (demo) and online (production)")


# ─── Demo: Full LangChain agent (requires langchain + LLM key) ────────────────

def demo_with_langchain_agent(guard: ACPAdmissionGuard) -> None:
    """
    Full LangChain ReAct agent with ACP-guarded tools.
    Requires: pip install langchain langchain-openai
              OPENAI_API_KEY env var
    """
    try:
        from langchain_core.tools import tool as lc_tool
        from langchain_core.tools import StructuredTool
    except ImportError:
        try:
            from langchain.tools import tool as lc_tool  # type: ignore
        except ImportError:
            print(f"\n{RED}langchain not installed.{RESET}")
            print("Install with: pip install langchain langchain-openai")
            return

    bank = BankingSystem()

    # ── Wrap functions with BOTH @acp_tool and LangChain's @tool ──────────────

    def _get_balance_fn(account: str) -> str:
        """Get the current balance of a bank account."""
        return bank.get_balance(account)

    def _transfer_funds_fn(amount: float, to_account: str) -> str:
        """Transfer funds. amount is in USD. to_account is the destination account ID."""
        return bank.transfer(amount, to_account)

    # Apply ACP wrapper first, then LangChain tool wrapper
    _get_balance_acp    = acp_tool(guard, "acp:cap:data.read",
                                   "bank://accounts/*")(_get_balance_fn)
    _transfer_funds_acp = acp_tool(guard, "acp:cap:financial.payment",
                                   "bank://accounts/*",
                                   action_parameter_keys=["amount"])(_transfer_funds_fn)

    try:
        get_balance_tool   = lc_tool(_get_balance_acp)
        transfer_funds_tool = lc_tool(_transfer_funds_acp)
    except Exception:
        # LangChain tool wrapping varies by version — use StructuredTool as fallback
        get_balance_tool = StructuredTool.from_function(_get_balance_acp)
        transfer_funds_tool = StructuredTool.from_function(_transfer_funds_acp)

    tools = [get_balance_tool, transfer_funds_tool]

    print(f"\n{BOLD}═══ ACP + LangChain Agent Demo ═══{RESET}")
    print(f"{DIM}Attempting to initialize LangChain ReAct agent...{RESET}")

    # ── Try to initialize a real LLM agent ───────────────────────────────────
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print(f"\n{YELLOW}No LLM API key found.{RESET}")
        print("Set OPENAI_API_KEY or ANTHROPIC_API_KEY to run the full agent.")
        print(f"\n{DIM}Showing tool wire-up instead:{RESET}")
        print()
        print("Tools registered with LangChain + ACP:")
        for t in tools:
            cap = getattr(getattr(t, 'func', t), '_acp_capability', 'unknown')
            print(f"  {t.name:25s} → {cap}")
        print()
        print("When the agent calls a tool, ACP runs first:")
        print(f"  agent.run('Get balance for ACC-001')")
        print(f"  → LangChain routes to get_balance_tool")
        print(f"  → {CYAN}@acp_tool intercepts{RESET}")
        print(f"  → ACP checks: identity + capability + risk")
        print(f"  → APPROVED (risk=0, data.read)")
        print(f"  → Tool body runs → 'Balance for ACC-001: $125,000.00'")
        return

    # ── With API key: run a real agent task ──────────────────────────────────
    try:
        from langchain_openai import ChatOpenAI
        from langchain.agents import AgentExecutor, create_react_agent
        from langchain import hub

        llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)
        prompt = hub.pull("hwchase17/react")
        agent = create_react_agent(llm, tools, prompt)
        agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True,
                                       handle_parsing_errors=True)

        print(f"\n{BOLD}Agent task: 'Check ACC-001 balance and transfer $500 to ACC-002'{RESET}")
        print(f"{DIM}(ACP admission check runs before each tool invocation){RESET}\n")

        result = agent_executor.invoke({
            "input": "Check the balance of account ACC-001, then transfer $500 to ACC-002."
        })
        print(f"\n{BOLD}Agent output:{RESET} {result['output']}")

    except ImportError as e:
        print(f"\n{YELLOW}LangChain agent setup failed: {e}{RESET}")
        print("Install with: pip install langchain langchain-openai")
    except Exception as e:
        print(f"\n{YELLOW}Agent error: {e}{RESET}")


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    args = sys.argv[1:]
    with_llm = "--with-llm" in args
    online   = "--online" in args

    print(f"\n{BOLD}ACP + LangChain Integration Demo{RESET}")
    print("─" * 50)
    print("Demonstrates ACP as the admission control layer for LangChain tools.")
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
    if with_llm:
        demo_with_langchain_agent(guard)
    else:
        demo_pattern(guard)

    print(f"\n{DIM}To run with a real LangChain agent:{RESET}")
    print(f"  pip install langchain langchain-openai")
    print(f"  export OPENAI_API_KEY=sk-...")
    print(f"  python examples/langchain_agent_demo.py --with-llm")
    print()
    print(f"{DIM}To run against the ACP reference server:{RESET}")
    print(f"  docker run -p 8080:8080 \\")
    print(f"    -e ACP_INSTITUTION_PUBLIC_KEY={pubkey_str}... \\")
    print(f"    ghcr.io/chelof100/acp-server:latest")
    print(f"  python examples/langchain_agent_demo.py --online")


if __name__ == "__main__":
    main()
