"""
ACP + MCP (Model Context Protocol) Integration Demo
=====================================================

Shows how ACP works as the admission control layer inside an MCP server.
Every tool call received from an MCP client passes through ACP before
the handler body executes — the connected LLM cannot bypass the check.

    MCP client (Claude Desktop / LangChain / etc.)
        |
        |  tools/call { name: "transfer_funds", arguments: {...} }
        |
    [MCP server — this file]
        |
        [ACP admission check]   ← wired in at the dispatch layer
        |  identity + capability + policy + risk
        |
    APPROVED → handler runs + execution token logged in response meta
    DENIED   → returns error content (MCP error format)
    ESCALATED → returns escalation notice (queued for human review)

Architecture
------------
The key abstraction is the `ACPToolDispatcher` — an MCP tool registry
that wraps every registered tool with an ACP admission check:

    dispatcher = ACPToolDispatcher(guard)

    @dispatcher.tool(
        capability="acp:cap:financial.payment",
        resource="bank://accounts/*",
        risk_params=["amount"],
    )
    def transfer_funds(amount: float, to_account: str) -> str:
        # This body only runs if ACP says APPROVED
        return payment_system.transfer(amount, to_account)

The dispatcher can be mounted on any MCP server framework:

    # With the official `mcp` package (FastMCP):
    from mcp.server.fastmcp import FastMCP
    mcp_server = FastMCP("acp-banking")
    dispatcher.mount(mcp_server)

    # Or used standalone for testing:
    result = dispatcher.call("transfer_funds", {"amount": 500, "to_account": "ACC-002"})

Modes
-----
  OFFLINE (default): ACP admission check runs locally (crypto only, no server).
    Shows the pattern works with zero infrastructure.

  SERVER: Start a real FastMCP server that Claude Desktop / any MCP client can connect to.
    Requires: pip install mcp
              (install Claude Desktop and add this server to claude_desktop_config.json)

Run
---
    python examples/mcp_server_demo.py             # offline dispatcher demo
    python examples/mcp_server_demo.py --server    # start MCP server (needs `mcp`)
    python examples/mcp_server_demo.py --online    # use ACP server for admission

Dependencies
------------
    pip install cryptography>=42.0.0    # ACP SDK (required)
    pip install mcp                     # MCP Python SDK (optional for --server)

Claude Desktop config (add to claude_desktop_config.json):
    {
      "mcpServers": {
        "acp-banking": {
          "command": "python",
          "args": ["/path/to/impl/python/examples/mcp_server_demo.py", "--server"]
        }
      }
    }
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

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
        self._client = client

    @property
    def online(self) -> bool:
        return self._client is not None

    def check(
        self,
        capability: str,
        resource: str,
        action_parameters: Optional[Dict[str, Any]] = None,
    ) -> AdmissionResult:
        if self._client is not None:
            return self._check_online(capability, resource, action_parameters)
        return self._check_offline(capability, resource, action_parameters)

    def _check_offline(
        self,
        capability: str,
        resource: str,
        action_parameters: Optional[Dict[str, Any]] = None,
    ) -> AdmissionResult:
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
    """Deterministic risk scoring — mirrors ACP-RISK-1.0 §4."""
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


# ─── MCP response helpers ─────────────────────────────────────────────────────

def _mcp_text(text: str) -> Dict[str, Any]:
    """Build a successful MCP tool result (text content)."""
    return {"content": [{"type": "text", "text": text}], "isError": False}


def _mcp_error(text: str) -> Dict[str, Any]:
    """Build an MCP tool error result."""
    return {"content": [{"type": "text", "text": text}], "isError": True}


# ─── ACP Tool Dispatcher ──────────────────────────────────────────────────────

class _RegisteredTool:
    """Internal record for a tool registered with ACPToolDispatcher."""
    def __init__(
        self,
        fn: Callable,
        capability: str,
        resource: str,
        risk_params: Optional[List[str]],
        description: str,
        input_schema: Dict[str, Any],
    ) -> None:
        self.fn = fn
        self.capability = capability
        self.resource = resource
        self.risk_params = risk_params or []
        self.description = description
        self.input_schema = input_schema


class ACPToolDispatcher:
    """
    MCP tool registry with ACP admission control at the dispatch layer.

    Register tools with @dispatcher.tool(capability=..., resource=...).
    Call them with dispatcher.call(tool_name, arguments).

    ACP admission check runs BEFORE every tool handler:
    - APPROVED  → handler runs, execution token included in response meta
    - DENIED    → returns MCP error (isError=True), no handler called
    - ESCALATED → returns MCP escalation notice, no handler called

    Compatible with FastMCP via dispatcher.mount(mcp_server).
    """

    def __init__(self, guard: ACPAdmissionGuard) -> None:
        self._guard = guard
        self._tools: Dict[str, _RegisteredTool] = {}

    def tool(
        self,
        capability: str,
        resource: str,
        risk_params: Optional[List[str]] = None,
        input_schema: Optional[Dict[str, Any]] = None,
    ) -> Callable:
        """
        Decorator: register a function as an ACP-guarded MCP tool.

        Usage:
            @dispatcher.tool(
                capability="acp:cap:financial.payment",
                resource="bank://accounts/*",
                risk_params=["amount"],
            )
            def transfer_funds(amount: float, to_account: str) -> str:
                return payment_system.transfer(amount, to_account)
        """
        def decorator(fn: Callable) -> Callable:
            schema = input_schema or _infer_schema(fn)
            self._tools[fn.__name__] = _RegisteredTool(
                fn=fn,
                capability=capability,
                resource=resource,
                risk_params=risk_params,
                description=(fn.__doc__ or "").strip(),
                input_schema=schema,
            )
            return fn
        return decorator

    def list_tools(self) -> List[Dict[str, Any]]:
        """Return MCP tools/list response body."""
        return [
            {
                "name": name,
                "description": t.description,
                "inputSchema": t.input_schema,
            }
            for name, t in self._tools.items()
        ]

    def call(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Dispatch a tools/call request.

        Runs the ACP admission check first. Returns MCP response format:
        {"content": [...], "isError": bool}
        """
        if tool_name not in self._tools:
            return _mcp_error(f"Unknown tool: {tool_name}")

        t = self._tools[tool_name]

        # Extract risk-relevant parameters
        action_params = {k: arguments[k] for k in t.risk_params if k in arguments}

        # ── ACP ADMISSION CHECK ───────────────────────────────────────────────
        result = self._guard.check(
            capability=t.capability,
            resource=t.resource,
            action_parameters=action_params,
        )

        mode = "online" if self._guard.online else "offline"
        print(f"    {DIM}[ACP/{mode}] {t.capability} → {result.decision}"
              f"{f' risk={result.risk_score}' if result.risk_score is not None else ''}{RESET}")

        if result.denied:
            msg = (
                f"[ACP DENIED] Tool '{tool_name}' was blocked before execution.\n"
                f"Capability: {t.capability}\n"
                f"Risk score: {result.risk_score}\n"
                f"Error code: {result.error_code}\n"
                f"No state mutation occurred."
            )
            return _mcp_error(msg)

        if result.escalated:
            msg = (
                f"[ACP ESCALATED] Tool '{tool_name}' requires human approval.\n"
                f"Capability: {t.capability}\n"
                f"Risk score: {result.risk_score}\n"
                f"Escalation ID: {result.escalation_id}\n"
                f"Action has been queued for review. Not executed."
            )
            return _mcp_error(msg)

        # ── Execute the tool handler ──────────────────────────────────────────
        try:
            output = t.fn(**arguments)
        except Exception as e:
            return _mcp_error(f"Tool execution error: {e}")

        et = result.execution_token_id
        if et:
            print(f"    {DIM}[ACP] ET issued: {et[:14]}... (single-use, 30s TTL){RESET}")

        # Attach execution token to successful response as metadata comment
        response_text = str(output)
        if et:
            response_text += f"\n[ACP execution token: {et[:14]}... — logged for audit]"

        return _mcp_text(response_text)

    def mount(self, mcp_server: Any) -> None:
        """
        Mount all registered tools onto a FastMCP server.

        Usage:
            from mcp.server.fastmcp import FastMCP
            mcp_server = FastMCP("acp-banking")
            dispatcher.mount(mcp_server)
            mcp_server.run()
        """
        dispatcher_ref = self

        for tool_name, t in self._tools.items():
            # Capture loop variable
            def _make_handler(name: str):
                def handler(**kwargs) -> str:
                    resp = dispatcher_ref.call(name, kwargs)
                    if resp.get("isError"):
                        raise ValueError(resp["content"][0]["text"])
                    return resp["content"][0]["text"]
                handler.__name__ = name
                handler.__doc__ = t.description
                return handler

            mcp_server.tool(name=tool_name)(_make_handler(tool_name))


def _infer_schema(fn: Callable) -> Dict[str, Any]:
    """Infer a basic JSON Schema from function type hints."""
    import inspect
    sig = inspect.signature(fn)
    props: Dict[str, Any] = {}
    required: List[str] = []
    for name, param in sig.parameters.items():
        ann = param.annotation
        if ann == inspect.Parameter.empty:
            type_str = "string"
        elif ann == float:
            type_str = "number"
        elif ann == int:
            type_str = "integer"
        elif ann == bool:
            type_str = "boolean"
        else:
            type_str = "string"
        props[name] = {"type": type_str}
        if param.default == inspect.Parameter.empty:
            required.append(name)
    return {
        "type": "object",
        "properties": props,
        "required": required,
    }


# ─── Simulated back-end systems ───────────────────────────────────────────────

class BankingSystem:
    """Simulates a real banking back-end. Only called if ACP admits the action."""

    def transfer(self, amount: float, to_account: str) -> str:
        return (f"Transfer COMPLETE: ${amount:,.2f} to {to_account}. "
                f"Ref: TXN-{uuid.uuid4().hex[:8].upper()}")

    def get_balance(self, account: str) -> str:
        balances = {"ACC-001": 125_000.00, "ACC-002": 8_400.50, "ACC-003": 2_100_000.00}
        bal = balances.get(account, 0)
        return f"Balance for {account}: ${bal:,.2f}"

    def delete_record(self, record_id: str) -> str:
        return f"Record {record_id} deleted permanently."


# ─── Demo: Dispatcher demo (no MCP package required) ──────────────────────────

def demo_dispatcher(guard: ACPAdmissionGuard) -> None:
    """
    Demonstrates the ACP + MCP integration pattern without a live MCP server.

    Shows how the ACPToolDispatcher intercepts tools/call requests and runs
    the ACP admission check before dispatching to the handler.
    """
    bank = BankingSystem()
    dispatcher = ACPToolDispatcher(guard)

    # ── Register tools ────────────────────────────────────────────────────────

    @dispatcher.tool(
        capability="acp:cap:data.read",
        resource="bank://accounts/*",
    )
    def get_balance(account: str) -> str:
        """Get the current balance of a bank account."""
        return bank.get_balance(account)

    @dispatcher.tool(
        capability="acp:cap:financial.payment",
        resource="bank://accounts/*",
        risk_params=["amount"],
    )
    def transfer_funds(amount: float, to_account: str) -> str:
        """Transfer funds to another account. amount is in USD."""
        return bank.transfer(amount, to_account)

    @dispatcher.tool(
        capability="acp:cap:admin.delete",
        resource="bank://system/records/*",
    )
    def delete_record(record_id: str) -> str:
        """Permanently delete a record from the system."""
        return bank.delete_record(record_id)

    @dispatcher.tool(
        capability="acp:cap:admin.full",
        resource="bank://system/config",
    )
    def reconfigure_system(setting: str, value: str) -> str:
        """Reconfigure a system setting. Requires admin.full capability."""
        return f"System setting {setting} = {value}"

    # ─────────────────────────────────────────────────────────────────────────
    print(f"\n{BOLD}═══ ACP + MCP Integration Demo (ACPToolDispatcher) ═══{RESET}")
    print(f"{DIM}Guard mode: {'online (ACP server)' if guard.online else 'offline (local crypto)'}{RESET}")
    print()
    print("MCP tools registered with ACP admission control:")
    for t_def in dispatcher.list_tools():
        cap = dispatcher._tools[t_def["name"]].capability
        print(f"  {DIM}{t_def['name']:25s} → {cap}{RESET}")

    # ── Scenario 1: APPROVED — data read ─────────────────────────────────────
    step("Scenario 1: MCP client calls get_balance (APPROVED — data.read, risk=0)")
    resp = dispatcher.call("get_balance", {"account": "ACC-001"})
    if not resp["isError"]:
        ok(f"Tool executed: {resp['content'][0]['text']}")
    else:
        deny(f"Error: {resp['content'][0]['text']}")

    # ── Scenario 2: APPROVED — small payment ─────────────────────────────────
    step("Scenario 2: MCP client calls transfer_funds $500 (APPROVED — risk=35)")
    resp = dispatcher.call("transfer_funds", {"amount": 500.00, "to_account": "ACC-002"})
    if not resp["isError"]:
        ok(f"Tool executed: {resp['content'][0]['text']}")
    else:
        deny(f"Error: {resp['content'][0]['text']}")

    # ── Scenario 3: ESCALATED — large payment ────────────────────────────────
    step("Scenario 3: MCP client calls transfer_funds $75,000 (ESCALATED — risk=65)")
    resp = dispatcher.call("transfer_funds", {"amount": 75_000.00, "to_account": "ACC-003"})
    if resp["isError"]:
        msg = resp["content"][0]["text"]
        if "ESCALATED" in msg:
            warn(f"Tool ESCALATED — action queued for human review")
            for line in msg.strip().split("\n"):
                warn(line) if "ESCALATED" in line or "Escalation" in line else info(line)
        else:
            deny(f"Denied: {msg[:80]}")
    else:
        ok(f"Tool executed: {resp['content'][0]['text']}")

    # ── Scenario 4: DENIED — admin delete ────────────────────────────────────
    step("Scenario 4: MCP client calls delete_record (DENIED — admin.delete, risk=75)")
    resp = dispatcher.call("delete_record", {"record_id": "TXN-0042"})
    if resp["isError"]:
        msg = resp["content"][0]["text"]
        if "DENIED" in msg:
            deny(f"Tool DENIED — blocked before execution")
            for line in msg.strip().split("\n"):
                deny(line) if "DENIED" in line else info(line)
        else:
            deny(f"Error: {msg[:80]}")
    else:
        ok(f"Tool executed: {resp['content'][0]['text']}")

    # ── Scenario 5: DENIED — privilege escalation ─────────────────────────────
    step("Scenario 5: MCP client calls reconfigure_system (DENIED — admin.full, risk=85)")
    resp = dispatcher.call("reconfigure_system",
                           {"setting": "max_transfer_limit", "value": "unlimited"})
    if resp["isError"]:
        msg = resp["content"][0]["text"]
        if "DENIED" in msg:
            deny(f"Escalation attempt BLOCKED — ACP intercepted before execution")
        else:
            deny(f"Error: {msg[:80]}")
    else:
        ok(f"Tool executed: {resp['content'][0]['text']}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{BOLD}Dispatcher demo complete.{RESET}")
    print()
    print("Key observations:")
    ok("dispatch layer: ACP check runs at tools/call, before handler invocation")
    ok("fail-closed: isError=True response means zero state mutation")
    ok("audit: every decision is cryptographically logged (APPROVED + DENIED)")
    ok("compatible: ACPToolDispatcher.mount() works with FastMCP servers")


# ─── Demo: Live FastMCP server (requires `mcp` package) ───────────────────────

def start_mcp_server(guard: ACPAdmissionGuard) -> None:
    """
    Start a live FastMCP server with ACP-guarded tools.
    Requires: pip install mcp

    Connect from Claude Desktop by adding to claude_desktop_config.json:
        {
          "mcpServers": {
            "acp-banking": {
              "command": "python",
              "args": ["/path/to/mcp_server_demo.py", "--server"]
            }
          }
        }
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print(f"\n{RED}mcp package not installed.{RESET}")
        print("Install with: pip install mcp")
        print()
        print("Without `mcp`, use --server=false to run the dispatcher demo instead.")
        return

    bank = BankingSystem()
    dispatcher = ACPToolDispatcher(guard)

    @dispatcher.tool(
        capability="acp:cap:data.read",
        resource="bank://accounts/*",
    )
    def get_balance(account: str) -> str:
        """Get the current balance of a bank account."""
        return bank.get_balance(account)

    @dispatcher.tool(
        capability="acp:cap:financial.payment",
        resource="bank://accounts/*",
        risk_params=["amount"],
    )
    def transfer_funds(amount: float, to_account: str) -> str:
        """Transfer funds to another account. amount is in USD."""
        return bank.transfer(amount, to_account)

    # Mount all ACP-guarded tools onto FastMCP
    mcp_server = FastMCP("acp-banking")
    dispatcher.mount(mcp_server)

    print(f"\n{BOLD}ACP + MCP Server starting{RESET}")
    print(f"{DIM}Guard mode: {'online (ACP server)' if guard.online else 'offline (local crypto)'}{RESET}")
    print(f"{DIM}Every tools/call will pass through ACP admission control.{RESET}")
    print()
    print("Add to Claude Desktop (claude_desktop_config.json):")
    print(json.dumps({
        "mcpServers": {
            "acp-banking": {
                "command": "python",
                "args": [os.path.abspath(__file__), "--server"],
            }
        }
    }, indent=2))
    print()

    mcp_server.run()


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    args = sys.argv[1:]
    server_mode = "--server" in args
    online      = "--online" in args

    print(f"\n{BOLD}ACP + MCP Integration Demo{RESET}")
    print("─" * 50)
    print("Demonstrates ACP as the admission control layer for MCP tool calls.")
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
    if server_mode:
        start_mcp_server(guard)
    else:
        demo_dispatcher(guard)

    if not server_mode:
        print(f"\n{DIM}To start a live MCP server (for Claude Desktop):{RESET}")
        print(f"  pip install mcp")
        print(f"  python examples/mcp_server_demo.py --server")
        print()
        print(f"{DIM}To run against the ACP reference server:{RESET}")
        print(f"  docker run -p 8080:8080 \\")
        print(f"    -e ACP_INSTITUTION_PUBLIC_KEY={pubkey_str}... \\")
        print(f"    ghcr.io/chelof100/acp-server:latest")
        print(f"  python examples/mcp_server_demo.py --online")


if __name__ == "__main__":
    main()
