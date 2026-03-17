# ACP Python SDK — Examples

Three examples that demonstrate ACP as admission control for agent actions,
across the dominant Python agent frameworks.

---

## `admission_control_demo.py` — Core pattern (no framework required)

Shows the `ACPAdmissionGuard` pattern directly: token issuance, signature
verification, multi-hop delegation, APPROVED / DENIED / ESCALATED decisions.

```bash
pip install cryptography>=42.0.0

# Offline (default) — crypto only, no server
python examples/admission_control_demo.py

# Online — full admission check via ACP server
python examples/admission_control_demo.py --online
```

---

## `langchain_agent_demo.py` — LangChain integration

Shows how to wrap any LangChain tool with ACP admission control using the
`@acp_tool` decorator. The LLM agent cannot call a tool without passing the
ACP admission check first.

```bash
pip install cryptography>=42.0.0

# Pattern demo (no LLM key required)
python examples/langchain_agent_demo.py

# Full ReAct agent (requires LangChain + OpenAI key)
pip install langchain langchain-openai
export OPENAI_API_KEY=sk-...
python examples/langchain_agent_demo.py --with-llm
```

### The `@acp_tool` decorator

```python
from langchain_agent_demo import acp_tool, ACPAdmissionGuard

guard = ACPAdmissionGuard(identity=agent, institution=institution)

@acp_tool(guard=guard,
          capability="acp:cap:financial.payment",
          resource="bank://accounts/*",
          action_parameter_keys=["amount"])
def transfer_funds(amount: float, to_account: str) -> str:
    """Transfer funds. Body only runs if ACP says APPROVED."""
    return payment_system.transfer(amount, to_account)
```

This is a drop-in replacement for LangChain's `@tool`. The function body
only executes if ACP admits the action. Otherwise:

| ACP decision | Exception raised | Agent sees |
|---|---|---|
| `APPROVED` | — | Tool result + execution token logged |
| `ESCALATED` | `ACPEscalatedError` | Tool error → human review required |
| `DENIED` | `ACPDeniedError` | Tool error → blocked, no state mutation |

---

## `pydantic_ai_demo.py` — Pydantic AI integration

Shows how to inject `ACPAdmissionGuard` as a Pydantic AI `RunContext` dependency.
The guard is available inside every `@agent.tool` function via `ctx.deps`.

```bash
pip install cryptography>=42.0.0

# Pattern demo (no LLM key required)
python examples/pydantic_ai_demo.py

# Full Pydantic AI agent (requires pydantic-ai + LLM key)
pip install pydantic-ai
export OPENAI_API_KEY=sk-...
python examples/pydantic_ai_demo.py --with-agent
```

### The `RunContext` injection pattern

```python
from pydantic_ai import Agent, ModelRetry
from pydantic_ai.tools import RunContext
from pydantic_ai_demo import ACPAdmissionGuard

agent = Agent('openai:gpt-4o-mini', deps_type=ACPAdmissionGuard)

@agent.tool
async def transfer_funds(
    ctx: RunContext[ACPAdmissionGuard],
    amount: float,
    to_account: str,
) -> str:
    """Transfer funds. Body only runs if ACP says APPROVED."""
    result = ctx.deps.check(
        capability="acp:cap:financial.payment",
        resource="bank://accounts/*",
        action_parameters={"amount": amount},
    )
    if result.denied:
        raise ModelRetry(f"ACP DENIED: {result.error_code}")
    if result.escalated:
        raise ModelRetry(f"ACP ESCALATED: human review required ({result.escalation_id})")
    return payment_system.transfer(amount, to_account)

# Guard injected at invocation time — not baked into the tool definition
response = await agent.run("Transfer $500 to ACC-002", deps=guard)
```

| ACP decision | Action | Agent sees |
|---|---|---|
| `APPROVED` | Tool body runs | Tool result + ET logged |
| `ESCALATED` | `ModelRetry` raised | Retry/abort → reports to user |
| `DENIED` | `ModelRetry` raised | Retry/abort → reports to user |

---

## `mcp_server_demo.py` — MCP server integration

Shows how to add ACP admission control at the MCP dispatch layer using
`ACPToolDispatcher`. Every `tools/call` request passes ACP before the
handler runs. Compatible with Claude Desktop and any MCP client.

```bash
pip install cryptography>=42.0.0

# Dispatcher demo (no MCP package required)
python examples/mcp_server_demo.py

# Start a live FastMCP server (for Claude Desktop)
pip install mcp
python examples/mcp_server_demo.py --server
```

### The `ACPToolDispatcher`

```python
from mcp_server_demo import ACPToolDispatcher, ACPAdmissionGuard

dispatcher = ACPToolDispatcher(guard)

@dispatcher.tool(
    capability="acp:cap:financial.payment",
    resource="bank://accounts/*",
    risk_params=["amount"],
)
def transfer_funds(amount: float, to_account: str) -> str:
    """Transfer funds. Body only runs if ACP says APPROVED."""
    return payment_system.transfer(amount, to_account)

# Mount on FastMCP
from mcp.server.fastmcp import FastMCP
mcp_server = FastMCP("acp-banking")
dispatcher.mount(mcp_server)
mcp_server.run()
```

MCP response format:

| ACP decision | `isError` | `content[0].text` |
|---|---|---|
| `APPROVED` | `false` | Tool result + ET reference |
| `ESCALATED` | `true` | Escalation notice + ID |
| `DENIED` | `true` | Denial notice + risk score |

### Claude Desktop config

```json
{
  "mcpServers": {
    "acp-banking": {
      "command": "python",
      "args": ["/path/to/impl/python/examples/mcp_server_demo.py", "--server"]
    }
  }
}
```

---

## Running with the ACP reference server

All three integration demos support `--online` to run against the ACP
reference server instead of the offline crypto layer:

```bash
docker run -p 8080:8080 \
  -e ACP_INSTITUTION_PUBLIC_KEY=cA4s58S2dEJ-qye6EpJaJKKaVfvPT8mAQf97Vo8TInk \
  ghcr.io/chelof100/acp-server:latest

python examples/admission_control_demo.py --online
python examples/langchain_agent_demo.py --online
python examples/pydantic_ai_demo.py --online
python examples/mcp_server_demo.py --online
```
