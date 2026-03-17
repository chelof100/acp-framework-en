# ACP Python SDK — Examples

Two examples that demonstrate ACP as admission control for agent actions.

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

## `langchain_agent_demo.py` — LangChain integration

Shows how to wrap any LangChain tool with ACP admission control using the
`@acp_tool` decorator. The agent cannot call a tool without passing the ACP
admission check first.

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

## Running with the ACP reference server

```bash
docker run -p 8080:8080 \
  -e ACP_INSTITUTION_PUBLIC_KEY=cA4s58S2dEJ-qye6EpJaJKKaVfvPT8mAQf97Vo8TInk \
  ghcr.io/chelof100/acp-server:latest

python examples/admission_control_demo.py --online
python examples/langchain_agent_demo.py --online
```
