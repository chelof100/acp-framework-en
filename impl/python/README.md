# ACP Python SDK

Python SDK for the Agent Control Protocol (ACP) — admission control for agent actions.

## Install

```bash
pip install -e .
```

Requires Python 3.10+. The only dependency is `cryptography>=42.0.0`.

## Quick start

```python
from acp.identity import AgentIdentity
from acp.signer import ACPSigner

# Generate agent identity
agent = AgentIdentity.generate()
print(agent.agent_id)   # base58(SHA-256(public_key))

# Sign and verify a capability token
signer = ACPSigner(agent)
token = signer.sign_capability({
    "ver": "1.0",
    "iss": agent.did,
    "sub": agent.agent_id,
    "cap": ["acp:cap:financial.payment"],
    "resource": "bank://accounts/ACC-001",
    "exp": 9999999999,
    "nonce": "abc123",
})
assert ACPSigner.verify_capability(token, agent.public_key_bytes)
```

## Examples

```bash
# Core admission control pattern (offline, no server)
python examples/admission_control_demo.py

# LangChain integration (offline)
python examples/langchain_agent_demo.py

# LangChain integration (with LLM)
pip install langchain langchain-openai
export OPENAI_API_KEY=sk-...
python examples/langchain_agent_demo.py --with-llm
```

See `examples/README.md` for full documentation.

## Repository

https://github.com/chelof100/acp-framework-en
https://agentcontrolprotocol.xyz
