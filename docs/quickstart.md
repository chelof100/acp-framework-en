# ACP Quickstart

> Get started with Agent Control Protocol in under 10 minutes.

## What is ACP?

ACP is a governance protocol — a standard (not a software library) — that defines how autonomous agents must prove identity, capability, and delegation authority before executing any action.

## Prerequisites

- Read [`docs/architecture-overview.md`](architecture-overview.md) for the conceptual model
- Choose a conformance target: L1-CORE (minimum) through L5-DECENTRALIZED

## Step 1 — Understand the core invariant

Every ACP-compliant execution must satisfy:

```
Execute(req) ⟹ ValidIdentity ∧ ValidCapability ∧ ValidDelegationChain ∧ AcceptableRisk
```

No action proceeds unless all four predicates hold simultaneously.

## Step 2 — Pick your conformance level

| Target | Specs required |
|--------|---------------|
| L1-CORE | ACP-AGENT-1.0, ACP-CAP-REG-1.0 |
| L2-SECURITY | + ACP-SIGN-1.0 |
| L3-FULL | + ACP-DCMA-1.0, ACP-CT-1.0 |
| L4-EXTENDED | + ACP-LEDGER-1.0, ACP-RISK-1.0 |
| L5-DECENTRALIZED | + ACP-D |

## Step 3 — Read the specs

All specifications live in [`spec/`](../spec/). Start with:

1. [`spec/core/ACP-AGENT-1.0.md`](../spec/core/ACP-AGENT-1.0.md) — Agent identity model
2. [`spec/core/ACP-CAP-REG-1.0.md`](../spec/core/ACP-CAP-REG-1.0.md) — Capability registry
3. [`spec/governance/ACP-CONF-1.1.md`](../spec/governance/ACP-CONF-1.1.md) — Conformance levels

## Step 4 — Explore the reference implementation

Working code in [`impl/`](../impl/):
- Go: [`impl/go/`](../impl/go/)
- Python SDK: [`impl/python/`](../impl/python/)
- Rust SDK: [`impl/rust/`](../impl/rust/)
- TypeScript SDK: [`impl/typescript/`](../impl/typescript/)

## Step 5 — Run compliance tests

```bash
cd compliance/
# See compliance/README.md for test vector instructions
```

## Next steps

- [`docs/faq.md`](faq.md) — Common questions
- [`CONTRIBUTING.md`](../CONTRIBUTING.md) — How to contribute specs or code
