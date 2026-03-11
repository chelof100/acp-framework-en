# ACP — Frequently Asked Questions

## What is ACP?

ACP (Agent Control Protocol) is a protocol standard — like JWT or OAuth — that defines constitutional governance for autonomous agents. It is not a software library. The spec is the product; implementations are evidence the spec works.

## Is ACP software I can install?

No. ACP is a specification. You implement it. Reference implementations exist in [`impl/`](../impl/) to demonstrate that the spec is implementable, but the authoritative artifact is the spec in [`spec/`](../spec/).

## How does ACP relate to MIR and ARAF?

ACP sits at layer 4 of the Agent Governance Stack (Execution Governance). It produces the cryptographic evidence — identity assertions, delegation proofs, policy snapshots — that:
- **MIR** (participation history layer, L5) consumes to build verifiable agent history
- **ARAF** (risk architecture layer, L8) consumes to produce risk scores and liability traces

## What is the minimum I need to implement?

L1-CORE conformance requires:
- `ACP-AGENT-1.0` — agent identity model
- `ACP-CAP-REG-1.0` — capability registry

See [`docs/quickstart.md`](quickstart.md) for a step-by-step guide.

## What makes ACP different from other agent frameworks?

ACP focuses exclusively on **governance at execution time** — the moment an agent decides to act. It answers: *by what authority does this agent take this action, right now, under current policy?*

Most frameworks focus on capability (what an agent can do). ACP focuses on authority provenance (where the right to do it came from).

## What is Authority Provenance?

A structured object that proves, at execution time, the complete chain of authority behind an agent's action:
- Which principal originally delegated
- Through what delegation chain
- Under what policy context
- At what time

This is being formalized in `ACP-PROVENANCE-1.0` (in progress).

## Can ACP work without a central identity issuer?

Yes. The `spec/decentralized/` section (ACP-D) defines architecture for decentralized operation without a central trust anchor. This corresponds to L5-DECENTRALIZED conformance.

## How do I contribute?

See [`CONTRIBUTING.md`](../CONTRIBUTING.md) and [`spec/governance/RFC-PROCESS.md`](../spec/governance/RFC-PROCESS.md).
