## 1. Prototype Scope

Implement:

- Agent registration with public key.
- Formal authorization engine.
- Delegation with constraints.
- Hash-chained ledger.
- Transitive revocation.
- Failed attack simulation.

Do not implement:

- Real distributed infrastructure.
- Full PKI.
- UI.
- Real network.

Everything can run locally.

## 2. Prototype Architecture

Minimal Python structure:

```
acp/
 ├── identity.py
 ├── agent.py
 ├── delegation.py
 ├── policy_engine.py
 ├── authorization.py
 ├── ledger.py
 ├── control_authority.py
 └── main_demo.py
```

## 3. Technical Components

### 3.1 Identity Module

Responsible for:

- Generating public/private key pair.
- Signing messages.
- Verifying signatures.

Use a standard library such as:

- cryptography (ed25519)

Requirement:

- Every ActionRequest must be verified against the registered public key.

### 3.2 Agent Model

Agent class:

Attributes:

- agent_id
- public_key
- capabilities
- limits
- state
- delegations_received

Method:

- request_action(action_type, params)

Does not execute directly.
Only generates a request.

### 3.3 Delegation Engine

Structure:

```
Delegation:
  - delegator_id
  - delegate_id
  - capability
  - constraints
  - expiry
  - signature
```

Validation:

- delegator must have the capability.
- constraints ⊆ original constraints.
- must not exceed depth limit.

### 3.4 Policy Engine

Function:

- evaluate(request)

Simple implementation:

- verify capability
- verify limits
- calculate risk (simulated)
- compare against threshold

Returns:

- APPROVED
- DENIED
- ESCALATED

### 3.5 Authorization Layer

Central function:

- authorize(request)

Steps:

1. Verify signature.
2. Verify agent state.
3. Resolve delegation if applicable.
4. Evaluate policies.
5. Record in ledger.
6. Return decision.

Mandatory separation:

- Agent never executes without authorize().

### 3.6 Ledger

Structure:

```
Event:
  - request_id
  - decision
  - risk
  - prev_hash
  - hash
```

Hash:

```
sha256(serialized_event + prev_hash)
```

Method:

- verify_chain()

If someone alters an event → chain is invalid.

### 3.7 Control Authority

Functions:

- suspend_agent(agent_id)
- revoke_agent(agent_id)
- revoke_delegations(agent_id)

Revocation must:

- invalidate descendant delegations
- block future actions

## 4. Demonstration Scenario

main_demo.py must execute:

### Case 1 — Valid execution

- Agent A has capability `approve_tx`
- Requests action
- Engine approves
- Ledger records
- Expected result: APPROVED

### Case 2 — Attempt without capability

- Agent B without permission
- Requests `approve_tx`
- Expected result: DENIED

### Case 3 — Valid delegation

- A delegates `approve_tx` to B
- B executes within limits
- Expected result: APPROVED

### Case 4 — Delegation exceeding limits

- B attempts amount greater than allowed
- Expected result: DENIED

### Case 5 — Transitive revocation

- Revoke A
- B attempts to execute inherited delegation
- Expected result: DENIED

### Case 6 — Ledger tampering

- Manually alter an event
- Run verify_chain()
- Expected result: FAIL

## 5. Properties to Demonstrate

The prototype must prove:

- Execute(req) ⇒ Decision = APPROVED
- Delegation does not expand privileges.
- Revocation invalidates the chain.
- Ledger detects tampering.
- No direct execution exists.

If any single one fails → design is incorrect.

## 6. Success Metric

Prototype is valid if:

- Code < 800 lines.
- Demonstrable cases are reproducible.
- Engine is deterministic.
- Simulated attacks fail.
