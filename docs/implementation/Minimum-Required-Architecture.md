ACP v1.0
Minimum Required Architecture (MRA)

# 1. Objective

Define the minimum set of components and rules required for an implementation to declare itself:

"ACP v1.0 Compliant"

Everything not listed here is an optional extension.

# 2. Fundamental Principle

No critical action executed by an autonomous agent may occur without prior explicit authorization issued by the ACP system.

Formally:

```
Decision(A) ≠ Execution(A)
Execution(A) requires Authorization(A, Action)
```

# 3. Minimum Required Components

An ACP v1.0 implementation MUST include the following five components:

## 3.1 Agent Identity Registry (AIR)

### Function

Register agents as autonomous entities with verifiable identity.

### Minimum requirements

Each agent MUST have:

- unique `agent_id`
- verifiable public key
- institutional domain
- autonomy level
- operational state

### Mandatory states

- `active`
- `restricted`
- `suspended`
- `revoked`

### Critical requirement

Every Action Request MUST be cryptographically signed by the agent's registered identity.

## 3.2 Authorization Enforcement Layer (AEL)

### Function

Intercept all critical actions before execution.

### Mandatory property

MUST be technically separate from the agent runtime.

The agent cannot modify or bypass this layer.

### Responsibilities

- Validate identity
- Validate operational state
- Validate permissions
- Submit to risk evaluation
- Issue formal decision

If the AEL fails, the action MUST be denied by default.

**Fail-closed is mandatory.**

## 3.3 Policy and Risk Engine (PRE)

### Function

Evaluate whether an action should be:

- `Approved`
- `Denied`
- `Escalated`

### Minimum requirements

MUST evaluate:

- Permission scope
- Quantitative constraints
- Operational context
- Risk threshold

### Minimum decision model

```
if not valid_permission:
    Denied
elif risk_score >= threshold:
    Escalated
else:
    Approved
```

Risk calculation may vary, but MUST produce:

- numeric `risk_score`
- structured `reason_code`

## 3.4 Action Ledger (AL)

### Function

Record all decisions.

### MUST record

- `request_id`
- `agent_id`
- `timestamp`
- `decision`
- `risk_score`
- `reason_code`
- `execution_status`

### Mandatory property

Records MUST be:

- Immutable
- Sequential
- Auditable

Blockchain is not mandatory.
But verifiable integrity MUST be guaranteed.

## 3.5 Control Authority Interface (CAI)

### Function

Allow external intervention.

### MUST allow

- Suspend agent
- Change autonomy level
- Revoke permissions
- Force audit

### Mandatory property

CAI decisions MUST take effect immediately.

No logical latency may exist that would allow execution after suspension.

# 4. Minimum Required Flow

For each critical action:

1. Agent generates Action Request.
2. Cryptographic signature included.
3. AEL intercepts.
4. PRE evaluates.
5. Decision is issued.
6. Recorded in Action Ledger.
7. Only if `Approved` → actual execution.

Mandatory order.

Cannot be altered.

# 5. Definition of Critical Action

ACP v1.0 does not define what is universally critical.

Each implementation MUST explicitly declare:

```
critical_action_set = { … }
```

And all MUST pass through the AEL.

# 6. Mandatory Decision Codes

An implementation MUST support at least:

- `ACP-100` Approved
- `ACP-200` Denied
- `ACP-300` Escalated
- `ACP-400` Agent Suspended
- `ACP-500` System Failure

# 7. Non-Compliance Conditions

An implementation is NOT ACP v1.0 compliant if:

- The agent can execute without passing through the AEL.
- No immutable record exists per action.
- No verifiable cryptographic identity exists.
- No immediate external suspension exists.
- The system operates in fail-open mode.

# 8. Mandatory Systemic Properties

ACP v1.0 MUST guarantee:

- Structural separation between decision and execution.
- Mandatory prior authorization.
- Reconstructible traceability.
- Immediate external intervention capability.
- Verifiable integrity of records.

# 9. What Is NOT Part of ACP v1.0

- Specific risk scoring model.
- Specific storage technology.
- Network infrastructure.
- Economic model.
- Political governance.

These belong to higher layers.

# 10. Result

With this minimum architecture:

ACP ceases to be a concept.
It becomes an implementable protocol.
