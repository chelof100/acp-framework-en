# @acp/sdk — ACP TypeScript SDK

TypeScript SDK for the **Agent Control Protocol (ACP) v1.0**. For AI agents built with LangChain.js, Vercel AI SDK, or any Node.js framework.

## Install

```bash
npm install @acp/sdk
```

## Quick Start

```typescript
import { ACPIdentity, ACPClient, signToken } from "@acp/sdk";

// 1. Create or restore agent identity
const identity = ACPIdentity.generate();
// or: ACPIdentity.fromHex(process.env.ACP_AGENT_SEED!)

// 2. Create client
const client = new ACPClient(identity, {
  baseUrl: "https://api.institution.com",
});

// 3. Execute with capability token (full PoP handshake is automatic)
const response = await client.execute({
  method: "POST",
  path: "/api/v1/payments/transfer",
  capabilityToken: myCapabilityTokenJson,
  payload: { amount: 500, currency: "USD", to_account: "ACC-999" },
});
```

## Specs Implemented

| Spec | Description |
|---|---|
| ACP-CT-1.0 §5 | Capability Token structure |
| ACP-SIGN-1.0 | Ed25519 signing with JCS (RFC 8785) canonicalization |
| ACP-HP-1.0 | Challenge/PoP HTTP handshake with channel binding |

## API Reference

### `ACPIdentity`

```typescript
// Create
const identity = ACPIdentity.generate();
const identity = ACPIdentity.fromSeed(seed: Uint8Array);
const identity = ACPIdentity.fromHex(hex: string); // 64-char hex

// Properties
identity.agentId     // base58(SHA-256(publicKey))
identity.publicKey   // Uint8Array (32 bytes)
identity.privateKey  // Uint8Array (32-byte seed)

// Methods
identity.sign(canonicalBytes: Uint8Array) // → base64url signature
```

### `ACPClient`

```typescript
const client = new ACPClient(identity, {
  baseUrl: "https://api.institution.com",
  timeoutMs: 10000, // optional, default 10s
});

// Execute with auto-handshake
const response = await client.execute({
  method: "POST",
  path: "/api/v1/payments/transfer",
  capabilityToken: tokenJson,
  payload: { amount: 500 },
});
```

### Token Utilities

```typescript
import { signToken, verifyTokenSignature, computeTokenHash } from "@acp/sdk";

// Sign a token (issuer only — not agents)
const signed = signToken(payload, issuerIdentity);

// Verify signature
verifyTokenSignature(token, issuerPublicKey); // throws CT-006 if invalid

// Hash for delegation chains
const hash = computeTokenHash(tokenJson); // → base64url SHA-256
```

## Build

```bash
npm install
npm run build    # produces dist/
npm run typecheck
```

## LangChain.js Integration

```typescript
import { Tool } from "langchain/tools";
import { ACPClient, ACPIdentity } from "@acp/sdk";

class ACPPaymentTool extends Tool {
  name = "acp_payment";
  description = "Execute authorized payment via ACP";

  private client: ACPClient;
  private tokenJson: string;

  constructor(identity: ACPIdentity, baseUrl: string, tokenJson: string) {
    super();
    this.client = new ACPClient(identity, { baseUrl });
    this.tokenJson = tokenJson;
  }

  async _call(input: string): Promise<string> {
    const payload = JSON.parse(input);
    const response = await this.client.execute({
      method: "POST",
      path: "/api/v1/payments/transfer",
      capabilityToken: this.tokenJson,
      payload,
    });
    return response.text();
  }
}
```
