/**
 * Example: AI Agent executing a payment using ACP TypeScript SDK.
 *
 * Demonstrates the complete ACP-HP-1.0 flow for an autonomous agent:
 *   1. Load/generate Ed25519 identity
 *   2. Create a capability token (issued by institutional authority)
 *   3. Execute the payment via ACPClient (auto handles challenge/PoP)
 *
 * Environment variables:
 *   ACP_AGENT_SEED   64-char hex-encoded 32-byte Ed25519 seed (optional)
 *   ACP_SERVER_URL   ACP server base URL (default: http://localhost:8080)
 *
 * Run (requires Go server):
 *   cd acp-go && ACP_INSTITUTION_PUBLIC_KEY=<pubkey> go run ./cmd/acp-server &
 *   ACP_SERVER_URL=http://localhost:8080 npx tsx examples/agent_payment.ts
 */

import { ACPIdentity, ACPClient, signToken } from "../src/index.js";
import type { CapabilityToken } from "../src/index.js";

// ─── Identity ─────────────────────────────────────────────────────────────────

function loadOrGenerateIdentity(): ACPIdentity {
  const seedHex = process.env.ACP_AGENT_SEED;
  if (seedHex && seedHex.length === 64) {
    console.log("[ACP] Loading identity from ACP_AGENT_SEED");
    return ACPIdentity.fromHex(seedHex);
  }
  console.warn("[ACP] ACP_AGENT_SEED not set — generating ephemeral identity");
  return ACPIdentity.generate();
}

// ─── Token Factory ────────────────────────────────────────────────────────────

/**
 * Create a test capability token signed by the issuer.
 *
 * In production:
 *   - The institutional issuer signs tokens via their secure HSM/KMS
 *   - The agent NEVER signs its own tokens
 *   - This is ONLY for local testing/demo purposes
 */
function createTestToken(
  issuerIdentity: ACPIdentity,
  agentIdentity: ACPIdentity
): string {
  const now = Math.floor(Date.now() / 1000);

  // Generate random 128-bit nonce.
  const nonceBytes = new Uint8Array(16);
  crypto.getRandomValues(nonceBytes);
  const nonce = Buffer.from(nonceBytes).toString("base64url");

  const payload: Omit<CapabilityToken, "sig"> = {
    ver: "1.0",
    iss: issuerIdentity.agentId,
    sub: agentIdentity.agentId,
    cap: ["acp:cap:financial.payment"],
    res: "org.banco-soberano/accounts/ACC-001",
    iat: now,
    exp: now + 3600,
    nonce,
    deleg: { allowed: false, max_depth: 0 },
    parent_hash: null,
    constraints: { max_amount_usd: 10000 },
    rev: {
      type: "endpoint",
      uri: "https://acp.banco-soberano.com/acp/v1/rev/check",
    },
  };

  const signed = signToken(payload, issuerIdentity);
  return JSON.stringify(signed);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log("=== ACP TypeScript SDK — Agent Payment Example ===\n");

  // 1. Agent identity.
  const agent = loadOrGenerateIdentity();
  console.log(`Agent AgentID : ${agent.agentId}`);
  console.log(`Agent PubKey  : ${Buffer.from(agent.publicKey).toString("hex").slice(0, 16)}...\n`);

  // 2. Institutional issuer (separate keypair in production).
  const issuer = ACPIdentity.generate();
  console.log(`Issuer AgentID: ${issuer.agentId}`);
  console.log(`Issuer PubKey : ${Buffer.from(issuer.publicKey).toString("hex").slice(0, 16)}...\n`);

  // 3. Create capability token.
  const tokenJson = createTestToken(issuer, agent);
  const tokenPreview = tokenJson.slice(0, 100);
  console.log(`Token (first 100 chars): ${tokenPreview}...\n`);

  // 4. Initialize ACP client.
  const baseUrl = process.env.ACP_SERVER_URL ?? "http://localhost:8080";
  const client = new ACPClient(agent, { baseUrl, timeoutMs: 5000 });

  // 5. Register agent with server (for PoP verification).
  console.log("Registering agent with server...");
  try {
    const pubKeyB64 = Buffer.from(agent.publicKey).toString("base64url");
    const regResponse = await fetch(`${baseUrl}/acp/v1/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ agent_id: agent.agentId, public_key_hex: pubKeyB64 }),
    });
    const regData = await regResponse.json() as { ok: boolean };
    if (regData.ok) {
      console.log("Agent registered successfully\n");
    }
  } catch (err) {
    console.log(`[Expected without server] Registration: ${(err as Error).message}\n`);
  }

  // 6. Execute payment with full ACP-HP-1.0 handshake.
  const transferPayload = {
    to_account: "ACC-999",
    amount: 500,
    currency: "USD",
    memo: "Invoice payment #2024-001",
  };

  console.log(`Executing payment: ${JSON.stringify(transferPayload)}`);
  console.log(`Server          : ${baseUrl}\n`);

  try {
    const response = await client.execute({
      method: "POST",
      path: "/api/v1/payments/transfer",
      capabilityToken: tokenJson,
      payload: transferPayload,
    });

    console.log(`Response status: ${response.status}`);
    const text = await response.text();
    console.log(`Response body  : ${text.slice(0, 300)}`);
  } catch (err) {
    const e = err as Error;
    console.log(`[Expected in demo without configured server]`);
    console.log(`${e.constructor.name}: ${e.message}`);
    console.log("\n--- To run the full demo ---");
    console.log("1. cd acp-go");
    console.log(`2. ACP_INSTITUTION_PUBLIC_KEY=${Buffer.from(issuer.publicKey).toString("base64url")} go run ./cmd/acp-server`);
    console.log("3. ACP_SERVER_URL=http://localhost:8080 npx tsx examples/agent_payment.ts");
  }
}

main().catch(console.error);
