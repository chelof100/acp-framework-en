/**
 * @acp/sdk — Agent Control Protocol TypeScript SDK v1.0
 *
 * Implements: ACP-CT-1.0, ACP-SIGN-1.0, ACP-HP-1.0
 *
 * @example
 * ```typescript
 * import { ACPIdentity, ACPClient, signToken } from "@acp/sdk";
 *
 * const identity = ACPIdentity.generate();
 * const client = new ACPClient(identity, { baseUrl: "https://api.institution.com" });
 *
 * const response = await client.execute({
 *   method: "POST",
 *   path: "/api/v1/payments/transfer",
 *   capabilityToken: tokenJson,
 *   payload: { amount: 500, currency: "USD", to_account: "ACC-999" },
 * });
 * ```
 */

export { ACPIdentity, deriveAgentId, validateAgentId } from "./identity.js";
export {
  signToken,
  verifyTokenSignature,
  computeTokenHash,
  canonicalizePayload,
} from "./signer.js";
export { ACPClient, ACPHandshakeError } from "./client.js";

export type {
  CapabilityToken,
  SignedCapabilityToken,
  DelegationConstraints,
  RevocationConfig,
  ACPHeaders,
  ACPClientOptions,
  ExecuteOptions,
  ACPErrorCode,
} from "./types.js";

export const VERSION = "1.0.0";
