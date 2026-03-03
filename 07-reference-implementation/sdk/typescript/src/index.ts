/**
 * @acp/sdk — Agent Capability Protocol TypeScript/Node.js SDK v1.0
 *
 * Implements: ACP-CT-1.0, ACP-SIGN-1.0, ACP-HP-1.0
 *
 * Zero runtime dependencies — requires only Node.js 18+.
 *
 * @example
 * ```typescript
 * import { AgentIdentity, ACPSigner, ACPClient } from '@acp/sdk';
 *
 * const agent = AgentIdentity.generate();
 * const signer = new ACPSigner(agent);
 * const client = new ACPClient('http://localhost:8080', agent, signer);
 *
 * // Register once
 * await client.register();
 *
 * // Verify a capability token
 * const result = await client.verify(signedToken);
 * // { ok: true, agent_id: '...', capabilities: [...] }
 * ```
 */

// ─── Core exports ─────────────────────────────────────────────────────────────
export { AgentIdentity, deriveAgentId } from './identity';
export { ACPSigner, jcsCanonicalize } from './signer';
export { ACPClient, ACPError } from './client';

// ─── Type exports ─────────────────────────────────────────────────────────────
export type {
  CapabilityToken,
  SignedCapabilityToken,
  DelegationConstraints,
  RevocationConfig,
  ACPHeaders,
  ACPClientOptions,
  ExecuteOptions,
  ACPErrorCode,
} from './types';

// ─── Version ──────────────────────────────────────────────────────────────────
export const VERSION = '1.0.0';
