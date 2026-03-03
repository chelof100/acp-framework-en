/**
 * acp/signer — JCS canonicalization + Ed25519 signing pipeline (ACP-SIGN-1.0)
 *
 * ACP signing pipeline:
 *   1. Canonicalize the capability object using JCS (RFC 8785)
 *   2. Compute SHA-256 of the canonical bytes
 *   3. Sign the digest with Ed25519
 *   4. Embed the signature as base64url in the capability's flat "sig" field (ACP-CT-1.0)
 *
 * Zero runtime dependencies — uses only Node.js built-in `node:crypto`.
 *
 * @example
 * ```typescript
 * import { AgentIdentity, ACPSigner } from '@acp/sdk';
 *
 * const agent = AgentIdentity.generate();
 * const signer = new ACPSigner(agent);
 *
 * const capability = {
 *   ver: '1.0', iss: agent.did, sub: agent.agentId,
 *   iat: 1700000000, exp: 1700003600,
 *   nonce: 'random-nonce',
 *   cap: ['acp:cap:financial.payment'],
 *   res: 'org.example/accounts/ACC-001',
 * };
 *
 * const signed = signer.signCapability(capability);
 * // signed['sig'] contains the base64url Ed25519 signature
 *
 * const isValid = ACPSigner.verifyCapability(signed, agent.publicKeyBytes);
 * ```
 */

import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { AgentIdentity } from './identity';

// ─── JCS Canonicalization (RFC 8785) ─────────────────────────────────────────

/**
 * Recursively produce the JCS (RFC 8785) canonical string of a JSON value.
 *
 * Rules:
 *   - Object keys sorted lexicographically by Unicode code point
 *   - No whitespace between tokens
 *   - Strings encoded via JSON.stringify (proper escape sequences)
 *   - Numbers encoded via JSON.stringify (IEEE 754 representation)
 */
function _jcsStr(obj: unknown): string {
  if (obj === null) return 'null';
  if (typeof obj === 'boolean') return obj ? 'true' : 'false';
  if (typeof obj === 'number') return JSON.stringify(obj);
  if (typeof obj === 'string') return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return '[' + obj.map(_jcsStr).join(',') + ']';
  }
  if (typeof obj === 'object') {
    const sorted = Object.entries(obj as Record<string, unknown>).sort(
      ([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)
    );
    return (
      '{' +
      sorted.map(([k, v]) => `${JSON.stringify(k)}:${_jcsStr(v)}`).join(',') +
      '}'
    );
  }
  throw new TypeError(`jcsCanonicalize: not JSON-serializable: ${typeof obj}`);
}

/**
 * JCS-canonicalize an object to UTF-8 bytes (RFC 8785).
 * Exported for use by tests and external callers.
 */
export function jcsCanonicalize(obj: unknown): Buffer {
  return Buffer.from(_jcsStr(obj), 'utf-8');
}

// ─── SPKI header (for verifyCapability) ──────────────────────────────────────

// Ed25519 SPKI DER prefix (12 bytes): 302a300506032b6570032100
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

// ─── ACPSigner ────────────────────────────────────────────────────────────────

/**
 * ACP signing and verification pipeline (ACP-SIGN-1.0).
 *
 * Pipeline: JCS(capability) → SHA-256 → Ed25519.sign → base64url
 */
export class ACPSigner {
  private readonly _identity: AgentIdentity;

  constructor(identity: AgentIdentity) {
    this._identity = identity;
  }

  // ─── Signing ────────────────────────────────────────────────────────────────

  /**
   * Sign a capability object and embed the signature in capability["sig"].
   *
   * The input dict is NOT modified. A new object is returned with the "sig"
   * field added/replaced (flat field per ACP-CT-1.0).
   *
   * The signing input is JCS(capability WITHOUT "sig").
   */
  signCapability(capability: Record<string, unknown>): Record<string, unknown> {
    // Strip existing "sig" before signing
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { sig: _sig, ...capToSign } = capability;

    // JCS canonicalize → SHA-256 → Ed25519.sign
    const canonical = jcsCanonicalize(capToSign);
    const digest = createHash('sha256').update(canonical).digest();
    const sigBytes = this._identity.sign(digest);
    const sigB64 = sigBytes.toString('base64url');

    return { ...capability, sig: sigB64 };
  }

  /**
   * Sign arbitrary bytes directly (for PoP challenges).
   * Returns raw 64-byte Ed25519 signature.
   */
  signBytes(data: Buffer): Buffer {
    return this._identity.sign(data);
  }

  // ─── Verification ───────────────────────────────────────────────────────────

  /**
   * Verify a signed capability against a 32-byte Ed25519 public key.
   *
   * Returns true if the signature is valid, false otherwise.
   * Expects the signature in the flat "sig" field (ACP-CT-1.0).
   */
  static verifyCapability(
    capability: Record<string, unknown>,
    publicKeyBytes: Buffer
  ): boolean {
    const sig = capability['sig'];
    if (!sig || typeof sig !== 'string') return false;

    // Reconstruct signing input (capability without "sig")
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { sig: _sig, ...capToVerify } = capability;

    try {
      const canonical = jcsCanonicalize(capToVerify);
      const digest = createHash('sha256').update(canonical).digest();

      // Decode base64url signature
      const sigBytes = Buffer.from(sig, 'base64url');
      if (sigBytes.length !== 64) return false;

      // Reconstruct public key from raw bytes
      const spkiDer = Buffer.concat([SPKI_PREFIX, publicKeyBytes]);
      const pubKey = createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });

      return cryptoVerify(null, digest, pubKey, sigBytes);
    } catch {
      return false;
    }
  }

  /** Expose JCS canonicalization for external use. */
  static canonicalize(obj: unknown): Buffer {
    return jcsCanonicalize(obj);
  }
}
