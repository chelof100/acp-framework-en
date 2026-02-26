/**
 * ACP Identity — Ed25519 key management and AgentID derivation.
 * Implements ACP-SIGN-1.0 §3.1:
 *   AgentID = base58(SHA-256(publicKeyBytes))
 *
 * Uses @noble/ed25519 v2 — pure JS, audited, no native bindings.
 */

import * as ed from "@noble/ed25519";
import bs58 from "bs58";
import { createHash } from "crypto";

// noble/ed25519 v2 requires a synchronous SHA-512 implementation.
// Node 18+ has createHash built-in.
ed.etc.sha512Sync = (...msgs: Uint8Array[]) => {
  const hash = createHash("sha512");
  for (const msg of msgs) hash.update(msg);
  return hash.digest();
};

// ─── ACPIdentity ──────────────────────────────────────────────────────────────

/**
 * An ACP agent's Ed25519 cryptographic identity.
 *
 * The private key is a 32-byte seed (never exposed on the wire).
 * The public key is a 32-byte Ed25519 point.
 * The AgentID is base58(SHA-256(publicKey)) — stable identifier.
 */
export class ACPIdentity {
  readonly privateKey: Uint8Array; // 32-byte seed
  readonly publicKey: Uint8Array;  // 32-byte Ed25519 public key

  private constructor(privateKey: Uint8Array, publicKey: Uint8Array) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /** Generate a new random Ed25519 identity. */
  static generate(): ACPIdentity {
    const privKey = ed.utils.randomPrivateKey();
    const pubKey = ed.getPublicKeySync(privKey);
    return new ACPIdentity(privKey, pubKey);
  }

  /**
   * Restore an identity from a 32-byte seed.
   * @param seed 32-byte Ed25519 private key seed
   */
  static fromSeed(seed: Uint8Array): ACPIdentity {
    if (seed.length !== 32) {
      throw new Error(`ACPIdentity.fromSeed: seed must be 32 bytes, got ${seed.length}`);
    }
    const pubKey = ed.getPublicKeySync(seed);
    return new ACPIdentity(seed, pubKey);
  }

  /**
   * Restore an identity from a 64-char hex-encoded seed.
   * @param hex 64-character hex string (encodes 32 bytes)
   */
  static fromHex(hex: string): ACPIdentity {
    const seed = Buffer.from(hex, "hex");
    return ACPIdentity.fromSeed(seed);
  }

  /**
   * The agent's stable identifier: base58(SHA-256(publicKey)).
   * Implements ACP-SIGN-1.0 §3.1.
   */
  get agentId(): string {
    return deriveAgentId(this.publicKey);
  }

  /**
   * Sign a canonical byte payload using ACP-SIGN-1.0:
   *   sig = Ed25519(sk, SHA-256(canonicalBytes))
   *
   * @param canonicalBytes JCS-canonicalized token payload bytes
   * @returns base64url-encoded (no padding) Ed25519 signature
   */
  sign(canonicalBytes: Uint8Array): string {
    const digest = createHash("sha256").update(canonicalBytes).digest();
    const sig = ed.signSync(digest, this.privateKey);
    return Buffer.from(sig).toString("base64url");
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Derive an AgentID from an Ed25519 public key.
 * AgentID = base58(SHA-256(publicKeyBytes))
 */
export function deriveAgentId(publicKey: Uint8Array): string {
  const hash = createHash("sha256").update(publicKey).digest();
  return bs58.encode(hash);
}

/**
 * Validate that a string looks like a valid ACP AgentID.
 * AgentIDs are 43-44 char base58 strings derived from a 32-byte SHA-256 hash.
 */
export function validateAgentId(agentId: string): void {
  if (!agentId || agentId.length < 40 || agentId.length > 50) {
    throw new Error(
      `acp/identity: invalid AgentID length ${agentId?.length}: "${agentId}"`
    );
  }
  if (/\s/.test(agentId)) {
    throw new Error(`acp/identity: AgentID must not contain whitespace: "${agentId}"`);
  }
}
