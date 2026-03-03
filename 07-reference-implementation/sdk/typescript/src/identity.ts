/**
 * acp/identity — Ed25519 Agent Identity + AgentID derivation (ACP-SIGN-1.0)
 *
 * An agent's cryptographic identity consists of:
 *   - An Ed25519 private/public key pair
 *   - An AgentID derived as base58(SHA-256(raw 32-byte public key))
 *   - A DID (did:key) representation
 *
 * Zero runtime dependencies — uses only Node.js built-in `node:crypto`.
 *
 * @example
 * ```typescript
 * import { AgentIdentity } from '@acp/sdk';
 *
 * const agent = AgentIdentity.generate();
 * console.log(agent.agentId);         // base58 string
 * console.log(agent.did);             // "did:key:z..."
 * console.log(agent.publicKeyBytes);  // Buffer(32)
 *
 * // Round-trip
 * const restored = AgentIdentity.fromPrivateBytes(agent.privateKeyBytes);
 * // restored.agentId === agent.agentId
 * ```
 */

import {
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  createHash,
} from 'node:crypto';
import type { KeyObject } from 'node:crypto';

// ─── DER headers ──────────────────────────────────────────────────────────────
// Ed25519 PKCS8 DER prefix (16 bytes): 302e020100300506032b657004220420
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
// Ed25519 SPKI DER prefix (12 bytes): 302a300506032b6570032100
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
// Multicodec prefix for Ed25519 public key (for did:key): 0xed 0x01
const ED25519_MULTICODEC = Buffer.from([0xed, 0x01]);

// ─── Base58btc ────────────────────────────────────────────────────────────────

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/** Base58btc encoding (Bitcoin alphabet, same as Python's _base58_encode). */
function base58Encode(data: Buffer): string {
  // Count leading zero bytes
  let leadingZeros = 0;
  for (const byte of data) {
    if (byte === 0) leadingZeros++;
    else break;
  }

  // Convert bytes → big integer
  let n = 0n;
  for (const byte of data) {
    n = n * 256n + BigInt(byte);
  }

  // Convert big integer → base58 digits (reversed)
  const digits: number[] = [];
  while (n > 0n) {
    const rem = Number(n % 58n);
    n /= 58n;
    digits.push(rem);
  }

  return (
    BASE58_ALPHABET[0].repeat(leadingZeros) +
    digits
      .reverse()
      .map((d) => BASE58_ALPHABET[d])
      .join('')
  );
}

// ─── AgentIdentity ────────────────────────────────────────────────────────────

/**
 * Ed25519 Agent Identity (ACP-SIGN-1.0).
 *
 * Attributes:
 *   agentId        — base58(SHA-256(raw 32-byte public key))  [ACP-CT-1.0 §3]
 *   did            — did:key:z<base58(0xed01 || pubkey)>
 *   publicKeyBytes — 32-byte raw Ed25519 public key
 *   privateKeyBytes— 32-byte raw Ed25519 private key (store securely!)
 */
export class AgentIdentity {
  private readonly _privateKey: KeyObject;
  private readonly _publicKey: KeyObject;
  private readonly _pubkeyRaw: Buffer;

  private constructor(privateKey: KeyObject, publicKey: KeyObject) {
    this._privateKey = privateKey;
    this._publicKey = publicKey;
    // Strip the 12-byte SPKI DER header to get the raw 32-byte key
    const spkiDer = this._publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
    this._pubkeyRaw = Buffer.from(spkiDer.subarray(12));
  }

  // ─── Constructors ───────────────────────────────────────────────────────────

  /** Generate a new random Ed25519 agent identity. */
  static generate(): AgentIdentity {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    return new AgentIdentity(privateKey, publicKey);
  }

  /**
   * Restore an identity from 32 raw private key bytes.
   * @param data 32-byte raw Ed25519 private key seed
   */
  static fromPrivateBytes(data: Buffer): AgentIdentity {
    if (data.length !== 32) {
      throw new Error(
        `AgentIdentity.fromPrivateBytes: expected 32 bytes, got ${data.length}`
      );
    }
    const pkcs8 = Buffer.concat([PKCS8_PREFIX, data]);
    const privateKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
    const publicKey = createPublicKey(privateKey);
    return new AgentIdentity(privateKey, publicKey);
  }

  // ─── Properties ─────────────────────────────────────────────────────────────

  /**
   * ACP AgentID: base58(SHA-256(raw 32-byte public key)).
   * Implements ACP-SIGN-1.0 §3.1.
   */
  get agentId(): string {
    const digest = createHash('sha256').update(this._pubkeyRaw).digest();
    return base58Encode(digest);
  }

  /**
   * did:key representation (multicodec Ed25519 + base58btc).
   * Format: did:key:z<base58(0xed01 || pubkey)>
   */
  get did(): string {
    const multicodec = Buffer.concat([ED25519_MULTICODEC, this._pubkeyRaw]);
    return `did:key:z${base58Encode(multicodec)}`;
  }

  /** Raw 32-byte Ed25519 public key. */
  get publicKeyBytes(): Buffer {
    return Buffer.from(this._pubkeyRaw);
  }

  /** Raw 32-byte Ed25519 private key (store securely!). */
  get privateKeyBytes(): Buffer {
    const pkcs8 = this._privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
    return Buffer.from(pkcs8.subarray(16)); // strip 16-byte PKCS8 header
  }

  // ─── Signing ────────────────────────────────────────────────────────────────

  /**
   * Sign arbitrary bytes with Ed25519. Returns 64-byte raw signature.
   * The caller is responsible for any pre-hashing (e.g. SHA-256 for ACP-SIGN-1.0).
   */
  sign(message: Buffer): Buffer {
    return cryptoSign(null, message, this._privateKey) as Buffer;
  }

  /**
   * Verify a 64-byte Ed25519 signature against a message.
   * Returns true if valid, false otherwise.
   */
  verify(signature: Buffer, message: Buffer): boolean {
    try {
      return cryptoVerify(null, message, this._publicKey, signature);
    } catch {
      return false;
    }
  }

  toString(): string {
    return `AgentIdentity(agentId=${this.agentId})`;
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Derive an AgentID from raw 32-byte Ed25519 public key bytes.
 * AgentID = base58(SHA-256(publicKeyBytes))
 */
export function deriveAgentId(publicKeyBytes: Buffer): string {
  const digest = createHash('sha256').update(publicKeyBytes).digest();
  return base58Encode(digest);
}
