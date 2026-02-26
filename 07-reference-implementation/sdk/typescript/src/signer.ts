/**
 * ACP Signer — Token signing and signature verification.
 *
 * Implements ACP-SIGN-1.0:
 *   sig = Ed25519(sk, SHA-256(JCS(payload_without_sig)))
 *
 * JCS = JSON Canonicalization Scheme (RFC 8785)
 * Library: "canonicalize" — compliant RFC 8785 implementation.
 */

import * as ed from "@noble/ed25519";
import canonicalize from "canonicalize";
import { createHash } from "crypto";

import type { CapabilityToken, SignedCapabilityToken } from "./types.js";
import { ACPIdentity } from "./identity.js";

// ─── JCS Canonicalization ─────────────────────────────────────────────────────

/**
 * Produce the JCS (RFC 8785) canonical byte representation of a payload.
 * Returns UTF-8 encoded bytes suitable for hashing.
 */
export function canonicalizePayload(payload: unknown): Uint8Array {
  const canonical = canonicalize(payload);
  if (canonical === undefined) {
    throw new Error("acp/signer: canonicalize() returned undefined for payload");
  }
  return Buffer.from(canonical, "utf-8");
}

// ─── Token Signing ────────────────────────────────────────────────────────────

/**
 * Sign a Capability Token using ACP-SIGN-1.0.
 *
 * Steps:
 *   1. Remove any existing "sig" field from the payload
 *   2. JCS-canonicalize (RFC 8785) the remaining fields
 *   3. SHA-256 hash the canonical bytes
 *   4. Ed25519-sign the hash
 *   5. Encode signature as base64url (no padding)
 *   6. Return token with "sig" populated
 *
 * @param payload Token payload — the "sig" field will be ignored/stripped
 * @param identity Issuer's ACPIdentity
 * @returns SignedCapabilityToken with populated "sig" field
 */
export function signToken(
  payload: Omit<CapabilityToken, "sig">,
  identity: ACPIdentity
): SignedCapabilityToken {
  // Strip sig if present.
  const { sig: _sig, ...withoutSig } = payload as CapabilityToken;

  // JCS-canonicalize.
  const canonicalBytes = canonicalizePayload(withoutSig);

  // Sign.
  const sigB64 = identity.sign(canonicalBytes);

  return { ...withoutSig, sig: sigB64 } as SignedCapabilityToken;
}

// ─── Signature Verification ───────────────────────────────────────────────────

/**
 * Verify the Ed25519 signature on a Capability Token.
 *
 * @param token A SignedCapabilityToken (must have non-empty "sig" field)
 * @param issuerPublicKey 32-byte Ed25519 public key of the issuer
 * @returns true if signature is valid
 * @throws Error with code CT-006 if signature is invalid or missing
 */
export function verifyTokenSignature(
  token: SignedCapabilityToken,
  issuerPublicKey: Uint8Array
): boolean {
  const { sig, ...withoutSig } = token;

  if (!sig) {
    throw new Error("CT-006: missing signature field (sig)");
  }

  // Reconstruct canonical bytes (same as signing).
  const canonicalBytes = canonicalizePayload(withoutSig);
  const digest = createHash("sha256").update(canonicalBytes).digest();

  // Decode signature.
  let sigBytes: Buffer;
  try {
    sigBytes = Buffer.from(sig, "base64url");
  } catch {
    throw new Error("CT-006: invalid signature encoding (expected base64url)");
  }

  if (sigBytes.length !== 64) {
    throw new Error(`CT-006: signature must be 64 bytes, got ${sigBytes.length}`);
  }

  // Verify with noble/ed25519.
  const valid = ed.verifySync(
    new Uint8Array(sigBytes),
    new Uint8Array(digest),
    issuerPublicKey
  );

  if (!valid) {
    throw new Error("CT-006: Ed25519 signature verification failed");
  }
  return true;
}

// ─── Token Hash ───────────────────────────────────────────────────────────────

/**
 * Compute SHA-256 hash of a signed token JSON string.
 * Used for delegation chain linking (parent_hash field).
 *
 * @param tokenJson Raw JSON string of the signed token
 * @returns base64url-encoded (no padding) SHA-256 hash
 */
export function computeTokenHash(tokenJson: string): string {
  return createHash("sha256")
    .update(Buffer.from(tokenJson, "utf-8"))
    .digest("base64url");
}
