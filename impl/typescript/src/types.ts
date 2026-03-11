/**
 * ACP Type Definitions — ACP-CT-1.0, ACP-HP-1.0, ACP-SIGN-1.0
 */

// ─── Capability Token ─────────────────────────────────────────────────────────

/** ACP Capability Token as defined in ACP-CT-1.0 §5 */
export interface CapabilityToken {
  /** Protocol version — must be "1.0" */
  ver: string;
  /** Issuer AgentID: base58(SHA-256(issuer_pubkey)) */
  iss: string;
  /** Subject AgentID — the agent authorized to use this token */
  sub: string;
  /** Capability identifiers granted (e.g., ["acp:cap:financial.payment"]) */
  cap: string[];
  /** Resource scope (e.g., "org.bank/accounts/ACC-001") */
  res: string;
  /** Issued-at Unix timestamp */
  iat: number;
  /** Expiration Unix timestamp */
  exp: number;
  /** Random nonce — 128-bit base64url, prevents replay attacks */
  nonce: string;
  /** Delegation constraints */
  deleg: DelegationConstraints;
  /** Parent token hash for delegated tokens (null for root tokens) */
  parent_hash: string | null;
  /** Domain-specific constraints (e.g., max_amount_usd) */
  constraints?: Record<string, unknown>;
  /** Revocation endpoint configuration */
  rev?: RevocationConfig;
  /** Ed25519 signature over SHA-256(JCS(payload_without_sig)) */
  sig?: string;
}

/** Delegation constraints embedded in every token */
export interface DelegationConstraints {
  /** Whether the subject may further delegate this token */
  allowed: boolean;
  /** Maximum remaining delegation depth (0 = no further delegation) */
  max_depth: number;
}

/** Revocation endpoint configuration */
export interface RevocationConfig {
  /** Type of revocation check */
  type: "endpoint" | "crl";
  /** URI for revocation check */
  uri: string;
}

/** A CapabilityToken with the `sig` field populated */
export type SignedCapabilityToken = CapabilityToken & { sig: string };

// ─── ACP Error Codes ─────────────────────────────────────────────────────────

/** Standardized error codes per ACP-CT-1.0 §8 */
export type ACPErrorCode =
  | "CT-001" // malformed JSON
  | "CT-002" // unsupported version
  | "CT-003" // token expired
  | "CT-004" // iat in future
  | "CT-005" // revoked
  | "CT-006" // invalid signature
  | "CT-007" // issuer mismatch
  | "CT-008" // empty capabilities
  | "CT-009" // missing resource
  | "CT-010" // delegation depth exceeded
  | "CT-011" // subject mismatch
  | "CT-012" // nonce replay
  | "CT-013"; // constraint violation

// ─── ACP HTTP Headers ─────────────────────────────────────────────────────────

/** ACP HTTP Security Headers (ACP-HP-1.0) */
export interface ACPHeaders {
  Authorization: string;        // Bearer <token_json>
  "X-ACP-Agent-ID": string;    // AgentID
  "X-ACP-Challenge": string;   // challenge nonce
  "X-ACP-Signature": string;   // PoP signature
  "Content-Type": string;
}

// ─── Client Options ───────────────────────────────────────────────────────────

/** Options for ACPClient constructor */
export interface ACPClientOptions {
  /** Base URL of the ACP-compatible server (no trailing slash) */
  baseUrl: string;
  /** Request timeout in milliseconds (default: 10000) */
  timeoutMs?: number;
}

/** Options for client.execute() */
export interface ExecuteOptions {
  /** HTTP method */
  method: string;
  /** API path starting with "/" */
  path: string;
  /** Raw JSON capability token string */
  capabilityToken: string;
  /** Optional request body (will be JSON-serialized) */
  payload?: Record<string, unknown>;
}
