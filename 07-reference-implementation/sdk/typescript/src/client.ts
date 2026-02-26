/**
 * ACP HTTP Client — ACP-HP-1.0 Challenge/PoP Handshake.
 *
 * Automatically handles the full handshake:
 *   1. Request ephemeral challenge nonce from server
 *   2. Generate Proof-of-Possession with HTTP channel binding
 *   3. Attach ACP security headers to the actual request
 *
 * Compatible with LangChain.js, Vercel AI SDK, and plain Node.js.
 */

import { createHash } from "crypto";
import type { ACPClientOptions, ACPHeaders, ExecuteOptions } from "./types.js";
import type { ACPIdentity } from "./identity.js";

// ─── Constants ────────────────────────────────────────────────────────────────

const CHALLENGE_PATH = "/acp/v1/challenge";

// ─── Errors ───────────────────────────────────────────────────────────────────

/** Thrown when the ACP challenge/PoP handshake fails. */
export class ACPHandshakeError extends Error {
  constructor(message: string) {
    super(`ACPHandshakeError: ${message}`);
    this.name = "ACPHandshakeError";
  }
}

// ─── ACPClient ────────────────────────────────────────────────────────────────

/**
 * ACP HTTP client for autonomous AI agents.
 *
 * Performs the full ACP-HP-1.0 handshake transparently on every request.
 *
 * @example
 * ```typescript
 * const identity = ACPIdentity.generate();
 * const client = new ACPClient(identity, { baseUrl: "https://api.institution.com" });
 *
 * const response = await client.execute({
 *   method: "POST",
 *   path: "/api/v1/payments/transfer",
 *   capabilityToken: tokenJson,
 *   payload: { to_account: "ACC-999", amount: 500, currency: "USD" },
 * });
 * ```
 */
export class ACPClient {
  private readonly identity: ACPIdentity;
  private readonly baseUrl: string;
  private readonly timeoutMs: number;

  constructor(identity: ACPIdentity, options: ACPClientOptions) {
    this.identity = identity;
    this.baseUrl = options.baseUrl.replace(/\/$/, "");
    this.timeoutMs = options.timeoutMs ?? 10_000;
  }

  // ── Public API ──────────────────────────────────────────────────────────────

  /**
   * Execute an authenticated action using a Capability Token.
   *
   * Full ACP-HP-1.0 handshake is performed automatically:
   *   challenge request → PoP signing → actual API call.
   *
   * @param options Execute options
   * @returns Raw fetch Response
   */
  async execute(options: ExecuteOptions): Promise<Response> {
    const method = options.method.toUpperCase();
    const path = options.path.startsWith("/") ? options.path : `/${options.path}`;
    const { capabilityToken, payload } = options;

    // 1. Request ephemeral challenge from server.
    const challenge = await this.requestChallenge();

    // 2. Serialize body deterministically.
    const bodyBytes =
      payload !== undefined
        ? Buffer.from(JSON.stringify(payload), "utf-8")
        : Buffer.alloc(0);

    // 3. Generate Proof-of-Possession signature.
    const popSig = this.buildPopSignature(method, path, challenge, bodyBytes);

    // 4. Assemble ACP security headers.
    const headers: ACPHeaders = {
      "Content-Type":      "application/json",
      "Authorization":     `Bearer ${capabilityToken}`,
      "X-ACP-Challenge":   challenge,
      "X-ACP-Signature":   popSig,
      "X-ACP-Agent-ID":    this.identity.agentId,
    };

    // 5. Send request with timeout.
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timerId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      return await fetch(url, {
        method,
        headers,
        body: bodyBytes.length > 0 ? bodyBytes : undefined,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timerId);
    }
  }

  // ── Internal ────────────────────────────────────────────────────────────────

  /**
   * Request a one-time 128-bit challenge nonce from the ACP server.
   * GET /acp/v1/challenge → { "challenge": "<base64url>" }
   */
  private async requestChallenge(): Promise<string> {
    const url = `${this.baseUrl}${CHALLENGE_PATH}`;
    const controller = new AbortController();
    const timerId = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await fetch(url, { method: "GET", signal: controller.signal });
    } finally {
      clearTimeout(timerId);
    }

    if (!response.ok) {
      throw new ACPHandshakeError(
        `challenge request failed: HTTP ${response.status} ${response.statusText}`
      );
    }

    const data = (await response.json()) as { challenge?: string };
    if (!data.challenge) {
      throw new ACPHandshakeError("server response missing 'challenge' field");
    }
    return data.challenge;
  }

  /**
   * Build the Proof-of-Possession signature (ACP-HP-1.0 channel binding).
   *
   * Signed payload (UTF-8):
   *   Method + "|" + Path + "|" + Challenge + "|" + base64url(SHA-256(body))
   *
   * Signature:
   *   Ed25519(sk_agent, SHA-256(signed_payload_bytes))
   *
   * @returns base64url-encoded (no padding) Ed25519 signature
   */
  private buildPopSignature(
    method: string,
    path: string,
    challenge: string,
    bodyBytes: Buffer
  ): string {
    const bodyHash = createHash("sha256").update(bodyBytes).digest();
    const bodyHashB64 = bodyHash.toString("base64url");

    const payload = `${method}|${path}|${challenge}|${bodyHashB64}`;
    return this.identity.sign(Buffer.from(payload, "utf-8"));
  }
}
