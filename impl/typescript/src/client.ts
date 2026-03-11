/**
 * acp/client — HTTP ACP client with automatic PoP handshake (ACP-HP-1.0)
 *
 * The ACPClient handles the full ACP authorization flow:
 *   1. POST /acp/v1/register → register agent's public key (once per agent)
 *   2. GET  /acp/v1/challenge → receive one-time nonce
 *   3. Sign PoP: Method|Path|Challenge|base64url(SHA-256(body)) → SHA-256 → Ed25519
 *   4. POST /acp/v1/verify   → send token + PoP via HTTP headers, receive decision
 *
 * HTTP headers used by verify():
 *   Authorization:   Bearer <capability_token_json>
 *   X-ACP-Agent-ID:  <agent_id>
 *   X-ACP-Challenge: <challenge>
 *   X-ACP-Signature: <pop_signature>
 *
 * Zero runtime dependencies — uses only Node.js built-in `node:crypto` and `fetch` (Node 18+).
 *
 * @example
 * ```typescript
 * import { AgentIdentity, ACPSigner, ACPClient } from '@acp/sdk';
 *
 * const agent = AgentIdentity.generate();
 * const signer = new ACPSigner(agent);
 * const client = new ACPClient('http://localhost:8080', agent, signer);
 *
 * // Register agent with the server (once)
 * await client.register();
 *
 * // Verify a capability token
 * const result = await client.verify(signedToken);
 * console.log(result); // { ok: true, agent_id: '...', capabilities: [...] }
 * ```
 */

import { createHash } from 'node:crypto';
import { AgentIdentity } from './identity';
import { ACPSigner } from './signer';

// ─── ACPError ─────────────────────────────────────────────────────────────────

/** Thrown when the ACP server returns an error or the request fails. */
export class ACPError extends Error {
  /** HTTP status code, if applicable. */
  readonly statusCode?: number;

  constructor(message: string, statusCode?: number) {
    super(message);
    this.name = 'ACPError';
    this.statusCode = statusCode;
  }
}

// ─── ACPClient ────────────────────────────────────────────────────────────────

/**
 * ACP HTTP client implementing the Challenge/PoP handshake (ACP-HP-1.0).
 *
 * The client is stateless between calls. Each verify() call performs a
 * fresh challenge request to prevent replay attacks.
 */
export class ACPClient {
  private readonly _server: string;
  private readonly _identity: AgentIdentity;
  private readonly _signer: ACPSigner;
  private readonly _timeoutMs: number;

  /**
   * @param serverUrl  Base URL of the ACP validator (e.g. "http://localhost:8080")
   * @param identity   Agent identity (Ed25519 key pair)
   * @param signer     ACPSigner instance for producing PoP signatures
   * @param timeoutMs  HTTP timeout in milliseconds (default: 10000)
   */
  constructor(
    serverUrl: string,
    identity: AgentIdentity,
    signer: ACPSigner,
    timeoutMs = 10_000
  ) {
    this._server = serverUrl.replace(/\/$/, '');
    this._identity = identity;
    this._signer = signer;
    this._timeoutMs = timeoutMs;
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  /**
   * Register this agent's public key with the ACP server.
   *
   * POST /acp/v1/register
   * Body: { "agent_id": "<agent_id>", "public_key_hex": "<base64url(pubkey)>" }
   *
   * Must be called once before verify(). In production, this endpoint is
   * restricted to institutional administrators.
   */
  async register(): Promise<Record<string, unknown>> {
    const pubKeyB64 = this._identity.publicKeyBytes.toString('base64url');
    return this._postJson('/acp/v1/register', {
      agent_id: this._identity.agentId,
      public_key_hex: pubKeyB64,
    });
  }

  /**
   * Full ACP verification flow (ACP-HP-1.0):
   *   1. GET /acp/v1/challenge  → one-time nonce
   *   2. Compute PoP: Method|Path|Challenge|base64url(SHA-256(body))
   *   3. POST /acp/v1/verify via HTTP headers (Authorization + X-ACP-*)
   *
   * @param capabilityToken Signed capability token object (from ACPSigner)
   * @returns { ok: true, agent_id: '...', capabilities: [...] }
   */
  async verify(
    capabilityToken: Record<string, unknown>
  ): Promise<Record<string, unknown>> {
    // Step 1: Get challenge
    const challengeResp = await this._getJson('/acp/v1/challenge');
    const challenge = challengeResp['challenge'] as string | undefined;
    if (!challenge) {
      throw new ACPError("server response missing 'challenge' field");
    }

    // Step 2: Serialize token (compact JSON) and compute PoP over empty body
    const tokenJson = JSON.stringify(capabilityToken);
    const body = Buffer.alloc(0);
    const popSig = this._signPop('POST', '/acp/v1/verify', challenge, body);

    // Step 3: POST with ACP headers
    return this._postWithAcpHeaders(
      '/acp/v1/verify',
      body,
      tokenJson,
      this._identity.agentId,
      challenge,
      popSig
    );
  }

  /**
   * GET /acp/v1/health — check server availability.
   */
  async health(): Promise<Record<string, unknown>> {
    return this._getJson('/acp/v1/health');
  }

  // ─── Internal ───────────────────────────────────────────────────────────────

  /**
   * Compute Proof-of-Possession signature (ACP-HP-1.0 channel binding).
   *
   * signed_payload = Method + "|" + Path + "|" + Challenge + "|" + base64url(SHA-256(body))
   * sig = Ed25519(sk, SHA-256(signed_payload_bytes))
   *
   * Returns base64url-encoded signature (no padding).
   */
  private _signPop(
    method: string,
    path: string,
    challenge: string,
    body: Buffer
  ): string {
    const bodyHash = createHash('sha256').update(body).digest();
    const bodyHashB64 = bodyHash.toString('base64url');
    const signedPayload = `${method}|${path}|${challenge}|${bodyHashB64}`;
    const payloadHash = createHash('sha256')
      .update(Buffer.from(signedPayload, 'utf-8'))
      .digest();
    const sigBytes = this._signer.signBytes(payloadHash);
    return sigBytes.toString('base64url');
  }

  private async _getJson(path: string): Promise<Record<string, unknown>> {
    const url = `${this._server}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this._timeoutMs);
    try {
      const resp = await fetch(url, { method: 'GET', signal: controller.signal });
      if (!resp.ok) {
        throw new ACPError(`HTTP ${resp.status}`, resp.status);
      }
      return (await resp.json()) as Record<string, unknown>;
    } catch (err) {
      if (err instanceof ACPError) throw err;
      throw new ACPError(`Connection failed: ${(err as Error).message}`);
    } finally {
      clearTimeout(timer);
    }
  }

  private async _postJson(
    path: string,
    body: Record<string, unknown>
  ): Promise<Record<string, unknown>> {
    const url = `${this._server}${path}`;
    const data = Buffer.from(JSON.stringify(body), 'utf-8');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this._timeoutMs);
    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: data,
        signal: controller.signal,
      });
      if (!resp.ok) {
        const errBody = await resp.json().catch(() => ({ error: resp.statusText })) as Record<string, unknown>;
        throw new ACPError(
          `HTTP ${resp.status}: ${String(errBody['error'] ?? resp.statusText)}`,
          resp.status
        );
      }
      return (await resp.json()) as Record<string, unknown>;
    } catch (err) {
      if (err instanceof ACPError) throw err;
      throw new ACPError(`Connection failed: ${(err as Error).message}`);
    } finally {
      clearTimeout(timer);
    }
  }

  private async _postWithAcpHeaders(
    path: string,
    body: Buffer,
    tokenJson: string,
    agentId: string,
    challenge: string,
    popSig: string
  ): Promise<Record<string, unknown>> {
    const url = `${this._server}${path}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${tokenJson}`,
      'X-ACP-Agent-ID': agentId,
      'X-ACP-Challenge': challenge,
      'X-ACP-Signature': popSig,
    };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this._timeoutMs);
    try {
      const resp = await fetch(url, {
        method: 'POST',
        headers,
        body: body.length > 0 ? body : undefined,
        signal: controller.signal,
      });
      if (!resp.ok) {
        const errBody = await resp.json().catch(() => ({ error: resp.statusText })) as Record<string, unknown>;
        throw new ACPError(
          `HTTP ${resp.status}: ${String(errBody['error'] ?? resp.statusText)}`,
          resp.status
        );
      }
      return (await resp.json()) as Record<string, unknown>;
    } catch (err) {
      if (err instanceof ACPError) throw err;
      throw new ACPError(`Connection failed: ${(err as Error).message}`);
    } finally {
      clearTimeout(timer);
    }
  }
}
