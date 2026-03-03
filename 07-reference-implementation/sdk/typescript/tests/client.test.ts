/**
 * Tests for ACPClient (ACP-HP-1.0)
 *
 * Uses vi.stubGlobal to mock the global fetch without any external http libraries.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { AgentIdentity } from '../src/identity';
import { ACPSigner } from '../src/signer';
import { ACPClient, ACPError } from '../src/client';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function makeFetchOk(json: unknown) {
  return vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    statusText: 'OK',
    json: () => Promise.resolve(json),
  });
}

function makeFetchError(status: number, error: string) {
  return vi.fn().mockResolvedValue({
    ok: false,
    status,
    statusText: error,
    json: () => Promise.resolve({ error }),
  });
}

const SAMPLE_TOKEN: Record<string, unknown> = {
  ver: '1.0',
  iss: 'test-issuer',
  sub: 'test-sub',
  iat: 1700000000,
  exp: 1700003600,
  sig: 'fake-sig-for-client-tests',
};

// ─── Fixtures ────────────────────────────────────────────────────────────────

let agent: AgentIdentity;
let signer: ACPSigner;
let client: ACPClient;

beforeEach(() => {
  agent = AgentIdentity.generate();
  signer = new ACPSigner(agent);
  client = new ACPClient('http://localhost:8080', agent, signer);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

// ─── register() ──────────────────────────────────────────────────────────────

describe('ACPClient.register()', () => {
  it('sends POST to /acp/v1/register', async () => {
    const fetchMock = makeFetchOk({ registered: true });
    vi.stubGlobal('fetch', fetchMock);

    await client.register();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('http://localhost:8080/acp/v1/register');
  });

  it('uses POST method', async () => {
    const fetchMock = makeFetchOk({ registered: true });
    vi.stubGlobal('fetch', fetchMock);

    await client.register();

    const [, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(opts.method).toBe('POST');
  });

  it('sends agent_id in body', async () => {
    const fetchMock = makeFetchOk({ registered: true });
    vi.stubGlobal('fetch', fetchMock);

    await client.register();

    const [, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse((opts.body as Buffer).toString()) as Record<string, unknown>;
    expect(body['agent_id']).toBe(agent.agentId);
  });

  it('sends public_key_hex (base64url) in body', async () => {
    const fetchMock = makeFetchOk({ registered: true });
    vi.stubGlobal('fetch', fetchMock);

    await client.register();

    const [, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
    const body = JSON.parse((opts.body as Buffer).toString()) as Record<string, unknown>;
    // Should be base64url of 32-byte public key
    expect(typeof body['public_key_hex']).toBe('string');
    expect(body['public_key_hex'] as string).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('returns the server response', async () => {
    const fetchMock = makeFetchOk({ registered: true, agent_id: agent.agentId });
    vi.stubGlobal('fetch', fetchMock);

    const result = await client.register();
    expect(result['registered']).toBe(true);
  });

  it('throws ACPError on HTTP 409 (duplicate)', async () => {
    vi.stubGlobal('fetch', makeFetchError(409, 'agent already registered'));
    await expect(client.register()).rejects.toBeInstanceOf(ACPError);
  });
});

// ─── verify() ────────────────────────────────────────────────────────────────

describe('ACPClient.verify()', () => {
  const CHALLENGE = 'test-challenge-xyz-128bits';

  function makeVerifyMocks() {
    let callCount = 0;
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      callCount++;
      if ((url as string).includes('/acp/v1/challenge')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ challenge: CHALLENGE }),
        });
      }
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ ok: true, capabilities: [] }),
      });
    });
    return fetchMock;
  }

  it('makes exactly 2 HTTP calls (challenge + verify)', async () => {
    const fetchMock = makeVerifyMocks();
    vi.stubGlobal('fetch', fetchMock);

    await client.verify(SAMPLE_TOKEN);

    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('first call is GET /acp/v1/challenge', async () => {
    const fetchMock = makeVerifyMocks();
    vi.stubGlobal('fetch', fetchMock);

    await client.verify(SAMPLE_TOKEN);

    const [challengeUrl, challengeOpts] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(challengeUrl).toContain('/acp/v1/challenge');
    expect(challengeOpts.method).toBe('GET');
  });

  it('second call is POST /acp/v1/verify', async () => {
    const fetchMock = makeVerifyMocks();
    vi.stubGlobal('fetch', fetchMock);

    await client.verify(SAMPLE_TOKEN);

    const [verifyUrl, verifyOpts] = fetchMock.mock.calls[1] as [string, RequestInit];
    expect(verifyUrl).toContain('/acp/v1/verify');
    expect(verifyOpts.method).toBe('POST');
  });

  it('sets Authorization: Bearer <token_json>', async () => {
    const fetchMock = makeVerifyMocks();
    vi.stubGlobal('fetch', fetchMock);

    await client.verify(SAMPLE_TOKEN);

    const [, opts] = fetchMock.mock.calls[1] as [string, RequestInit];
    const headers = opts.headers as Record<string, string>;
    expect(headers['Authorization']).toContain('Bearer ');
    expect(headers['Authorization']).toContain('"ver":"1.0"');
  });

  it('sets X-ACP-Agent-ID to agentId', async () => {
    const fetchMock = makeVerifyMocks();
    vi.stubGlobal('fetch', fetchMock);

    await client.verify(SAMPLE_TOKEN);

    const [, opts] = fetchMock.mock.calls[1] as [string, RequestInit];
    const headers = opts.headers as Record<string, string>;
    expect(headers['X-ACP-Agent-ID']).toBe(agent.agentId);
  });

  it('sets X-ACP-Challenge to the received challenge', async () => {
    const fetchMock = makeVerifyMocks();
    vi.stubGlobal('fetch', fetchMock);

    await client.verify(SAMPLE_TOKEN);

    const [, opts] = fetchMock.mock.calls[1] as [string, RequestInit];
    const headers = opts.headers as Record<string, string>;
    expect(headers['X-ACP-Challenge']).toBe(CHALLENGE);
  });

  it('sets X-ACP-Signature (non-empty base64url)', async () => {
    const fetchMock = makeVerifyMocks();
    vi.stubGlobal('fetch', fetchMock);

    await client.verify(SAMPLE_TOKEN);

    const [, opts] = fetchMock.mock.calls[1] as [string, RequestInit];
    const headers = opts.headers as Record<string, string>;
    expect(headers['X-ACP-Signature']).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('PoP signature changes with different challenge', async () => {
    const sigs: string[] = [];

    for (const challenge of ['challenge-1', 'challenge-2']) {
      const fetchMock = vi.fn().mockImplementation((url: string) => {
        if ((url as string).includes('/acp/v1/challenge')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            json: () => Promise.resolve({ challenge }),
          });
        }
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ ok: true }),
        });
      });
      vi.stubGlobal('fetch', fetchMock);

      await client.verify(SAMPLE_TOKEN);
      const [, opts] = fetchMock.mock.calls[1] as [string, RequestInit];
      const headers = opts.headers as Record<string, string>;
      sigs.push(headers['X-ACP-Signature']);

      vi.unstubAllGlobals();
    }

    expect(sigs[0]).not.toBe(sigs[1]);
  });

  it('throws ACPError if challenge response is missing "challenge" field', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ oops: 'no challenge here' }),
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(client.verify(SAMPLE_TOKEN)).rejects.toBeInstanceOf(ACPError);
  });

  it('throws ACPError on verify HTTP 401', async () => {
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if ((url as string).includes('/acp/v1/challenge')) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve({ challenge: CHALLENGE }),
        });
      }
      return Promise.resolve({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        json: () => Promise.resolve({ error: 'invalid token' }),
      });
    });
    vi.stubGlobal('fetch', fetchMock);

    await expect(client.verify(SAMPLE_TOKEN)).rejects.toBeInstanceOf(ACPError);
  });
});

// ─── health() ────────────────────────────────────────────────────────────────

describe('ACPClient.health()', () => {
  it('sends GET to /acp/v1/health', async () => {
    const fetchMock = makeFetchOk({ status: 'ok' });
    vi.stubGlobal('fetch', fetchMock);

    await client.health();

    const [url, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('http://localhost:8080/acp/v1/health');
    expect(opts.method).toBe('GET');
  });

  it('returns server response', async () => {
    vi.stubGlobal('fetch', makeFetchOk({ status: 'ok', version: '1.0.0' }));

    const result = await client.health();
    expect(result['status']).toBe('ok');
  });

  it('throws ACPError on HTTP 503', async () => {
    vi.stubGlobal('fetch', makeFetchError(503, 'service unavailable'));
    await expect(client.health()).rejects.toBeInstanceOf(ACPError);
  });
});

// ─── ACPError ─────────────────────────────────────────────────────────────────

describe('ACPError', () => {
  it('has name "ACPError"', () => {
    const err = new ACPError('test');
    expect(err.name).toBe('ACPError');
  });

  it('stores statusCode', () => {
    const err = new ACPError('not found', 404);
    expect(err.statusCode).toBe(404);
  });

  it('statusCode is undefined when not provided', () => {
    const err = new ACPError('connection failed');
    expect(err.statusCode).toBeUndefined();
  });

  it('is instanceof Error', () => {
    expect(new ACPError('test')).toBeInstanceOf(Error);
  });
});
