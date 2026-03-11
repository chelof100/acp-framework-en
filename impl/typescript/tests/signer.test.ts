/**
 * Tests for ACPSigner and jcsCanonicalize (ACP-SIGN-1.0)
 */
import { describe, it, expect } from 'vitest';
import { AgentIdentity } from '../src/identity';
import { ACPSigner, jcsCanonicalize } from '../src/signer';

// ─── Sample capability ───────────────────────────────────────────────────────

const SAMPLE_CAPABILITY: Record<string, unknown> = {
  ver: '1.0',
  iss: 'test-issuer-did',
  sub: 'test-subject-id',
  iat: 1700000000,
  exp: 1700003600,
  nonce: 'test-nonce-abc123',
  cap: ['acp:cap:financial.payment'],
  res: 'org.example/accounts/ACC-001',
};

// ─── jcsCanonicalize (RFC 8785) ──────────────────────────────────────────────

describe('jcsCanonicalize()', () => {
  it('returns a Buffer', () => {
    expect(jcsCanonicalize({ a: 1 })).toBeInstanceOf(Buffer);
  });

  it('sorts object keys lexicographically', () => {
    const result = jcsCanonicalize({ z: 1, a: 2, m: 3 });
    expect(result.toString()).toBe('{"a":2,"m":3,"z":1}');
  });

  it('handles nested objects with sorted keys', () => {
    const result = jcsCanonicalize({ z: { b: 1, a: 2 }, a: 'x' });
    // top-level: a < z; inner: a < b (values stay as-is)
    expect(result.toString()).toBe('{"a":"x","z":{"a":2,"b":1}}');
  });

  it('handles arrays (preserves order)', () => {
    const result = jcsCanonicalize({ caps: ['b', 'a', 'c'] });
    expect(result.toString()).toBe('{"caps":["b","a","c"]}');
  });

  it('handles null values', () => {
    expect(jcsCanonicalize({ parent_hash: null }).toString()).toBe(
      '{"parent_hash":null}'
    );
  });

  it('handles booleans', () => {
    expect(
      jcsCanonicalize({ allowed: true, delegated: false }).toString()
    ).toBe('{"allowed":true,"delegated":false}');
  });

  it('handles numbers (integer and float)', () => {
    expect(jcsCanonicalize({ n: 42, f: 3.14 }).toString()).toBe(
      '{"f":3.14,"n":42}'
    );
  });

  it('handles strings with special characters', () => {
    const result = jcsCanonicalize({ key: 'hello "world"' });
    expect(result.toString()).toBe('{"key":"hello \\"world\\""}');
  });

  it('is deterministic across calls', () => {
    const a = jcsCanonicalize(SAMPLE_CAPABILITY);
    const b = jcsCanonicalize(SAMPLE_CAPABILITY);
    expect(a).toEqual(b);
  });

  it('empty object serializes to {}', () => {
    expect(jcsCanonicalize({}).toString()).toBe('{}');
  });

  it('empty array serializes to []', () => {
    expect(jcsCanonicalize([]).toString()).toBe('[]');
  });
});

// ─── ACPSigner.signCapability() ──────────────────────────────────────────────

describe('ACPSigner.signCapability()', () => {
  it('adds a "sig" field to the returned object', () => {
    const agent = AgentIdentity.generate();
    const signer = new ACPSigner(agent);
    const signed = signer.signCapability(SAMPLE_CAPABILITY);
    expect(signed['sig']).toBeTruthy();
    expect(typeof signed['sig']).toBe('string');
  });

  it('does NOT mutate the input capability', () => {
    const agent = AgentIdentity.generate();
    const signer = new ACPSigner(agent);
    const input = { ...SAMPLE_CAPABILITY };
    signer.signCapability(input);
    expect(input).not.toHaveProperty('sig');
  });

  it('"sig" is base64url (no padding, no +/=)', () => {
    const agent = AgentIdentity.generate();
    const signer = new ACPSigner(agent);
    const signed = signer.signCapability(SAMPLE_CAPABILITY);
    expect(signed['sig']).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(signed['sig'] as string).not.toContain('=');
  });

  it('"sig" encodes 64 bytes (length 86-88 chars in base64url)', () => {
    const agent = AgentIdentity.generate();
    const signer = new ACPSigner(agent);
    const signed = signer.signCapability(SAMPLE_CAPABILITY);
    const sigLen = (signed['sig'] as string).length;
    // 64 bytes base64url = 86 chars (64 * 4/3, no padding)
    expect(sigLen).toBeGreaterThanOrEqual(85);
    expect(sigLen).toBeLessThanOrEqual(88);
  });

  it('strips existing "sig" before re-signing', () => {
    const agent = AgentIdentity.generate();
    const signer = new ACPSigner(agent);
    const withOldSig = { ...SAMPLE_CAPABILITY, sig: 'invalid-old-sig' };
    const signed = signer.signCapability(withOldSig);
    // New sig should verify correctly
    expect(ACPSigner.verifyCapability(signed, agent.publicKeyBytes)).toBe(true);
  });

  it('different nonces produce different signatures', () => {
    const agent = AgentIdentity.generate();
    const signer = new ACPSigner(agent);
    const s1 = signer.signCapability({ ...SAMPLE_CAPABILITY, nonce: 'nonce-1' });
    const s2 = signer.signCapability({ ...SAMPLE_CAPABILITY, nonce: 'nonce-2' });
    expect(s1['sig']).not.toBe(s2['sig']);
  });

  it('same capability produces same signature (deterministic)', () => {
    const agent = AgentIdentity.generate();
    const signer = new ACPSigner(agent);
    const s1 = signer.signCapability(SAMPLE_CAPABILITY);
    const s2 = signer.signCapability(SAMPLE_CAPABILITY);
    expect(s1['sig']).toBe(s2['sig']);
  });
});

// ─── ACPSigner.verifyCapability() ────────────────────────────────────────────

describe('ACPSigner.verifyCapability()', () => {
  it('returns true for a freshly signed capability', () => {
    const agent = AgentIdentity.generate();
    const signer = new ACPSigner(agent);
    const signed = signer.signCapability(SAMPLE_CAPABILITY);
    expect(ACPSigner.verifyCapability(signed, agent.publicKeyBytes)).toBe(true);
  });

  it('returns false if "sig" field is missing', () => {
    const agent = AgentIdentity.generate();
    expect(ACPSigner.verifyCapability(SAMPLE_CAPABILITY, agent.publicKeyBytes)).toBe(false);
  });

  it('returns false if "sig" field is empty string', () => {
    const agent = AgentIdentity.generate();
    const badCap = { ...SAMPLE_CAPABILITY, sig: '' };
    expect(ACPSigner.verifyCapability(badCap, agent.publicKeyBytes)).toBe(false);
  });

  it('returns false if sig is tampered (wrong base64url)', () => {
    const agent = AgentIdentity.generate();
    const signer = new ACPSigner(agent);
    const signed = { ...signer.signCapability(SAMPLE_CAPABILITY) };
    // Replace sig with all-A (still 88 chars but wrong value)
    signed['sig'] = 'A'.repeat(88);
    expect(ACPSigner.verifyCapability(signed, agent.publicKeyBytes)).toBe(false);
  });

  it('returns false when verifying with a different public key', () => {
    const agent = AgentIdentity.generate();
    const other = AgentIdentity.generate();
    const signer = new ACPSigner(agent);
    const signed = signer.signCapability(SAMPLE_CAPABILITY);
    expect(ACPSigner.verifyCapability(signed, other.publicKeyBytes)).toBe(false);
  });

  it('returns false if any capability field is modified after signing', () => {
    const agent = AgentIdentity.generate();
    const signer = new ACPSigner(agent);
    const signed = { ...signer.signCapability(SAMPLE_CAPABILITY) };
    signed['res'] = 'org.attacker/accounts/EVIL'; // tamper
    expect(ACPSigner.verifyCapability(signed, agent.publicKeyBytes)).toBe(false);
  });
});

// ─── ACPSigner.signBytes() ───────────────────────────────────────────────────

describe('ACPSigner.signBytes()', () => {
  it('returns a 64-byte Buffer', () => {
    const agent = AgentIdentity.generate();
    const signer = new ACPSigner(agent);
    const sig = signer.signBytes(Buffer.from('pop challenge data'));
    expect(sig).toBeInstanceOf(Buffer);
    expect(sig.length).toBe(64);
  });

  it('is verifiable by AgentIdentity.verify()', () => {
    const agent = AgentIdentity.generate();
    const signer = new ACPSigner(agent);
    const data = Buffer.from('pop challenge data');
    const sig = signer.signBytes(data);
    expect(agent.verify(sig, data)).toBe(true);
  });
});

// ─── ACPSigner.canonicalize() ────────────────────────────────────────────────

describe('ACPSigner.canonicalize()', () => {
  it('is equivalent to jcsCanonicalize()', () => {
    const obj = { b: 2, a: 1 };
    expect(ACPSigner.canonicalize(obj)).toEqual(jcsCanonicalize(obj));
  });

  it('returns Buffer with sorted keys', () => {
    const result = ACPSigner.canonicalize({ b: 2, a: 1 });
    expect(result.toString()).toBe('{"a":1,"b":2}');
  });
});
