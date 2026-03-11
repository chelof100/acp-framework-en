/**
 * Tests for AgentIdentity (ACP-SIGN-1.0)
 */
import { describe, it, expect } from 'vitest';
import { AgentIdentity, deriveAgentId } from '../src/identity';

const BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]+$/;

describe('AgentIdentity.generate()', () => {
  it('generates unique identities', () => {
    const a = AgentIdentity.generate();
    const b = AgentIdentity.generate();
    expect(a.agentId).not.toBe(b.agentId);
    expect(a.publicKeyBytes).not.toEqual(b.publicKeyBytes);
  });

  it('publicKeyBytes is 32 bytes', () => {
    const agent = AgentIdentity.generate();
    expect(agent.publicKeyBytes.length).toBe(32);
    expect(agent.publicKeyBytes).toBeInstanceOf(Buffer);
  });

  it('privateKeyBytes is 32 bytes', () => {
    const agent = AgentIdentity.generate();
    expect(agent.privateKeyBytes.length).toBe(32);
    expect(agent.privateKeyBytes).toBeInstanceOf(Buffer);
  });

  it('agentId is a valid base58 string (43-44 chars)', () => {
    const agent = AgentIdentity.generate();
    expect(agent.agentId).toMatch(BASE58_RE);
    // SHA-256 is 32 bytes → base58 of 32 bytes is 43-44 chars
    expect(agent.agentId.length).toBeGreaterThanOrEqual(43);
    expect(agent.agentId.length).toBeLessThanOrEqual(44);
  });

  it('did starts with did:key:z and contains base58', () => {
    const agent = AgentIdentity.generate();
    expect(agent.did).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
  });
});

describe('AgentIdentity.fromPrivateBytes()', () => {
  it('round-trips: restores same agentId, did, publicKeyBytes', () => {
    const original = AgentIdentity.generate();
    const restored = AgentIdentity.fromPrivateBytes(original.privateKeyBytes);
    expect(restored.agentId).toBe(original.agentId);
    expect(restored.did).toBe(original.did);
    expect(restored.publicKeyBytes).toEqual(original.publicKeyBytes);
  });

  it('throws on wrong length (< 32 bytes)', () => {
    expect(() =>
      AgentIdentity.fromPrivateBytes(Buffer.from('tooshort'))
    ).toThrow(/32 bytes/);
  });

  it('throws on wrong length (> 32 bytes)', () => {
    expect(() =>
      AgentIdentity.fromPrivateBytes(Buffer.alloc(64))
    ).toThrow(/32 bytes/);
  });
});

describe('AgentIdentity.sign() / verify()', () => {
  it('sign() produces a 64-byte Buffer', () => {
    const agent = AgentIdentity.generate();
    const sig = agent.sign(Buffer.from('hello ACP'));
    expect(sig).toBeInstanceOf(Buffer);
    expect(sig.length).toBe(64);
  });

  it('verify() returns true for valid signature', () => {
    const agent = AgentIdentity.generate();
    const msg = Buffer.from('test message');
    const sig = agent.sign(msg);
    expect(agent.verify(sig, msg)).toBe(true);
  });

  it('verify() returns false for different message', () => {
    const agent = AgentIdentity.generate();
    const sig = agent.sign(Buffer.from('original'));
    expect(agent.verify(sig, Buffer.from('tampered'))).toBe(false);
  });

  it('verify() returns false for bit-flipped signature', () => {
    const agent = AgentIdentity.generate();
    const msg = Buffer.from('test message');
    const sig = agent.sign(msg);
    const tampered = Buffer.from(sig);
    tampered[0] ^= 0xff;
    expect(agent.verify(tampered, msg)).toBe(false);
  });

  it('verify() returns false with wrong identity', () => {
    const a = AgentIdentity.generate();
    const b = AgentIdentity.generate();
    const msg = Buffer.from('test');
    const sig = a.sign(msg);
    expect(b.verify(sig, msg)).toBe(false);
  });

  it('different messages produce different signatures', () => {
    const agent = AgentIdentity.generate();
    const sig1 = agent.sign(Buffer.from('message-1'));
    const sig2 = agent.sign(Buffer.from('message-2'));
    expect(sig1).not.toEqual(sig2);
  });
});

describe('deriveAgentId()', () => {
  it('matches agent.agentId', () => {
    const agent = AgentIdentity.generate();
    expect(deriveAgentId(agent.publicKeyBytes)).toBe(agent.agentId);
  });

  it('is deterministic', () => {
    const agent = AgentIdentity.generate();
    expect(deriveAgentId(agent.publicKeyBytes)).toBe(
      deriveAgentId(agent.publicKeyBytes)
    );
  });

  it('differs for different keys', () => {
    const a = AgentIdentity.generate();
    const b = AgentIdentity.generate();
    expect(deriveAgentId(a.publicKeyBytes)).not.toBe(
      deriveAgentId(b.publicKeyBytes)
    );
  });
});
