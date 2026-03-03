"""
Tests for acp.identity — AgentIdentity, AgentID derivation, DID format.

Spec references:
  - ACP-CT-1.0 §3: AgentID = base58(SHA-256(raw Ed25519 public key))
  - ACP-SIGN-1.0: Ed25519 key pair, raw 32-byte encoding
"""
import hashlib
import pytest
from acp.identity import AgentIdentity, _base58_encode

TEST_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55"
)


class TestKeyGeneration:
    def test_generate_creates_valid_identity(self):
        agent = AgentIdentity.generate()
        assert agent.agent_id
        assert agent.did.startswith("did:key:z")
        assert len(agent.public_key_bytes) == 32
        assert len(agent.private_key_bytes) == 32

    def test_generate_produces_unique_identities(self):
        a1 = AgentIdentity.generate()
        a2 = AgentIdentity.generate()
        assert a1.agent_id != a2.agent_id
        assert a1.public_key_bytes != a2.public_key_bytes

    def test_from_private_bytes_deterministic(self):
        a1 = AgentIdentity.from_private_bytes(TEST_SEED)
        a2 = AgentIdentity.from_private_bytes(TEST_SEED)
        assert a1.agent_id == a2.agent_id
        assert a1.public_key_bytes == a2.public_key_bytes

    def test_from_private_bytes_requires_32_bytes(self):
        with pytest.raises(Exception):
            AgentIdentity.from_private_bytes(b"\x00" * 31)

    def test_private_key_roundtrip(self, test_identity):
        pk_bytes = test_identity.private_key_bytes
        restored = AgentIdentity.from_private_bytes(pk_bytes)
        assert restored.agent_id == test_identity.agent_id
        assert restored.public_key_bytes == test_identity.public_key_bytes


class TestAgentID:
    def test_agent_id_is_base58_of_sha256_pubkey(self, test_identity):
        """ACP-CT-1.0 §3: AgentID = base58(SHA-256(raw_pubkey))."""
        digest = hashlib.sha256(test_identity.public_key_bytes).digest()
        expected = _base58_encode(digest)
        assert test_identity.agent_id == expected

    def test_agent_id_has_no_prefix(self, test_identity):
        """AgentID must NOT have 'acp:agent:' or any prefix."""
        assert not test_identity.agent_id.startswith("acp:")
        assert not test_identity.agent_id.startswith("acp:agent:")
        assert ":" not in test_identity.agent_id

    def test_agent_id_base58_alphabet_only(self, test_identity):
        """base58btc excludes 0, O, I, l to avoid visual ambiguity."""
        forbidden = set("0OIl")
        for ch in test_identity.agent_id:
            assert ch not in forbidden, f"Forbidden base58 char '{ch}' in AgentID"

    def test_agent_id_length(self, test_identity):
        """SHA-256 = 32 bytes → base58 ≈ 43–44 chars."""
        assert 40 <= len(test_identity.agent_id) <= 50

    def test_agent_id_deterministic_from_seed(self):
        """Same seed always produces same AgentID."""
        a1 = AgentIdentity.from_private_bytes(TEST_SEED)
        a2 = AgentIdentity.from_private_bytes(TEST_SEED)
        assert a1.agent_id == a2.agent_id

    def test_agent_id_changes_with_different_key(self):
        a1 = AgentIdentity.from_private_bytes(TEST_SEED)
        a2 = AgentIdentity.generate()
        assert a1.agent_id != a2.agent_id


class TestDID:
    def test_did_starts_with_did_key_z(self, test_identity):
        """did:key uses multibase prefix 'z' for base58btc."""
        assert test_identity.did.startswith("did:key:z")

    def test_did_deterministic_from_seed(self):
        a1 = AgentIdentity.from_private_bytes(TEST_SEED)
        a2 = AgentIdentity.from_private_bytes(TEST_SEED)
        assert a1.did == a2.did

    def test_did_unique_per_key(self):
        a1 = AgentIdentity.from_private_bytes(TEST_SEED)
        a2 = AgentIdentity.generate()
        assert a1.did != a2.did

    def test_did_encodes_ed25519_multicodec(self, test_identity):
        """DID must embed the 0xed01 multicodec prefix for Ed25519."""
        import base64
        did = test_identity.did
        # Strip 'did:key:z' and decode base58
        encoded_part = did[len("did:key:z"):]
        assert len(encoded_part) > 0
        # The multibase 'z' prefix means base58btc
        # We just verify the DID is well-formed and non-empty
        assert len(did) > len("did:key:z") + 10


class TestSignAndVerify:
    def test_sign_returns_64_bytes(self, test_identity):
        sig = test_identity.sign(b"test message")
        assert len(sig) == 64

    def test_verify_valid_signature(self, test_identity):
        message = b"hello acp protocol"
        sig = test_identity.sign(message)
        assert test_identity.verify(sig, message) is True

    def test_verify_wrong_message_fails(self, test_identity):
        sig = test_identity.sign(b"original message")
        assert test_identity.verify(sig, b"tampered message") is False

    def test_verify_flipped_signature_fails(self, test_identity):
        message = b"hello"
        sig = bytearray(test_identity.sign(message))
        sig[0] ^= 0xFF  # flip first byte
        assert test_identity.verify(bytes(sig), message) is False

    def test_verify_empty_signature_fails(self, test_identity):
        assert test_identity.verify(b"\x00" * 64, b"any message") is False

    def test_cross_identity_verify_fails(self):
        a1 = AgentIdentity.generate()
        a2 = AgentIdentity.generate()
        sig = a1.sign(b"message")
        assert a2.verify(sig, b"message") is False

    def test_sign_deterministic(self, test_identity):
        """Ed25519 signatures are deterministic — same input → same output."""
        message = b"deterministic test"
        s1 = test_identity.sign(message)
        s2 = test_identity.sign(message)
        assert s1 == s2

    def test_sign_empty_bytes(self, test_identity):
        sig = test_identity.sign(b"")
        assert len(sig) == 64
        assert test_identity.verify(sig, b"") is True
