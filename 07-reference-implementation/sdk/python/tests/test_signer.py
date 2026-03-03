"""
Tests for acp.signer — JCS canonicalization, capability signing, PoP binding.

Spec references:
  - RFC 8785: JSON Canonicalization Scheme (JCS)
  - ACP-CT-1.0: Capability token format, flat "sig" field
  - ACP-SIGN-1.0: SHA-256(JCS(cap)) → Ed25519
  - ACP-HP-1.0: PoP binding = Method|Path|Challenge|base64url(SHA-256(body))
"""
import base64
import hashlib
import pytest
from acp.identity import AgentIdentity
from acp.signer import ACPSigner, _jcs_canonicalize

TEST_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55"
)


class TestJCS:
    """JSON Canonicalization Scheme (RFC 8785) compliance tests."""

    def test_null(self):
        assert _jcs_canonicalize(None) == b"null"

    def test_bool_true(self):
        assert _jcs_canonicalize(True) == b"true"

    def test_bool_false(self):
        assert _jcs_canonicalize(False) == b"false"

    def test_integer_positive(self):
        assert _jcs_canonicalize(42) == b"42"

    def test_integer_zero(self):
        assert _jcs_canonicalize(0) == b"0"

    def test_integer_negative(self):
        assert _jcs_canonicalize(-1) == b"-1"

    def test_string_simple(self):
        assert _jcs_canonicalize("hello") == b'"hello"'

    def test_string_with_slash(self):
        assert _jcs_canonicalize("a/b") == b'"a/b"'

    def test_empty_string(self):
        assert _jcs_canonicalize("") == b'""'

    def test_empty_array(self):
        assert _jcs_canonicalize([]) == b"[]"

    def test_array_of_ints(self):
        assert _jcs_canonicalize([1, 2, 3]) == b"[1,2,3]"

    def test_array_of_strings(self):
        assert _jcs_canonicalize(["b", "a"]) == b'["b","a"]'

    def test_empty_dict(self):
        assert _jcs_canonicalize({}) == b"{}"

    def test_dict_keys_sorted_lexicographically(self):
        """RFC 8785 §3.2.3: object properties sorted by Unicode code points."""
        obj = {"z": 1, "a": 2, "m": 3}
        assert _jcs_canonicalize(obj) == b'{"a":2,"m":3,"z":1}'

    def test_nested_dict_keys_sorted(self):
        obj = {"b": {"d": 4, "c": 3}, "a": 1}
        assert _jcs_canonicalize(obj) == b'{"a":1,"b":{"c":3,"d":4}}'

    def test_array_in_dict(self):
        obj = {"caps": ["pay", "read"], "ver": "1.0"}
        result = _jcs_canonicalize(obj)
        assert result == b'{"caps":["pay","read"],"ver":"1.0"}'

    def test_deterministic_repeated_calls(self):
        obj = {"cap": ["acp:cap:pay"], "iss": "did:key:z...", "ver": "1.0"}
        r1 = _jcs_canonicalize(obj)
        r2 = _jcs_canonicalize(obj)
        assert r1 == r2

    def test_unsupported_type_raises(self):
        with pytest.raises(TypeError):
            _jcs_canonicalize(object())


class TestSignCapability:
    def test_sign_adds_sig_field(self, test_signer, sample_capability):
        signed = test_signer.sign_capability(sample_capability)
        assert "sig" in signed

    def test_sign_does_not_mutate_input(self, test_signer, sample_capability):
        original_keys = set(sample_capability.keys())
        test_signer.sign_capability(sample_capability)
        assert set(sample_capability.keys()) == original_keys
        assert "sig" not in sample_capability

    def test_sig_is_base64url_no_padding(self, test_signer, sample_capability):
        signed = test_signer.sign_capability(sample_capability)
        sig = signed["sig"]
        assert "+" not in sig
        assert "/" not in sig
        assert "=" not in sig

    def test_sig_decodes_to_64_bytes(self, test_signer, sample_capability):
        signed = test_signer.sign_capability(sample_capability)
        sig = signed["sig"]
        padding = "=" * (-len(sig) % 4)
        decoded = base64.urlsafe_b64decode(sig + padding)
        assert len(decoded) == 64

    def test_sig_is_deterministic(self, test_signer, sample_capability):
        """Ed25519 signing is deterministic: same cap → same sig."""
        s1 = test_signer.sign_capability(sample_capability)
        s2 = test_signer.sign_capability(sample_capability)
        assert s1["sig"] == s2["sig"]

    def test_sign_strips_existing_sig_before_signing(self, test_signer, sample_capability):
        """Pre-existing 'sig' must not affect the new signature."""
        cap_with_old_sig = {**sample_capability, "sig": "old-garbage-value"}
        fresh = test_signer.sign_capability(sample_capability)
        replaced = test_signer.sign_capability(cap_with_old_sig)
        assert fresh["sig"] == replaced["sig"]

    def test_sig_is_flat_not_nested(self, test_signer, sample_capability):
        """ACP-CT-1.0: sig is a flat string field, NOT nested under proof."""
        signed = test_signer.sign_capability(sample_capability)
        assert isinstance(signed["sig"], str)
        assert "proof" not in signed

    def test_other_fields_preserved(self, test_signer, sample_capability):
        signed = test_signer.sign_capability(sample_capability)
        for key, val in sample_capability.items():
            assert signed[key] == val

    def test_different_caps_produce_different_sigs(self, test_signer, sample_capability):
        cap2 = {**sample_capability, "nonce": "different-nonce"}
        s1 = test_signer.sign_capability(sample_capability)
        s2 = test_signer.sign_capability(cap2)
        assert s1["sig"] != s2["sig"]


class TestVerifyCapability:
    def test_verify_valid_signature(self, test_signer, test_identity, sample_capability):
        signed = test_signer.sign_capability(sample_capability)
        assert ACPSigner.verify_capability(signed, test_identity.public_key_bytes) is True

    def test_verify_wrong_pubkey(self, test_signer, sample_capability):
        other = AgentIdentity.generate()
        signed = test_signer.sign_capability(sample_capability)
        assert ACPSigner.verify_capability(signed, other.public_key_bytes) is False

    def test_verify_tampered_cap_field(self, test_signer, test_identity, sample_capability):
        signed = test_signer.sign_capability(sample_capability)
        signed["cap"] = ["acp:cap:admin"]  # tamper after signing
        assert ACPSigner.verify_capability(signed, test_identity.public_key_bytes) is False

    def test_verify_tampered_resource(self, test_signer, test_identity, sample_capability):
        signed = test_signer.sign_capability(sample_capability)
        signed["resource"] = "org.attacker/accounts/ACC-999"
        assert ACPSigner.verify_capability(signed, test_identity.public_key_bytes) is False

    def test_verify_missing_sig_field(self, test_identity, sample_capability):
        assert ACPSigner.verify_capability(sample_capability, test_identity.public_key_bytes) is False

    def test_verify_corrupted_sig(self, test_signer, test_identity, sample_capability):
        signed = test_signer.sign_capability(sample_capability)
        signed["sig"] = "A" * 86  # 64 bytes in base64url = 86 chars, but wrong value
        assert ACPSigner.verify_capability(signed, test_identity.public_key_bytes) is False

    def test_verify_empty_sig(self, test_signer, test_identity, sample_capability):
        signed = test_signer.sign_capability(sample_capability)
        signed["sig"] = ""
        assert ACPSigner.verify_capability(signed, test_identity.public_key_bytes) is False

    def test_canonicalize_exposed(self):
        """ACPSigner.canonicalize() is a public helper."""
        obj = {"b": 2, "a": 1}
        result = ACPSigner.canonicalize(obj)
        assert result == b'{"a":1,"b":2}'


class TestPoPBinding:
    """
    ACP-HP-1.0 channel binding:
    signed_payload = Method + "|" + Path + "|" + Challenge + "|" + base64url(SHA-256(body))
    sig = Ed25519(SHA-256(signed_payload))
    """

    def test_empty_body_sha256_is_known_value(self):
        """SHA-256("") is a well-known constant."""
        empty_hash = hashlib.sha256(b"").digest()
        b64 = base64.urlsafe_b64encode(empty_hash).rstrip(b"=").decode()
        # Known SHA-256 of empty string
        assert b64 == "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"

    def test_pop_payload_format(self, test_identity):
        """Verify PoP signed payload matches ACP-HP-1.0 §3.2 format."""
        method = "POST"
        path = "/acp/v1/verify"
        challenge = "abc123"
        body = b""

        body_hash = hashlib.sha256(body).digest()
        body_b64 = base64.urlsafe_b64encode(body_hash).rstrip(b"=").decode()
        payload = f"{method}|{path}|{challenge}|{body_b64}"

        # Verify signing pipeline works
        payload_hash = hashlib.sha256(payload.encode("utf-8")).digest()
        sig = test_identity.sign(payload_hash)
        assert len(sig) == 64
        assert test_identity.verify(sig, payload_hash)

    def test_pop_signature_changes_with_different_challenge(self, test_identity):
        """Each challenge must produce a unique PoP signature."""
        def make_pop(challenge: str) -> bytes:
            body_hash = hashlib.sha256(b"").digest()
            body_b64 = base64.urlsafe_b64encode(body_hash).rstrip(b"=").decode()
            payload = f"POST|/acp/v1/verify|{challenge}|{body_b64}"
            return test_identity.sign(hashlib.sha256(payload.encode()).digest())

        sig1 = make_pop("challenge-aaa")
        sig2 = make_pop("challenge-bbb")
        assert sig1 != sig2
