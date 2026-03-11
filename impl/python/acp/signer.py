"""
acp.signer — JCS canonicalization + Ed25519 signing pipeline (ACP-SIGN-1.0)

ACP signing pipeline:
  1. Canonicalize the capability object using JCS (RFC 8785)
  2. Compute SHA-256 of the canonical bytes
  3. Sign the digest with Ed25519
  4. Embed the signature as base64url in the capability's flat "sig" field (ACP-CT-1.0)

Usage:
    from acp.identity import AgentIdentity
    from acp.signer import ACPSigner

    agent = AgentIdentity.generate()
    signer = ACPSigner(agent)

    capability = {
        "ver": "1.0",
        "iss": agent.did,
        "sub": agent.agent_id,
        "iat": 1700000000,
        "exp": 1700003600,
        "nonce": "random-nonce",
        "cap": ["acp:cap:financial.payment"],
        "resource": "org.example/accounts/ACC-001",
    }

    signed = signer.sign_capability(capability)
    # signed["sig"] contains the base64url Ed25519 signature (flat field)

    # Verify
    is_valid = ACPSigner.verify_capability(signed, agent.public_key_bytes)
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
from typing import Any, Dict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .identity import AgentIdentity


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _base64url_decode(s: str) -> bytes:
    padding = "=" * (4 - len(s) % 4) if len(s) % 4 else ""
    return base64.urlsafe_b64decode(s + padding)


def _jcs_canonicalize(obj: Any) -> bytes:
    """
    JSON Canonicalization Scheme (RFC 8785).

    Produces deterministic UTF-8 bytes:
    - Object keys sorted lexicographically
    - No whitespace
    - Unicode escapes for control characters
    """
    if obj is None:
        return b"null"
    if isinstance(obj, bool):
        return b"true" if obj else b"false"
    if isinstance(obj, int):
        return str(obj).encode()
    if isinstance(obj, float):
        # Use JSON representation (no trailing zeros)
        return json.dumps(obj, separators=(",", ":")).encode()
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()
    if isinstance(obj, (list, tuple)):
        items = b",".join(_jcs_canonicalize(v) for v in obj)
        return b"[" + items + b"]"
    if isinstance(obj, dict):
        # Sort keys lexicographically by their Unicode code points
        sorted_pairs = sorted(obj.items(), key=lambda kv: kv[0])
        items = b",".join(
            _jcs_canonicalize(k) + b":" + _jcs_canonicalize(v)
            for k, v in sorted_pairs
        )
        return b"{" + items + b"}"
    raise TypeError(f"Not JSON-serializable: {type(obj)}")


class ACPSigner:
    """
    ACP signing and verification pipeline (ACP-SIGN-1.0).

    Pipeline: JCS(capability) → SHA-256 → Ed25519.sign → base64url
    """

    def __init__(self, identity: AgentIdentity) -> None:
        self._identity = identity

    # ─── Signing ──────────────────────────────────────────────────────────────

    def sign_capability(self, capability: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sign a capability object and embed the signature in capability["sig"].

        The capability dict is NOT modified in-place. A copy is returned with
        the "sig" field added/replaced (flat field per ACP-CT-1.0).

        The signing input is the canonical JCS bytes of the capability WITHOUT
        the "sig" field (so the signature is not included in what's signed).
        """
        # Strip existing signature before signing
        cap_to_sign = {k: v for k, v in capability.items() if k != "sig"}

        canonical = _jcs_canonicalize(cap_to_sign)
        digest = hashlib.sha256(canonical).digest()
        signature_bytes = self._identity.sign(digest)
        signature_b64 = _base64url_encode(signature_bytes)

        signed = copy.deepcopy(capability)
        signed["sig"] = signature_b64
        return signed

    def sign_bytes(self, data: bytes) -> bytes:
        """Sign arbitrary bytes directly (for PoP challenges)."""
        return self._identity.sign(data)

    # ─── Verification ─────────────────────────────────────────────────────────

    @staticmethod
    def verify_capability(
        capability: Dict[str, Any],
        public_key_bytes: bytes,
    ) -> bool:
        """
        Verify a signed capability against a 32-byte Ed25519 public key.

        Returns True if the signature is valid, False otherwise.
        Expects the signature in the flat "sig" field (ACP-CT-1.0).
        """
        sig_b64 = capability.get("sig")
        if not sig_b64:
            return False

        # Reconstruct signing input (capability without "sig")
        cap_to_verify = {k: v for k, v in capability.items() if k != "sig"}

        try:
            canonical = _jcs_canonicalize(cap_to_verify)
            digest = hashlib.sha256(canonical).digest()
            signature_bytes = _base64url_decode(sig_b64)

            pub_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            pub_key.verify(signature_bytes, digest)
            return True
        except Exception:
            return False

    @staticmethod
    def canonicalize(obj: Any) -> bytes:
        """Expose JCS canonicalization for external use."""
        return _jcs_canonicalize(obj)
