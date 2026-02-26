"""
acp.signer — ACP token signing and JCS canonicalization.
Implements ACP-SIGN-1.0: JCS (RFC 8785) → SHA-256 → Ed25519.

Used by the issuer to produce capability tokens.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, Optional

from .identity import ACPIdentity


def canonicalize(data: Dict[str, Any]) -> bytes:
    """Serialize a dict to JCS canonical form (RFC 8785).

    JCS rules:
    - Keys sorted lexicographically by Unicode code point
    - No insignificant whitespace
    - UTF-8 encoding
    - Numbers as per ECMAScript JSON.stringify

    This is a pure-Python JCS implementation sufficient for ACP tokens.
    For production, consider using `jcs` PyPI package.
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sign_token(payload: Dict[str, Any], identity: ACPIdentity) -> Dict[str, Any]:
    """Sign a capability token payload using ACP-SIGN-1.0.

    1. Remove any existing 'sig' field.
    2. Canonicalize with JCS (RFC 8785).
    3. Compute SHA-256 of canonical bytes.
    4. Sign with Ed25519.
    5. Add 'sig' field as base64url without padding.

    Args:
        payload: Token dict WITHOUT 'sig' field.
        identity: Issuer's cryptographic identity.

    Returns:
        Token dict WITH 'sig' field appended.
    """
    # Ensure no stale signature.
    payload_copy = {k: v for k, v in payload.items() if k != "sig"}

    # Canonicalize and hash.
    canonical_bytes = canonicalize(payload_copy)
    sig_bytes = identity.sign(canonical_bytes)

    # Encode signature as base64url without padding.
    sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode("utf-8")

    # Return token with signature appended.
    return {**payload_copy, "sig": sig_b64}


def verify_token_signature(token: Dict[str, Any], issuer_pub_key_bytes: bytes) -> bool:
    """Verify the Ed25519 signature of a token dict.

    Args:
        token: Full token dict including 'sig' field.
        issuer_pub_key_bytes: 32-byte raw Ed25519 public key of the issuer.

    Returns:
        True if signature is valid, False otherwise.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.exceptions import InvalidSignature

    sig_b64 = token.get("sig")
    if not sig_b64:
        return False

    try:
        sig_bytes = base64.urlsafe_b64decode(sig_b64 + "==")
    except Exception:
        return False

    # Canonicalize without sig.
    payload_copy = {k: v for k, v in token.items() if k != "sig"}
    canonical_bytes = canonicalize(payload_copy)
    payload_hash = hashlib.sha256(canonical_bytes).digest()

    try:
        pub_key = Ed25519PublicKey.from_public_bytes(issuer_pub_key_bytes)
        pub_key.verify(sig_bytes, payload_hash)
        return True
    except (InvalidSignature, Exception):
        return False


def compute_token_hash(token: Dict[str, Any]) -> str:
    """Compute SHA-256(JCS(token without sig)) for use in parent_hash.

    Returns base64url-encoded hash (no padding), as specified in ACP-CT-1.0 §7.
    """
    payload_copy = {k: v for k, v in token.items() if k != "sig"}
    canonical_bytes = canonicalize(payload_copy)
    hash_bytes = hashlib.sha256(canonical_bytes).digest()
    return base64.urlsafe_b64encode(hash_bytes).rstrip(b"=").decode("utf-8")
