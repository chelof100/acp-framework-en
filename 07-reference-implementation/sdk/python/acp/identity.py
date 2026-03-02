"""
acp.identity — Ed25519 Agent Identity + AgentID derivation (ACP-SIGN-1.0)

An agent's cryptographic identity consists of:
  - An Ed25519 private/public key pair
  - An AgentID derived as the SHA-256 of the canonical DER public key bytes,
    encoded as base64url without padding

Usage:
    from acp.identity import AgentIdentity

    # Generate a new random identity
    agent = AgentIdentity.generate()
    print(agent.agent_id)   # "acp:agent:<base64url>"
    print(agent.did)        # "did:key:z<base58btc-encoded>"

    # Load from existing private key bytes
    agent = AgentIdentity.from_private_bytes(private_key_bytes)

    # Export private key for storage
    private_bytes = agent.private_key_bytes  # 32 raw bytes
"""
from __future__ import annotations

import base64
import hashlib
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)

# multicodec prefix for Ed25519 public key: 0xed 0x01
_ED25519_MULTICODEC = bytes([0xED, 0x01])


def _base64url(data: bytes) -> str:
    """Base64url encoding without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _base58_encode(data: bytes) -> str:
    """Base58btc encoding (Bitcoin alphabet)."""
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, "big")
    result = []
    while n:
        n, remainder = divmod(n, 58)
        result.append(alphabet[remainder])
    # Leading zeros
    for byte in data:
        if byte == 0:
            result.append(alphabet[0])
        else:
            break
    return "".join(reversed(result))


class AgentIdentity:
    """
    Ed25519 Agent Identity (ACP-SIGN-1.0).

    Attributes:
        agent_id: Canonical ACP agent identifier ("acp:agent:<base64url>")
        did:      did:key representation of the public key
        public_key_bytes: 32-byte raw Ed25519 public key
    """

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._public_key: Ed25519PublicKey = private_key.public_key()
        # Raw 32-byte public key
        self._pubkey_raw: bytes = self._public_key.public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    # ─── Constructors ──────────────────────────────────────────────────────────

    @classmethod
    def generate(cls) -> "AgentIdentity":
        """Generate a new random Ed25519 agent identity."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, data: bytes) -> "AgentIdentity":
        """Load from 32-byte raw private key."""
        return cls(Ed25519PrivateKey.from_private_bytes(data))

    # ─── Properties ───────────────────────────────────────────────────────────

    @property
    def agent_id(self) -> str:
        """ACP AgentID: sha-256 of raw public key, base64url-encoded."""
        digest = hashlib.sha256(self._pubkey_raw).digest()
        return f"acp:agent:{_base64url(digest)}"

    @property
    def did(self) -> str:
        """did:key representation (multicodec Ed25519 + base58btc)."""
        multicodec_bytes = _ED25519_MULTICODEC + self._pubkey_raw
        return f"did:key:z{_base58_encode(multicodec_bytes)}"

    @property
    def public_key_bytes(self) -> bytes:
        """Raw 32-byte Ed25519 public key."""
        return self._pubkey_raw

    @property
    def private_key_bytes(self) -> bytes:
        """Raw 32-byte Ed25519 private key (store securely!)."""
        return self._private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )

    # ─── Signing ──────────────────────────────────────────────────────────────

    def sign(self, message: bytes) -> bytes:
        """Sign arbitrary bytes. Returns 64-byte Ed25519 signature."""
        return self._private_key.sign(message)

    def verify(self, signature: bytes, message: bytes) -> bool:
        """Verify a signature. Returns True if valid, False otherwise."""
        try:
            self._public_key.verify(signature, message)
            return True
        except Exception:
            return False

    def __repr__(self) -> str:
        return f"AgentIdentity(agent_id={self.agent_id!r})"
