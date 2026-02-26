"""
acp.identity — ACP Agent cryptographic identity.
Implements ACP-SIGN-1.0: Ed25519 key management and AgentID derivation.

AgentID = base58(SHA-256(pk_bytes))
  where pk_bytes = 32-byte raw Ed25519 public key (Bitcoin base58 alphabet)
"""

from __future__ import annotations

import hashlib
import os
from typing import Optional

import base58  # pip: base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


class ACPIdentity:
    """Cryptographic identity of an ACP agent.

    Usage::

        # Generate a new identity
        identity = ACPIdentity.generate()
        print(identity.agent_id)  # "7Xk3mNp9..."

        # Load from existing seed (32 bytes)
        identity = ACPIdentity.from_seed(seed_bytes)

        # Sign a canonical payload (ACP-SIGN-1.0)
        sig_b64 = identity.sign(canonical_bytes)
    """

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._public_key: Ed25519PublicKey = private_key.public_key()
        self._agent_id: str = self._derive_agent_id()

    # ── Factory Methods ───────────────────────────────────────────────────────

    @classmethod
    def generate(cls) -> "ACPIdentity":
        """Generate a new Ed25519 identity using OS CSPRNG."""
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> "ACPIdentity":
        """Load identity from a 32-byte private key seed.

        Args:
            seed: 32-byte raw private key seed.

        Raises:
            ValueError: if seed is not 32 bytes.
        """
        if len(seed) != 32:
            raise ValueError(f"seed must be 32 bytes, got {len(seed)}")
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def from_seed_file(cls, path: str) -> "ACPIdentity":
        """Load identity from a file containing 32-byte raw seed.

        The file should contain exactly 32 bytes (no encoding, no headers).
        Use PEM format for production; this is convenience for testing.
        """
        with open(path, "rb") as f:
            seed = f.read()
        return cls.from_seed(seed)

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def agent_id(self) -> str:
        """AgentID string: base58(SHA-256(pk_bytes)), 43-44 characters."""
        return self._agent_id

    @property
    def public_key_bytes(self) -> bytes:
        """Raw 32-byte Ed25519 public key."""
        return self._public_key.public_bytes(
            encoding=Encoding.Raw,
            format=PublicFormat.Raw,
        )

    @property
    def private_key_seed(self) -> bytes:
        """Raw 32-byte private key seed. NEVER log or transmit."""
        return self._private_key.private_bytes(
            encoding=Encoding.Raw,
            format=PrivateFormat.Raw,
            encryption_algorithm=NoEncryption(),
        )

    # ── Cryptographic Operations ──────────────────────────────────────────────

    def sign(self, canonical_bytes: bytes) -> bytes:
        """Sign a canonical payload using ACP-SIGN-1.0:
          sig = Ed25519(sk, SHA-256(canonical_bytes))

        Args:
            canonical_bytes: JCS-canonicalized payload bytes (UTF-8).

        Returns:
            64-byte raw Ed25519 signature.
        """
        payload_hash = hashlib.sha256(canonical_bytes).digest()
        return self._private_key.sign(payload_hash)

    # ── AgentID Derivation ────────────────────────────────────────────────────

    def _derive_agent_id(self) -> str:
        """Compute AgentID = base58(SHA-256(pk_bytes)).

        Uses Bitcoin alphabet (default for the base58 library).
        Output is 43-44 characters.
        """
        sha256_hash = hashlib.sha256(self.public_key_bytes).digest()
        return base58.b58encode(sha256_hash).decode("utf-8")

    def __repr__(self) -> str:
        return f"ACPIdentity(agent_id={self._agent_id!r})"


# ── Module-level helpers ──────────────────────────────────────────────────────

def derive_agent_id(public_key_bytes: bytes) -> str:
    """Standalone AgentID derivation from raw 32-byte public key bytes.

    Useful for computing the AgentID of a third party from their public key.
    """
    if len(public_key_bytes) != 32:
        raise ValueError("public_key_bytes must be 32 bytes (raw Ed25519 public key)")
    sha256_hash = hashlib.sha256(public_key_bytes).digest()
    return base58.b58encode(sha256_hash).decode("utf-8")


def validate_agent_id(agent_id: str) -> bool:
    """Returns True if agent_id is a well-formed ACP AgentID.

    A valid AgentID is 43-44 characters in the Bitcoin base58 alphabet.
    """
    bitcoin_alphabet = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    return 43 <= len(agent_id) <= 44 and all(c in bitcoin_alphabet for c in agent_id)
