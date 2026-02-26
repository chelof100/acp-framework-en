"""
ACP Python SDK — Agent Control Protocol
Version: 1.0.0
Spec: ACP-CT-1.0, ACP-SIGN-1.0, ACP-HP-1.0

Usage:
    from acp import ACPIdentity, ACPClient, sign_token, verify_token_signature
"""

from .identity import ACPIdentity, derive_agent_id, validate_agent_id
from .signer import sign_token, verify_token_signature, compute_token_hash, canonicalize
from .client import ACPClient, ACPHandshakeError

__version__ = "1.0.0"
__all__ = [
    "ACPIdentity",
    "ACPClient",
    "ACPHandshakeError",
    "derive_agent_id",
    "validate_agent_id",
    "sign_token",
    "verify_token_signature",
    "compute_token_hash",
    "canonicalize",
]
