#!/usr/bin/env python3
"""Compute ACP AgentID from a seed (hex) and print it to stdout.

Usage:
    python3 compute_agent_id.py <seed_hex_32_bytes>
"""
import hashlib
import sys

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    result = []
    while n:
        n, remainder = divmod(n, 58)
        result.append(ALPHABET[remainder])
    for byte in data:
        if byte == 0:
            result.append(ALPHABET[0])
        else:
            break
    return "".join(reversed(result))


def main():
    if len(sys.argv) != 2:
        print("usage: compute_agent_id.py <seed_hex>", file=sys.stderr)
        sys.exit(1)
    seed = bytes.fromhex(sys.argv[1])
    if len(seed) != 32:
        print("seed must be 32 bytes", file=sys.stderr)
        sys.exit(1)

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        pk = Ed25519PrivateKey.from_private_bytes(seed)
        pub_raw = pk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    except ImportError:
        # Fallback: derive pubkey via standard crypto — not available without dependency.
        print("cryptography library not available", file=sys.stderr)
        sys.exit(2)

    digest = hashlib.sha256(pub_raw).digest()
    print(base58_encode(digest))


if __name__ == "__main__":
    main()
