"""
acp.client — ACP HTTP Client for autonomous AI agents.
Implements ACP-HP-1.0: automatic challenge/PoP handshake.

Handles:
  1. Challenge acquisition (GET /acp/v1/challenge)
  2. Proof-of-Possession (PoP) signature generation with channel binding
  3. HTTP request execution with ACP security headers
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Dict, Optional

import requests

from .identity import ACPIdentity


# ACP Security Headers (ACP-HP-1.0)
HEADER_CHALLENGE = "X-ACP-Challenge"
HEADER_SIGNATURE = "X-ACP-Signature"
HEADER_AGENT_ID  = "X-ACP-Agent-ID"


class ACPClient:
    """ACP HTTP client for AI agents.

    Automatically manages the ACP Handshake Protocol (ACP-HP-1.0):
    - Requests ephemeral challenge nonces from the server
    - Generates Proof-of-Possession signatures with HTTP channel binding
    - Attaches required ACP security headers to every request

    Usage::

        identity = ACPIdentity.generate()
        client = ACPClient(identity, base_url="https://api.institution.com")

        response = client.execute(
            method="POST",
            path="/api/v1/payments/transfer",
            capability_token=token_json_str,
            payload={"to_account": "ACC-999", "amount": 500, "currency": "USD"},
        )
    """

    def __init__(self, identity: ACPIdentity, base_url: str, timeout: int = 10) -> None:
        """
        Args:
            identity: Agent's cryptographic identity (ACPIdentity).
            base_url: Base URL of the ACP-compatible server.
            timeout: HTTP request timeout in seconds.
        """
        self.identity = identity
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    # ── Public API ────────────────────────────────────────────────────────────

    def execute(
        self,
        method: str,
        path: str,
        capability_token: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        """Execute an action using a Capability Token.

        Performs the full ACP-HP-1.0 handshake transparently:
        1. Requests a challenge nonce from the server
        2. Generates a PoP signature over (method, path, challenge, body_hash)
        3. Attaches ACP security headers
        4. Sends the HTTP request

        Args:
            method: HTTP method ("GET", "POST", "PUT", etc.)
            path: API path starting with "/" (e.g., "/api/v1/payments/transfer")
            capability_token: Raw JSON capability token string (ACP-CT-1.0)
            payload: Optional request body dict (will be JSON-serialized)

        Returns:
            requests.Response from the server.

        Raises:
            requests.HTTPError: if the challenge request fails.
            ACPHandshakeError: if the PoP generation fails.
        """
        method = method.upper()
        if not path.startswith("/"):
            path = "/" + path

        # 1. Request ephemeral challenge.
        challenge = self._request_challenge()

        # 2. Serialize body deterministically (consistent hash).
        body_bytes = b""
        if payload is not None:
            body_bytes = json.dumps(
                payload, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")

        # 3. Generate Proof-of-Possession signature.
        pop_sig = self._generate_pop_signature(method, path, challenge, body_bytes)

        # 4. Assemble ACP security headers.
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {capability_token}",
            HEADER_CHALLENGE: challenge,
            HEADER_SIGNATURE: pop_sig,
            HEADER_AGENT_ID: self.identity.agent_id,
        }

        # 5. Send request.
        url = f"{self.base_url}{path}"
        return requests.request(
            method,
            url,
            data=body_bytes if body_bytes else None,
            headers=headers,
            timeout=self.timeout,
        )

    # ── Internal Methods ──────────────────────────────────────────────────────

    def _request_challenge(self) -> str:
        """Request a one-time 128-bit challenge from the server.

        Returns:
            challenge nonce as base64url string (valid for 30 seconds).

        Raises:
            requests.HTTPError: on non-2xx response.
        """
        url = f"{self.base_url}/acp/v1/challenge"
        response = requests.get(url, timeout=self.timeout)
        response.raise_for_status()
        return response.json()["challenge"]

    def _generate_pop_signature(
        self,
        method: str,
        path: str,
        challenge: str,
        body_bytes: bytes,
    ) -> str:
        """Generate Proof-of-Possession signature (ACP-HP-1.0 channel binding).

        Signed payload format:
          Method + "|" + Path + "|" + Challenge + "|" + base64url(SHA-256(body))

        The signature is:
          Ed25519(sk_agent, SHA-256(signed_payload_bytes))

        Returns:
            base64url-encoded (no padding) Ed25519 signature.
        """
        # SHA-256 of the body (empty body → SHA-256 of empty bytes).
        body_hash = hashlib.sha256(body_bytes).digest()
        body_hash_b64 = base64.urlsafe_b64encode(body_hash).rstrip(b"=").decode("utf-8")

        # Construct signed payload string.
        signed_payload = f"{method}|{path}|{challenge}|{body_hash_b64}"

        # Sign using ACP-SIGN-1.0: Ed25519(sk, SHA-256(payload))
        sig_bytes = self.identity.sign(signed_payload.encode("utf-8"))

        return base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode("utf-8")


class ACPHandshakeError(Exception):
    """Raised when the ACP handshake fails."""
    pass
