"""
acp.client — HTTP ACP client with automatic PoP handshake (ACP-HP-1.0)

The ACPClient handles the full ACP authorization flow:
  1. GET /acp/v1/challenge  → receive nonce
  2. Sign nonce with agent private key (Proof of Possession)
  3. POST /acp/v1/verify   → send capability token + PoP, receive decision

Usage:
    from acp.identity import AgentIdentity
    from acp.signer import ACPSigner
    from acp.client import ACPClient

    agent = AgentIdentity.generate()
    signer = ACPSigner(agent)
    client = ACPClient(
        server_url="http://localhost:8080",
        identity=agent,
        signer=signer,
    )

    # Verify a capability token for a given action + resource
    result = client.verify(
        capability_token=signed_token,
        requested_capability="acp:cap:financial.payment",
        requested_resource="org.banco/accounts/ACC-001",
    )
    print(result)  # {"decision": "AUTHORIZED", ...}
"""
from __future__ import annotations

import base64
import hashlib
import time
from typing import Any, Dict, Optional
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
import json

from .identity import AgentIdentity
from .signer import ACPSigner


class ACPError(Exception):
    """Raised when the ACP server returns an error or the request fails."""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def _post_json(url: str, body: Dict[str, Any], timeout: int = 10) -> Dict[str, Any]:
    """Minimal HTTP POST with JSON body, no external dependencies."""
    data = json.dumps(body).encode("utf-8")
    req = Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        body_bytes = e.read()
        try:
            err = json.loads(body_bytes)
        except Exception:
            err = {"error": body_bytes.decode("utf-8", errors="replace")}
        raise ACPError(
            f"HTTP {e.code}: {err.get('error', str(err))}", status_code=e.code
        ) from e
    except URLError as e:
        raise ACPError(f"Connection failed: {e.reason}") from e


def _get_json(url: str, timeout: int = 10) -> Dict[str, Any]:
    """Minimal HTTP GET returning parsed JSON."""
    req = Request(url)
    try:
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except HTTPError as e:
        raise ACPError(f"HTTP {e.code}", status_code=e.code) from e
    except URLError as e:
        raise ACPError(f"Connection failed: {e.reason}") from e


class ACPClient:
    """
    ACP HTTP client implementing the Challenge/PoP handshake (ACP-HP-1.0).

    The client is stateless between calls. Each `verify()` call performs a
    fresh challenge request to prevent replay attacks.
    """

    def __init__(
        self,
        server_url: str,
        identity: AgentIdentity,
        signer: ACPSigner,
        timeout: int = 10,
    ) -> None:
        """
        Args:
            server_url: Base URL of the ACP validator (e.g. "http://localhost:8080")
            identity:   Agent identity (Ed25519 key pair)
            signer:     ACPSigner instance for producing PoP signatures
            timeout:    HTTP timeout in seconds
        """
        self._server = server_url.rstrip("/")
        self._identity = identity
        self._signer = signer
        self._timeout = timeout

    # ─── Public API ───────────────────────────────────────────────────────────

    def verify(
        self,
        capability_token: Dict[str, Any],
        requested_capability: str,
        requested_resource: str,
    ) -> Dict[str, Any]:
        """
        Full ACP verification flow (ACP-HP-1.0):
          1. Fetch fresh challenge nonce from server
          2. Produce PoP signature over challenge + agent_id + capability_id
          3. POST to /acp/v1/verify with token + PoP

        Returns:
            dict with at minimum {"decision": "AUTHORIZED" | "DENIED", ...}

        Raises:
            ACPError on HTTP or connection failure
        """
        # Step 1: Get challenge
        challenge_resp = self._get_challenge()
        challenge = challenge_resp["challenge"]

        # Step 2: Proof of Possession
        pop = self._produce_pop(challenge, requested_capability)

        # Step 3: Verify
        return _post_json(
            f"{self._server}/acp/v1/verify",
            {
                "capability_token": capability_token,
                "requested_capability": requested_capability,
                "requested_resource": requested_resource,
                "agent_id": self._identity.agent_id,
                "proof_of_possession": pop,
            },
            timeout=self._timeout,
        )

    def health(self) -> Dict[str, Any]:
        """GET /acp/v1/health — check server availability."""
        return _get_json(f"{self._server}/acp/v1/health", timeout=self._timeout)

    # ─── Internal ─────────────────────────────────────────────────────────────

    def _get_challenge(self) -> Dict[str, Any]:
        """Fetch a one-time 128-bit challenge nonce (ACP-HP-1.0 §2)."""
        return _get_json(
            f"{self._server}/acp/v1/challenge", timeout=self._timeout
        )

    def _produce_pop(self, challenge: str, capability_id: str) -> Dict[str, Any]:
        """
        Produce a Proof of Possession over:
          SHA-256( challenge || agent_id || capability_id )

        Returns a PoP object compatible with the ACP-HP-1.0 verify endpoint.
        """
        agent_id = self._identity.agent_id

        # Binding input: challenge + agent_id + capability_id (deterministic order)
        binding = f"{challenge}.{agent_id}.{capability_id}".encode("utf-8")
        digest = hashlib.sha256(binding).digest()

        # Sign the digest
        sig_bytes = self._signer.sign_bytes(digest)
        sig_b64 = base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()

        return {
            "challenge": challenge,
            "agent_id": agent_id,
            "capability_id": capability_id,
            "signature": sig_b64,
            "algorithm": "Ed25519",
        }
