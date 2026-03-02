"""
acp.client — HTTP ACP client with automatic PoP handshake (ACP-HP-1.0)

The ACPClient handles the full ACP authorization flow:
  1. POST /acp/v1/register → register agent's public key (once per agent)
  2. GET  /acp/v1/challenge → receive one-time nonce
  3. Sign PoP: Method|Path|Challenge|base64url(SHA-256(body)) → Ed25519
  4. POST /acp/v1/verify   → send token + PoP via HTTP headers, receive decision

HTTP headers used by verify():
  Authorization:   Bearer <capability_token_json>
  X-ACP-Agent-ID:  <agent_id>
  X-ACP-Challenge: <challenge>
  X-ACP-Signature: <pop_signature>

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

    # Register agent with the server (once)
    client.register()

    # Verify a capability token
    result = client.verify(capability_token=signed_token)
    print(result)  # {"ok": true, "agent_id": "...", "capabilities": [...]}
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

    def register(self) -> Dict[str, Any]:
        """
        Register this agent's public key with the ACP server.

        POST /acp/v1/register
        Body: {"agent_id": "<agent_id>", "public_key_hex": "<base64url(pubkey)>"}

        Must be called once before verify(). In production this endpoint is
        restricted to institutional administrators.
        """
        pubkey_b64 = base64.urlsafe_b64encode(
            self._identity.public_key_bytes
        ).rstrip(b"=").decode()
        return _post_json(
            f"{self._server}/acp/v1/register",
            {"agent_id": self._identity.agent_id, "public_key_hex": pubkey_b64},
            timeout=self._timeout,
        )

    def verify(
        self,
        capability_token: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Full ACP verification flow (ACP-HP-1.0):
          1. GET /acp/v1/challenge  → one-time nonce
          2. Compute PoP: Method|Path|Challenge|base64url(SHA-256(body))
          3. POST /acp/v1/verify via HTTP headers (Authorization + X-ACP-*)

        Args:
            capability_token: Signed capability token dict (from ACPSigner).

        Returns:
            {"ok": true, "agent_id": "...", "capabilities": [...], ...}

        Raises:
            ACPError on HTTP or connection failure.
        """
        # Step 1: Get challenge
        challenge_resp = self._get_challenge()
        challenge = challenge_resp["challenge"]

        # Step 2: Serialize token and compute PoP over empty body
        token_json = json.dumps(capability_token, separators=(",", ":"))
        body = b""
        pop_sig = self._sign_pop("POST", "/acp/v1/verify", challenge, body)

        # Step 3: POST with ACP headers
        return self._post_with_acp_headers(
            f"{self._server}/acp/v1/verify",
            body=body,
            token_json=token_json,
            agent_id=self._identity.agent_id,
            challenge=challenge,
            pop_sig=pop_sig,
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

    def _sign_pop(
        self, method: str, path: str, challenge: str, body: bytes
    ) -> str:
        """
        Compute Proof-of-Possession signature (ACP-HP-1.0 channel binding).

        signed_payload = Method + "|" + Path + "|" + Challenge + "|" + base64url(SHA-256(body))
        sig = Ed25519(sk, SHA-256(signed_payload_bytes))

        Returns base64url-encoded signature (no padding).
        """
        body_hash = hashlib.sha256(body).digest()
        body_hash_b64 = base64.urlsafe_b64encode(body_hash).rstrip(b"=").decode()
        signed_payload = f"{method}|{path}|{challenge}|{body_hash_b64}"
        payload_hash = hashlib.sha256(signed_payload.encode("utf-8")).digest()
        sig_bytes = self._signer.sign_bytes(payload_hash)
        return base64.urlsafe_b64encode(sig_bytes).rstrip(b"=").decode()

    def _post_with_acp_headers(
        self,
        url: str,
        body: bytes,
        token_json: str,
        agent_id: str,
        challenge: str,
        pop_sig: str,
    ) -> Dict[str, Any]:
        """POST request with ACP authentication headers."""
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token_json}",
            "X-ACP-Agent-ID": agent_id,
            "X-ACP-Challenge": challenge,
            "X-ACP-Signature": pop_sig,
        }
        req = Request(url, data=body, headers=headers)
        try:
            with urlopen(req, timeout=self._timeout) as resp:
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
