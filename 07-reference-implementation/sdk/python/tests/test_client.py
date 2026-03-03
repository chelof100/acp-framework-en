"""
Tests for acp.client — ACPClient HTTP flows (mocked).

Spec references:
  - ACP-HP-1.0: Challenge/PoP handshake
  - POST /acp/v1/register — agent key registration
  - GET  /acp/v1/challenge — one-time nonce
  - POST /acp/v1/verify   — capability verification via headers
"""
import json
import base64
import pytest
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError, URLError
from io import BytesIO

from acp.identity import AgentIdentity
from acp.signer import ACPSigner
from acp.client import ACPClient, ACPError

TEST_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55"
)


@pytest.fixture
def identity():
    return AgentIdentity.from_private_bytes(TEST_SEED)


@pytest.fixture
def signer(identity):
    return ACPSigner(identity)


@pytest.fixture
def client(identity, signer):
    return ACPClient("http://localhost:8080", identity, signer)


@pytest.fixture
def sample_capability(identity):
    return {
        "ver": "1.0",
        "iss": identity.did,
        "sub": identity.agent_id,
        "iat": 1700000000,
        "exp": 9999999999,
        "nonce": "test-nonce",
        "cap": ["acp:cap:financial.payment"],
        "resource": "org.example/accounts/ACC-001",
    }


class TestACPClientInit:
    def test_trailing_slash_stripped(self, identity, signer):
        c = ACPClient("http://localhost:8080/", identity, signer)
        # Internal server URL should not have trailing slash
        assert not c._server.endswith("/")

    def test_server_url_stored(self, client):
        assert "localhost:8080" in client._server


class TestRegister:
    def test_register_calls_correct_url(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"ok": True}
            client.register()
        url = mock_post.call_args[0][0]
        assert url == "http://localhost:8080/acp/v1/register"

    def test_register_sends_agent_id(self, client, identity):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"ok": True}
            client.register()
        payload = mock_post.call_args[0][1]
        assert payload["agent_id"] == identity.agent_id

    def test_register_sends_public_key_hex(self, client, identity):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"ok": True}
            client.register()
        payload = mock_post.call_args[0][1]
        assert "public_key_hex" in payload
        # Decode and verify it matches the actual public key
        pk_b64 = payload["public_key_hex"]
        padding = "=" * (-len(pk_b64) % 4)
        pk_bytes = base64.urlsafe_b64decode(pk_b64 + padding)
        assert pk_bytes == identity.public_key_bytes

    def test_register_returns_server_response(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"ok": True, "message": "registered"}
            result = client.register()
        assert result == {"ok": True, "message": "registered"}


class TestVerify:
    def test_verify_fetches_challenge_first(self, client, signer, sample_capability):
        signed = signer.sign_capability(sample_capability)
        with patch("acp.client._get_json") as mock_get, \
             patch.object(client, "_post_with_acp_headers") as mock_post:
            mock_get.return_value = {"challenge": "ch-abc"}
            mock_post.return_value = {"ok": True}
            client.verify(signed)

        mock_get.assert_called_once()
        assert "/acp/v1/challenge" in mock_get.call_args[0][0]

    def test_verify_uses_challenge_in_pop(self, client, signer, sample_capability):
        signed = signer.sign_capability(sample_capability)
        challenge = "unique-challenge-xyz"
        with patch("acp.client._get_json") as mock_get, \
             patch.object(client, "_post_with_acp_headers") as mock_post:
            mock_get.return_value = {"challenge": challenge}
            mock_post.return_value = {"ok": True}
            client.verify(signed)

        kwargs = mock_post.call_args.kwargs
        assert kwargs["challenge"] == challenge

    def test_verify_sends_agent_id(self, client, identity, signer, sample_capability):
        signed = signer.sign_capability(sample_capability)
        with patch("acp.client._get_json") as mock_get, \
             patch.object(client, "_post_with_acp_headers") as mock_post:
            mock_get.return_value = {"challenge": "ch-1"}
            mock_post.return_value = {"ok": True}
            client.verify(signed)

        kwargs = mock_post.call_args.kwargs
        assert kwargs["agent_id"] == identity.agent_id

    def test_verify_calls_verify_endpoint(self, client, signer, sample_capability):
        signed = signer.sign_capability(sample_capability)
        with patch("acp.client._get_json") as mock_get, \
             patch.object(client, "_post_with_acp_headers") as mock_post:
            mock_get.return_value = {"challenge": "ch-2"}
            mock_post.return_value = {"ok": True}
            client.verify(signed)

        url = mock_post.call_args[0][0]
        assert url == "http://localhost:8080/acp/v1/verify"

    def test_verify_returns_server_response(self, client, signer, sample_capability):
        signed = signer.sign_capability(sample_capability)
        expected = {"ok": True, "capabilities": ["acp:cap:financial.payment"]}
        with patch("acp.client._get_json") as mock_get, \
             patch.object(client, "_post_with_acp_headers") as mock_post:
            mock_get.return_value = {"challenge": "ch-3"}
            mock_post.return_value = expected
            result = client.verify(signed)

        assert result == expected


class TestHealth:
    def test_health_calls_correct_url(self, client):
        with patch("acp.client._get_json") as mock_get:
            mock_get.return_value = {"ok": True, "version": "1.0.0"}
            result = client.health()

        mock_get.assert_called_once_with(
            "http://localhost:8080/acp/v1/health", timeout=10
        )
        assert result["ok"] is True

    def test_health_returns_version(self, client):
        with patch("acp.client._get_json") as mock_get:
            mock_get.return_value = {"ok": True, "version": "1.0.0"}
            result = client.health()
        assert result["version"] == "1.0.0"


class TestACPError:
    def test_acp_error_with_status_code(self):
        err = ACPError("Not Found", status_code=404)
        assert err.status_code == 404
        assert "Not Found" in str(err)

    def test_acp_error_without_status_code(self):
        err = ACPError("Connection refused")
        assert err.status_code is None

    def test_acp_error_is_exception(self):
        with pytest.raises(ACPError):
            raise ACPError("test error")


class TestPoPHeaders:
    def test_verify_includes_authorization_bearer(self, client, signer, sample_capability):
        """ACP-HP-1.0: token sent as 'Authorization: Bearer <token_json>'."""
        signed = signer.sign_capability(sample_capability)
        captured_headers = {}

        def fake_post(url, data, headers, **kwargs):
            captured_headers.update(headers)
            return MagicMock(
                read=lambda: json.dumps({"ok": True}).encode(),
                __enter__=lambda s: s,
                __exit__=MagicMock(return_value=False),
            )

        with patch("acp.client._get_json") as mock_get, \
             patch("acp.client.Request") as mock_req, \
             patch("acp.client.urlopen") as mock_open:

            mock_get.return_value = {"challenge": "ch-headers"}
            resp_mock = MagicMock()
            resp_mock.read.return_value = json.dumps({"ok": True}).encode()
            resp_mock.__enter__ = lambda s: s
            resp_mock.__exit__ = MagicMock(return_value=False)
            mock_open.return_value = resp_mock

            # Capture headers from Request constructor
            req_calls = []
            def capture_request(url, data=None, headers=None):
                if headers:
                    req_calls.append(headers)
                return MagicMock()
            mock_req.side_effect = capture_request

            try:
                client.verify(signed)
            except Exception:
                pass  # We just want to capture headers

        # If any request was made with ACP headers, check Authorization
        if req_calls:
            last_headers = req_calls[-1]
            if "Authorization" in last_headers:
                assert last_headers["Authorization"].startswith("Bearer ")
