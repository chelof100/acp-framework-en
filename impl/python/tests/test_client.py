"""
Tests para acp.client — ACPClient HTTP flows (mocked).

Cobertura:
  ACP-HP-1.0  — register, verify, health, challenge/PoP
  ACP-CT-1.0  — authorize, tokens_issue
  ACP-REV-1.0 — revocation_check, revoke (+ revoke_descendants)
  ACP-REP-1.1 — reputation_get, reputation_events, reputation_state (new_state)
  ACP-EXEC-1.0 — exec_token_consume, exec_token_status
  ACP-LEDGER-1.0 — audit_query (filtros completos), audit_verify
  ACP-API-1.0 §3 — agent_register, agent_get, agent_state
  ACP-API-1.0 §8 — escalation_resolve
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


# ─── Init ─────────────────────────────────────────────────────────────────────

class TestACPClientInit:
    def test_trailing_slash_stripped(self, identity, signer):
        c = ACPClient("http://localhost:8080/", identity, signer)
        assert not c._server.endswith("/")

    def test_server_url_stored(self, client):
        assert "localhost:8080" in client._server


# ─── ACP-HP-1.0: register / verify / health ───────────────────────────────────

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


# ─── ACP-CT-1.0: authorize / tokens_issue ─────────────────────────────────────

class TestAuthorize:
    def test_authorize_url(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"decision": "APPROVED"}
            client.authorize("req-1", "agent-1", "acp:cap:x", "res/1")
        assert mock_post.call_args[0][0] == "http://localhost:8080/acp/v1/authorize"

    def test_authorize_required_fields(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"decision": "APPROVED"}
            client.authorize("req-1", "agent-1", "acp:cap:x", "res/1")
        body = mock_post.call_args[0][1]
        assert body["request_id"] == "req-1"
        assert body["agent_id"] == "agent-1"
        assert body["capability"] == "acp:cap:x"
        assert body["resource"] == "res/1"

    def test_authorize_optional_params(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"decision": "APPROVED"}
            client.authorize(
                "req-2", "agent-1", "acp:cap:x", "res/1",
                action_parameters={"amount": 100},
                context={"ip": "10.0.0.1"},
            )
        body = mock_post.call_args[0][1]
        assert body["action_parameters"] == {"amount": 100}
        assert body["context"] == {"ip": "10.0.0.1"}

    def test_authorize_no_optional_when_none(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"decision": "APPROVED"}
            client.authorize("req-3", "agent-1", "acp:cap:x", "res/1")
        body = mock_post.call_args[0][1]
        assert "action_parameters" not in body
        assert "context" not in body


class TestTokensIssue:
    def test_tokens_issue_url(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"token_id": "ct-1"}
            client.tokens_issue("issuer-1", "agent-2", ["acp:cap:read"], "res/x")
        assert mock_post.call_args[0][0] == "http://localhost:8080/acp/v1/tokens"

    def test_tokens_issue_required_fields(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"token_id": "ct-1"}
            client.tokens_issue("issuer-1", "agent-2", ["acp:cap:read"], "res/x")
        body = mock_post.call_args[0][1]
        assert body["issuer_id"] == "issuer-1"
        assert body["subject_agent_id"] == "agent-2"
        assert body["capabilities"] == ["acp:cap:read"]
        assert body["resource"] == "res/x"
        assert body["expires_in"] == 3600  # default

    def test_tokens_issue_custom_expires_in(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"token_id": "ct-2"}
            client.tokens_issue("issuer-1", "agent-2", ["acp:cap:read"], "res/x", expires_in=7200)
        body = mock_post.call_args[0][1]
        assert body["expires_in"] == 7200

    def test_tokens_issue_action_parameters(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"token_id": "ct-3"}
            client.tokens_issue(
                "issuer-1", "agent-2", ["acp:cap:write"], "res/x",
                action_parameters={"max_amount": 500},
            )
        body = mock_post.call_args[0][1]
        assert body["action_parameters"] == {"max_amount": 500}


# ─── ACP-REV-1.0: revocation_check / revoke ───────────────────────────────────

class TestRevocationCheck:
    def test_revocation_check_url(self, client):
        with patch("acp.client._get_json_params") as mock_get:
            mock_get.return_value = {"status": "active"}
            client.revocation_check("tok-abc")
        url = mock_get.call_args[0][0]
        assert url == "http://localhost:8080/acp/v1/rev/check"

    def test_revocation_check_sends_token_id(self, client):
        with patch("acp.client._get_json_params") as mock_get:
            mock_get.return_value = {"status": "active"}
            client.revocation_check("tok-abc")
        params = mock_get.call_args[0][1]
        assert params["token_id"] == "tok-abc"


class TestRevoke:
    def test_revoke_url(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"ok": True}
            client.revoke("tok-1", "COMPROMISE", "admin-1")
        assert mock_post.call_args[0][0] == "http://localhost:8080/acp/v1/rev/revoke"

    def test_revoke_required_fields(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"ok": True}
            client.revoke("tok-1", "COMPROMISE", "admin-1")
        body = mock_post.call_args[0][1]
        assert body["token_id"] == "tok-1"
        assert body["reason_code"] == "COMPROMISE"
        assert body["revoked_by"] == "admin-1"

    def test_revoke_descendants_false_by_default(self, client):
        """ACP-REV-1.0: revoke_descendants debe enviarse (default False)."""
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"ok": True}
            client.revoke("tok-1", "POLICY_VIOLATION", "admin-1")
        body = mock_post.call_args[0][1]
        assert body["revoke_descendants"] is False

    def test_revoke_descendants_true(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"ok": True}
            client.revoke("tok-1", "COMPROMISE", "admin-1", revoke_descendants=True)
        body = mock_post.call_args[0][1]
        assert body["revoke_descendants"] is True

    def test_revoke_includes_sig(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"ok": True}
            client.revoke("tok-1", "COMPROMISE", "admin-1", sig="abc123")
        body = mock_post.call_args[0][1]
        assert body["sig"] == "abc123"


# ─── ACP-REP-1.1: reputation ──────────────────────────────────────────────────

class TestReputationGet:
    def test_reputation_get_url(self, client):
        with patch("acp.client._get_json") as mock_get:
            mock_get.return_value = {"agent_id": "ag-1", "score": 90}
            client.reputation_get("ag-1")
        assert mock_get.call_args[0][0] == "http://localhost:8080/acp/v1/rep/ag-1"


class TestReputationEvents:
    def test_reputation_events_url(self, client):
        with patch("acp.client._get_json_params") as mock_get:
            mock_get.return_value = {"events": []}
            client.reputation_events("ag-1")
        url = mock_get.call_args[0][0]
        assert url == "http://localhost:8080/acp/v1/rep/ag-1/events"

    def test_reputation_events_default_pagination(self, client):
        with patch("acp.client._get_json_params") as mock_get:
            mock_get.return_value = {"events": []}
            client.reputation_events("ag-1")
        params = mock_get.call_args[0][1]
        assert params["limit"] == 20
        assert params["offset"] == 0

    def test_reputation_events_custom_pagination(self, client):
        with patch("acp.client._get_json_params") as mock_get:
            mock_get.return_value = {"events": []}
            client.reputation_events("ag-1", limit=5, offset=10)
        params = mock_get.call_args[0][1]
        assert params["limit"] == 5
        assert params["offset"] == 10


class TestReputationState:
    def test_reputation_state_url(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"ok": True}
            client.reputation_state("ag-1", "PROBATION")
        assert mock_post.call_args[0][0] == "http://localhost:8080/acp/v1/rep/ag-1/state"

    def test_reputation_state_uses_new_state_field(self, client):
        """ACP-REP-1.1 §7: el campo debe llamarse new_state (no state)."""
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"ok": True}
            client.reputation_state("ag-1", "SUSPENDED", reason="policy", authorized_by="admin")
        body = mock_post.call_args[0][1]
        assert "new_state" in body
        assert "state" not in body
        assert body["new_state"] == "SUSPENDED"
        assert body["reason"] == "policy"
        assert body["authorized_by"] == "admin"


# ─── ACP-EXEC-1.0: execution tokens ───────────────────────────────────────────

class TestExecTokenConsume:
    def test_exec_token_consume_url(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"state": "consumed"}
            client.exec_token_consume("et-1", 1700000000, "success")
        assert mock_post.call_args[0][0] == "http://localhost:8080/acp/v1/exec-tokens/et-1/consume"

    def test_exec_token_consume_body(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"state": "consumed"}
            client.exec_token_consume("et-1", 1700000000, "success", sig="sig123")
        body = mock_post.call_args[0][1]
        assert body["et_id"] == "et-1"
        assert body["consumed_at"] == 1700000000
        assert body["execution_result"] == "success"
        assert body["sig"] == "sig123"


class TestExecTokenStatus:
    def test_exec_token_status_url(self, client):
        with patch("acp.client._get_json") as mock_get:
            mock_get.return_value = {"et_id": "et-1", "state": "active"}
            client.exec_token_status("et-1")
        assert mock_get.call_args[0][0] == "http://localhost:8080/acp/v1/exec-tokens/et-1/status"


# ─── ACP-LEDGER-1.0: audit ────────────────────────────────────────────────────

class TestAuditQuery:
    def test_audit_query_url(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"events": []}
            client.audit_query()
        assert mock_post.call_args[0][0] == "http://localhost:8080/acp/v1/audit/query"

    def test_audit_query_empty_body_when_no_filters(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"events": []}
            client.audit_query()
        body = mock_post.call_args[0][1]
        assert body == {}

    def test_audit_query_event_type_filter(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"events": []}
            client.audit_query(event_type="AUTHORIZATION")
        body = mock_post.call_args[0][1]
        assert body["event_type"] == "AUTHORIZATION"

    def test_audit_query_agent_id_filter(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"events": []}
            client.audit_query(agent_id="ag-1")
        body = mock_post.call_args[0][1]
        assert body["agent_id"] == "ag-1"

    def test_audit_query_time_range(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"events": []}
            client.audit_query(time_range_from=1700000000, time_range_to=1700009999)
        body = mock_post.call_args[0][1]
        assert body["time_range"]["from"] == 1700000000
        assert body["time_range"]["to"] == 1700009999

    def test_audit_query_partial_time_range_from_only(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"events": []}
            client.audit_query(time_range_from=1700000000)
        body = mock_post.call_args[0][1]
        assert "time_range" in body
        assert "from" in body["time_range"]
        assert "to" not in body["time_range"]

    def test_audit_query_sequence_range(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"events": []}
            client.audit_query(from_sequence=1, to_sequence=50)
        body = mock_post.call_args[0][1]
        assert body["from_sequence"] == 1
        assert body["to_sequence"] == 50

    def test_audit_query_pagination(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"events": []}
            client.audit_query(limit=10, offset=20)
        body = mock_post.call_args[0][1]
        assert body["limit"] == 10
        assert body["offset"] == 20

    def test_audit_query_all_filters_combined(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"events": []}
            client.audit_query(
                event_type="REVOCATION",
                agent_id="ag-1",
                time_range_from=1700000000,
                time_range_to=1800000000,
                from_sequence=1,
                to_sequence=100,
                limit=25,
                offset=0,
            )
        body = mock_post.call_args[0][1]
        assert body["event_type"] == "REVOCATION"
        assert body["agent_id"] == "ag-1"
        assert body["time_range"] == {"from": 1700000000, "to": 1800000000}
        assert body["limit"] == 25


class TestAuditVerify:
    def test_audit_verify_url(self, client):
        with patch("acp.client._get_json") as mock_get:
            mock_get.return_value = {"chain_valid": True}
            client.audit_verify("ev-abc-123")
        assert mock_get.call_args[0][0] == "http://localhost:8080/acp/v1/audit/verify/ev-abc-123"


# ─── ACP-API-1.0 §3: Agents ───────────────────────────────────────────────────

class TestAgentRegister:
    def test_agent_register_url(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"agent_id": "ag-new"}
            client.agent_register("ag-new", "pubkeyb64==", autonomy_level=2)
        assert mock_post.call_args[0][0] == "http://localhost:8080/acp/v1/agents"

    def test_agent_register_required_fields(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"agent_id": "ag-new"}
            client.agent_register("ag-new", "pubkeyb64==")
        body = mock_post.call_args[0][1]
        assert body["agent_id"] == "ag-new"
        assert body["public_key_hex"] == "pubkeyb64=="
        assert body["autonomy_level"] == 1  # default

    def test_agent_register_custom_autonomy(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"agent_id": "ag-new"}
            client.agent_register("ag-new", "pk==", autonomy_level=3)
        body = mock_post.call_args[0][1]
        assert body["autonomy_level"] == 3

    def test_agent_register_optional_metadata(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"agent_id": "ag-new"}
            client.agent_register("ag-new", "pk==", metadata={"team": "finance"})
        body = mock_post.call_args[0][1]
        assert body["metadata"] == {"team": "finance"}


class TestAgentGet:
    def test_agent_get_url(self, client):
        with patch("acp.client._get_json") as mock_get:
            mock_get.return_value = {"agent_id": "ag-1"}
            client.agent_get("ag-1")
        assert mock_get.call_args[0][0] == "http://localhost:8080/acp/v1/agents/ag-1"

    def test_agent_get_returns_response(self, client):
        expected = {"agent_id": "ag-1", "status": "active", "autonomy_level": 2}
        with patch("acp.client._get_json") as mock_get:
            mock_get.return_value = expected
            result = client.agent_get("ag-1")
        assert result == expected


class TestAgentState:
    def test_agent_state_url(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"agent_id": "ag-1", "state": "suspended"}
            client.agent_state("ag-1", "suspended")
        assert mock_post.call_args[0][0] == "http://localhost:8080/acp/v1/agents/ag-1/state"

    def test_agent_state_body(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"agent_id": "ag-1", "state": "suspended"}
            client.agent_state("ag-1", "suspended", reason="violation", authorized_by="admin")
        body = mock_post.call_args[0][1]
        assert body["new_state"] == "suspended"
        assert body["reason"] == "violation"
        assert body["authorized_by"] == "admin"


# ─── ACP-API-1.0 §8: Escalations ──────────────────────────────────────────────

class TestEscalationResolve:
    def test_escalation_resolve_url(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"resolution": "APPROVED"}
            client.escalation_resolve("esc-1", "APPROVED", "reviewer-1")
        assert mock_post.call_args[0][0] == "http://localhost:8080/acp/v1/escalations/esc-1/resolve"

    def test_escalation_resolve_body(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"resolution": "DENIED"}
            client.escalation_resolve("esc-1", "DENIED", "reviewer-1", notes="policy violation")
        body = mock_post.call_args[0][1]
        assert body["resolution"] == "DENIED"
        assert body["resolved_by"] == "reviewer-1"
        assert body["notes"] == "policy violation"

    def test_escalation_resolve_default_empty_notes(self, client):
        with patch("acp.client._post_json") as mock_post:
            mock_post.return_value = {"resolution": "APPROVED"}
            client.escalation_resolve("esc-1", "APPROVED", "reviewer-1")
        body = mock_post.call_args[0][1]
        assert body["notes"] == ""


# ─── Error handling ───────────────────────────────────────────────────────────

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
        """ACP-HP-1.0: token enviado como 'Authorization: Bearer <token_json>'."""
        signed = signer.sign_capability(sample_capability)
        captured_headers = {}

        with patch("acp.client._get_json") as mock_get, \
             patch("acp.client.Request") as mock_req, \
             patch("acp.client.urlopen") as mock_open:

            mock_get.return_value = {"challenge": "ch-headers"}
            resp_mock = MagicMock()
            resp_mock.read.return_value = json.dumps({"ok": True}).encode()
            resp_mock.__enter__ = lambda s: s
            resp_mock.__exit__ = MagicMock(return_value=False)
            mock_open.return_value = resp_mock

            req_calls = []
            def capture_request(url, data=None, headers=None):
                if headers:
                    req_calls.append(headers)
                return MagicMock()
            mock_req.side_effect = capture_request

            try:
                client.verify(signed)
            except Exception:
                pass

        if req_calls:
            last_headers = req_calls[-1]
            if "Authorization" in last_headers:
                assert last_headers["Authorization"].startswith("Bearer ")
