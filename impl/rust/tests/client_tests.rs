//! Tests for ACPClient — HTTP client with PoP handshake.
//!
//! Uses mockito for HTTP mocking (no real server needed).

use acp_sdk::{AgentIdentity, ACPSigner, ACPClient, ACPError};
use mockito::{Server, Matcher};
use serde_json::json;

fn setup() -> (AgentIdentity, mockito::ServerGuard) {
    let agent = AgentIdentity::generate();
    let server = Server::new();
    (agent, server)
}

// ─── health() tests ──────────────────────────────────────────────────────────

#[test]
fn health_returns_ok() {
    let (agent, mut server) = setup();
    let _m = server.mock("GET", "/acp/v1/health")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"status":"ok","version":"1.0.0"}"#)
        .create();

    let signer = ACPSigner::new(&agent);
    let client = ACPClient::new(&server.url(), &agent, &signer);
    let result = client.health().unwrap();
    assert_eq!(result["status"], "ok");
}

#[test]
fn health_returns_error_on_503() {
    let (agent, mut server) = setup();
    let _m = server.mock("GET", "/acp/v1/health")
        .with_status(503)
        .with_body(r#"{"error":"service unavailable"}"#)
        .create();

    let signer = ACPSigner::new(&agent);
    let client = ACPClient::new(&server.url(), &agent, &signer);
    let result = client.health();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().status_code(), Some(503));
}

// ─── register() tests ────────────────────────────────────────────────────────

#[test]
fn register_posts_to_correct_url() {
    let (agent, mut server) = setup();
    let _m = server.mock("POST", "/acp/v1/register")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(r#"{"registered":true}"#)
        .create();

    let signer = ACPSigner::new(&agent);
    let client = ACPClient::new(&server.url(), &agent, &signer);
    let result = client.register().unwrap();
    assert_eq!(result["registered"], true);
}

#[test]
fn register_body_contains_agent_id_and_pubkey() {
    let (agent, mut server) = setup();
    let expected_id = agent.agent_id();
    let expected_hex = agent.public_key_hex();

    let _m = server.mock("POST", "/acp/v1/register")
        .with_status(201)
        .with_header("content-type", "application/json")
        .with_body(r#"{"registered":true}"#)
        .match_body(Matcher::AllOf(vec![
            Matcher::PartialJsonString(format!(r#"{{"agent_id":"{}"}}"#, expected_id)),
            Matcher::PartialJsonString(format!(r#"{{"public_key_hex":"{}"}}"#, expected_hex)),
        ]))
        .create();

    let signer = ACPSigner::new(&agent);
    let client = ACPClient::new(&server.url(), &agent, &signer);
    client.register().unwrap();
    _m.assert();
}

#[test]
fn register_returns_error_on_409_conflict() {
    let (agent, mut server) = setup();
    let _m = server.mock("POST", "/acp/v1/register")
        .with_status(409)
        .with_body(r#"{"error":"agent already registered"}"#)
        .create();

    let signer = ACPSigner::new(&agent);
    let client = ACPClient::new(&server.url(), &agent, &signer);
    let err = client.register().unwrap_err();
    assert_eq!(err.status_code(), Some(409));
}

// ─── verify() tests ───────────────────────────────────────────────────────────

fn mock_verify(server: &mut mockito::Server, agent: &AgentIdentity) -> (mockito::Mock, mockito::Mock) {
    let challenge_mock = server.mock("GET", "/acp/v1/challenge")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"challenge":"test-challenge-nonce","expires_in":"30s"}"#)
        .create();

    let agent_id = agent.agent_id();
    let verify_mock = server.mock("POST", "/acp/v1/verify")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"decision":"PERMIT","agent_id":"<id>"}"#)
        // Must have Authorization Bearer header
        .match_header("Authorization", Matcher::Regex(r"^Bearer \{".to_string()))
        // Must have X-ACP-Agent-ID header
        .match_header("X-ACP-Agent-ID", agent_id.as_str())
        // Must have X-ACP-Challenge header
        .match_header("X-ACP-Challenge", "test-challenge-nonce")
        // Must have X-ACP-Signature header (any non-empty value)
        .match_header("X-ACP-Signature", Matcher::Regex(r"^[A-Za-z0-9\-_]{80,}$".to_string()))
        .create();

    (challenge_mock, verify_mock)
}

#[test]
fn verify_makes_two_http_calls() {
    let (agent, mut server) = setup();
    let (challenge_mock, verify_mock) = mock_verify(&mut server, &agent);

    let cap = json!({
        "ver": "1.0", "iss": "did:key:zABC",
        "sub": agent.agent_id(), "cap": "acp:cap:read",
        "resource": "acc:1", "iat": 1700000000_u64,
        "exp": 1700003600_u64, "nonce": "n1", "sig": "fakesig"
    });

    let signer = ACPSigner::new(&agent);
    let client = ACPClient::new(&server.url(), &agent, &signer);
    let _ = client.verify(&cap);

    challenge_mock.assert();
    verify_mock.assert();
}

#[test]
fn verify_returns_error_when_challenge_missing() {
    let (agent, mut server) = setup();
    let _m = server.mock("GET", "/acp/v1/challenge")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"nonce":"wrong-field-name"}"#)  // missing "challenge" key
        .create();

    let cap = json!({"ver":"1.0","sig":"x"});
    let signer = ACPSigner::new(&agent);
    let client = ACPClient::new(&server.url(), &agent, &signer);
    let err = client.verify(&cap).unwrap_err();
    assert!(matches!(err, ACPError::UnexpectedResponse(_)));
}

#[test]
fn verify_returns_error_on_401() {
    let (agent, mut server) = setup();
    let _ch = server.mock("GET", "/acp/v1/challenge")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"challenge":"ch123","expires_in":"30s"}"#)
        .create();
    let _vr = server.mock("POST", "/acp/v1/verify")
        .with_status(401)
        .with_body(r#"{"error":"invalid signature"}"#)
        .create();

    let cap = json!({"ver":"1.0","sig":"x"});
    let signer = ACPSigner::new(&agent);
    let client = ACPClient::new(&server.url(), &agent, &signer);
    let err = client.verify(&cap).unwrap_err();
    assert_eq!(err.status_code(), Some(401));
}

// ─── ACPError tests ───────────────────────────────────────────────────────────

#[test]
fn acp_error_http_has_status_code() {
    let err = ACPError::Http { status: 404, body: "not found".to_string() };
    assert_eq!(err.status_code(), Some(404));
}

#[test]
fn acp_error_network_has_no_status_code() {
    let err = ACPError::Network("timeout".to_string());
    assert_eq!(err.status_code(), None);
}

#[test]
fn acp_error_missing_signature_is_error() {
    let err = ACPError::MissingSignature;
    assert!(err.status_code().is_none());
    assert!(err.to_string().contains("signature"));
}
