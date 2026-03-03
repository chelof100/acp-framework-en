//! ACP HTTP Client — register/verify/health with automatic PoP handshake
//!
//! Implements ACP-HP-1.0 Challenge/PoP handshake transparently.

use serde_json::Value;
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crate::identity::AgentIdentity;
use crate::signer::ACPSigner;
use crate::error::ACPError;

/// ACP HTTP client for agent-to-institution communication.
pub struct ACPClient<'a> {
    server_url: String,
    identity: &'a AgentIdentity,
    signer: &'a ACPSigner<'a>,
}

impl<'a> ACPClient<'a> {
    /// Create a new client.
    ///
    /// `server_url` — base URL, e.g. "http://localhost:8080"
    pub fn new(server_url: &str, identity: &'a AgentIdentity, signer: &'a ACPSigner<'a>) -> Self {
        Self {
            server_url: server_url.trim_end_matches('/').to_string(),
            identity,
            signer,
        }
    }

    /// Register this agent's public key with the institution.
    ///
    /// POST /acp/v1/register
    /// Body: {"agent_id": "<base58>", "public_key_hex": "<64-char hex>"}
    pub fn register(&self) -> Result<Value, ACPError> {
        let body = serde_json::json!({
            "agent_id": self.identity.agent_id(),
            "public_key_hex": self.identity.public_key_hex()
        });
        self.post_json("/acp/v1/register", &body)
    }

    /// Verify a signed capability token (full Challenge/PoP handshake).
    ///
    /// 1. GET /acp/v1/challenge → nonce
    /// 2. Build PoP: SHA-256(Method|Path|Challenge|base64url(SHA-256(body)))
    /// 3. POST /acp/v1/verify with ACP headers + token as Bearer
    pub fn verify(&self, capability_token: &Value) -> Result<Value, ACPError> {
        // Step 1: Get challenge
        let challenge_resp = self.get_json("/acp/v1/challenge")?;
        let challenge = challenge_resp
            .get("challenge")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ACPError::UnexpectedResponse("missing 'challenge' field".into()))?
            .to_string();

        // Step 2: Build token JSON body
        let body_bytes = serde_json::to_vec(capability_token)?;

        // Step 3: Compute PoP signature
        let pop = self.sign_pop("POST", "/acp/v1/verify", &challenge, &body_bytes);

        // Step 4: POST with ACP headers
        let token_json = serde_json::to_string(capability_token)?;
        let url = format!("{}/acp/v1/verify", self.server_url);

        let resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .set("Authorization", &format!("Bearer {token_json}"))
            .set("X-ACP-Agent-ID", &self.identity.agent_id())
            .set("X-ACP-Challenge", &challenge)
            .set("X-ACP-Signature", &pop)
            .send_bytes(&body_bytes)
            .map_err(|e| map_ureq_error(e))?;

        let status = resp.status();
        let body_str = resp.into_string()
            .map_err(|e| ACPError::Network(e.to_string()))?;

        if status >= 400 {
            return Err(ACPError::Http { status, body: body_str });
        }

        serde_json::from_str(&body_str).map_err(ACPError::from)
    }

    /// Check server health.
    ///
    /// GET /acp/v1/health
    pub fn health(&self) -> Result<Value, ACPError> {
        self.get_json("/acp/v1/health")
    }

    // ─── Internal helpers ────────────────────────────────────────────────────

    fn get_json(&self, path: &str) -> Result<Value, ACPError> {
        let url = format!("{}{}", self.server_url, path);
        let resp = ureq::get(&url)
            .call()
            .map_err(|e| map_ureq_error(e))?;

        let status = resp.status();
        let body = resp.into_string()
            .map_err(|e| ACPError::Network(e.to_string()))?;

        if status >= 400 {
            return Err(ACPError::Http { status, body });
        }
        serde_json::from_str(&body).map_err(ACPError::from)
    }

    fn post_json(&self, path: &str, body: &Value) -> Result<Value, ACPError> {
        let url = format!("{}{}", self.server_url, path);
        let body_str = serde_json::to_string(body)?;

        let resp = ureq::post(&url)
            .set("Content-Type", "application/json")
            .send_string(&body_str)
            .map_err(|e| map_ureq_error(e))?;

        let status = resp.status();
        let resp_body = resp.into_string()
            .map_err(|e| ACPError::Network(e.to_string()))?;

        if status >= 400 {
            return Err(ACPError::Http { status, body: resp_body });
        }
        serde_json::from_str(&resp_body).map_err(ACPError::from)
    }

    /// Compute PoP signature.
    ///
    /// PoP = base64url(Ed25519(SHA-256("METHOD|/path|challenge|base64url(SHA-256(body))")))
    fn sign_pop(&self, method: &str, path: &str, challenge: &str, body: &[u8]) -> String {
        // Hash body
        let mut body_hasher = Sha256::new();
        body_hasher.update(body);
        let body_hash = body_hasher.finalize();
        let body_hash_b64 = URL_SAFE_NO_PAD.encode(body_hash);

        // Build PoP message
        let pop_message = format!("{method}|{path}|{challenge}|{body_hash_b64}");

        // SHA-256 the message
        let mut msg_hasher = Sha256::new();
        msg_hasher.update(pop_message.as_bytes());
        let msg_digest = msg_hasher.finalize();

        // Ed25519 sign
        let sig = self.signer.sign_raw(&msg_digest);
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    }
}

fn map_ureq_error(e: ureq::Error) -> ACPError {
    match e {
        ureq::Error::Status(status, resp) => {
            let body = resp.into_string().unwrap_or_default();
            ACPError::Http { status, body }
        }
        ureq::Error::Transport(t) => ACPError::Network(t.to_string()),
    }
}
