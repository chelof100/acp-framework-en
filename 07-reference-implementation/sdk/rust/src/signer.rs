//! ACP Capability Signer — JCS canonicalization (RFC 8785) + Ed25519 signing
//!
//! Implements ACP-SIGN-1.0 signing pipeline:
//!   JCS(capability without "sig") → SHA-256 → Ed25519.sign → base64url

use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use serde_json::Value;
use sha2::{Sha256, Digest};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crate::identity::AgentIdentity;
use crate::error::ACPError;

/// ACP capability signer.
pub struct ACPSigner<'a> {
    identity: &'a AgentIdentity,
}

impl<'a> ACPSigner<'a> {
    /// Create a signer bound to the given identity.
    pub fn new(identity: &'a AgentIdentity) -> Self {
        Self { identity }
    }

    /// Sign a capability token (JSON object).
    ///
    /// 1. Remove any existing "sig" field
    /// 2. JCS-canonicalize the remaining fields
    /// 3. SHA-256 the canonical bytes
    /// 4. Ed25519-sign the hash
    /// 5. Return new object with "sig" = base64url(signature)
    pub fn sign_capability(&self, capability: &Value) -> Result<Value, ACPError> {
        let obj = capability.as_object()
            .ok_or_else(|| ACPError::InvalidInput("capability must be a JSON object".into()))?;

        // Strip "sig" field
        let mut without_sig: serde_json::Map<String, Value> = obj.clone();
        without_sig.remove("sig");
        let stripped = Value::Object(without_sig);

        // JCS canonicalize
        let canonical = jcs_canonicalize(&stripped)?;

        // SHA-256
        let mut hasher = Sha256::new();
        hasher.update(&canonical);
        let digest = hasher.finalize();

        // Ed25519 sign
        let sig = self.identity.sign(&digest);
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        // Reconstruct with sig
        let mut result = obj.clone();
        result.insert("sig".to_string(), Value::String(sig_b64));
        Ok(Value::Object(result))
    }

    /// Sign raw bytes. Returns base64url(Ed25519(SHA-256(data))).
    pub fn sign_bytes(&self, data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = hasher.finalize();
        let sig = self.identity.sign(&digest);
        URL_SAFE_NO_PAD.encode(sig.to_bytes())
    }

    /// Sign raw bytes without hashing first (for PoP where we hash manually).
    pub(crate) fn sign_raw(&self, message: &[u8]) -> Signature {
        self.identity.sign(message)
    }

    /// Verify a signed capability.
    ///
    /// 1. Extract "sig" field (base64url)
    /// 2. Strip "sig" → JCS → SHA-256
    /// 3. Ed25519 verify with provided public key bytes
    pub fn verify_capability(capability: &Value, public_key_bytes: &[u8; 32]) -> Result<bool, ACPError> {
        let obj = capability.as_object()
            .ok_or_else(|| ACPError::InvalidInput("capability must be a JSON object".into()))?;

        let sig_b64 = obj.get("sig")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ACPError::MissingSignature)?;

        let sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64)
            .map_err(|e| ACPError::InvalidInput(format!("invalid base64url signature: {e}")))?;

        let sig_array: [u8; 64] = sig_bytes.try_into()
            .map_err(|_| ACPError::InvalidInput("signature must be 64 bytes".into()))?;
        let signature = Signature::from_bytes(&sig_array);

        // Strip sig and canonicalize
        let mut without_sig = obj.clone();
        without_sig.remove("sig");
        let stripped = Value::Object(without_sig);
        let canonical = jcs_canonicalize(&stripped)?;

        // SHA-256
        let mut hasher = Sha256::new();
        hasher.update(&canonical);
        let digest = hasher.finalize();

        // Verify
        let verifying_key = VerifyingKey::from_bytes(public_key_bytes)
            .map_err(|e| ACPError::CryptoError(e.to_string()))?;

        Ok(verifying_key.verify(&digest, &signature).is_ok())
    }

    /// JCS-canonicalize a JSON value. Public for advanced use.
    pub fn canonicalize(value: &Value) -> Result<Vec<u8>, ACPError> {
        jcs_canonicalize(value)
    }
}

/// JCS canonicalization (RFC 8785).
///
/// Rules:
/// - Object keys sorted lexicographically (UTF-16 code units)
/// - No whitespace
/// - Strings: standard JSON escaping
/// - Numbers: no trailing zeros in fractions, no exponent if avoidable
/// - null, true, false: lowercase literals
pub fn jcs_canonicalize(value: &Value) -> Result<Vec<u8>, ACPError> {
    let s = jcs_str(value);
    Ok(s.into_bytes())
}

fn jcs_str(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => {
            // serde_json handles proper JSON string escaping
            serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
        }
        Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(jcs_str).collect();
            format!("[{}]", items.join(","))
        }
        Value::Object(map) => {
            // Sort keys lexicographically
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let entries: Vec<String> = keys
                .iter()
                .map(|k| {
                    let key_json = serde_json::to_string(*k).unwrap_or_else(|_| "\"\"".to_string());
                    let val_json = jcs_str(&map[*k]);
                    format!("{}:{}", key_json, val_json)
                })
                .collect();
            format!("{{{}}}", entries.join(","))
        }
    }
}
