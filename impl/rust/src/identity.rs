//! ACP Agent Identity — Ed25519 keypair, AgentID (base58), DID (did:key)
//!
//! Implements ACP-SIGN-1.0 §3 identity primitives.

use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};

/// Ed25519 agent identity.
///
/// AgentID  = base58(SHA-256(raw 32-byte pubkey))
/// DID      = "did:key:z" + base58(0xed 0x01 || pubkey)
#[derive(Clone)]
pub struct AgentIdentity {
    signing_key: SigningKey,
}

impl AgentIdentity {
    /// Generate a new random Ed25519 keypair.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Reconstruct from raw 32-byte private key bytes.
    pub fn from_private_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        Self { signing_key }
    }

    /// Raw 32-byte private key.
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Raw 32-byte public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Public key as lowercase hex (for registration).
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    /// AgentID = base58btc(SHA-256(raw pubkey)).
    pub fn agent_id(&self) -> String {
        derive_agent_id(&self.public_key_bytes())
    }

    /// DID = "did:key:z" + base58btc(0xed01 || raw pubkey).
    pub fn did(&self) -> String {
        let pubkey = self.public_key_bytes();
        let mut multicodec = vec![0xed_u8, 0x01];
        multicodec.extend_from_slice(&pubkey);
        format!("did:key:z{}", bs58::encode(&multicodec).into_string())
    }

    /// Sign arbitrary bytes. Returns 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Verify a signature against this identity's public key.
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.signing_key.verifying_key().verify(message, signature).is_ok()
    }

    /// Access the inner verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

/// Derive AgentID from raw 32-byte public key bytes.
/// AgentID = base58btc(SHA-256(pubkey))
pub fn derive_agent_id(public_key_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(public_key_bytes);
    let hash = hasher.finalize();
    bs58::encode(hash).into_string()
}

impl std::fmt::Debug for AgentIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentIdentity")
            .field("agent_id", &self.agent_id())
            .field("did", &self.did())
            .finish()
    }
}
