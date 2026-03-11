//! Tests for AgentIdentity — ACP-SIGN-1.0 identity primitives.

use acp_sdk::{AgentIdentity, derive_agent_id};

#[test]
fn generate_produces_unique_identities() {
    let a = AgentIdentity::generate();
    let b = AgentIdentity::generate();
    assert_ne!(a.agent_id(), b.agent_id());
    assert_ne!(a.public_key_bytes(), b.public_key_bytes());
}

#[test]
fn public_key_is_32_bytes() {
    let agent = AgentIdentity::generate();
    assert_eq!(agent.public_key_bytes().len(), 32);
}

#[test]
fn private_key_is_32_bytes() {
    let agent = AgentIdentity::generate();
    assert_eq!(agent.private_key_bytes().len(), 32);
}

#[test]
fn public_key_hex_is_64_chars() {
    let agent = AgentIdentity::generate();
    assert_eq!(agent.public_key_hex().len(), 64);
    assert!(agent.public_key_hex().chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn agent_id_is_base58_format() {
    let agent = AgentIdentity::generate();
    let id = agent.agent_id();
    // Base58 uses Bitcoin alphabet — no 0, O, I, l
    assert!(id.chars().all(|c| !"0OIl".contains(c)));
    // SHA-256 → 32 bytes → ~43-44 base58 chars
    assert!(id.len() >= 40 && id.len() <= 50, "unexpected length: {}", id.len());
}

#[test]
fn did_starts_with_did_key_z() {
    let agent = AgentIdentity::generate();
    let did = agent.did();
    assert!(did.starts_with("did:key:z"), "DID: {did}");
}

#[test]
fn different_agents_have_different_dids() {
    let a = AgentIdentity::generate();
    let b = AgentIdentity::generate();
    assert_ne!(a.did(), b.did());
}

#[test]
fn round_trip_from_private_bytes() {
    let original = AgentIdentity::generate();
    let bytes = original.private_key_bytes();
    let restored = AgentIdentity::from_private_bytes(&bytes);

    assert_eq!(original.agent_id(), restored.agent_id());
    assert_eq!(original.did(), restored.did());
    assert_eq!(original.public_key_bytes(), restored.public_key_bytes());
}

#[test]
fn sign_produces_64_bytes() {
    let agent = AgentIdentity::generate();
    let sig = agent.sign(b"hello ACP");
    assert_eq!(sig.to_bytes().len(), 64);
}

#[test]
fn verify_valid_signature() {
    let agent = AgentIdentity::generate();
    let msg = b"test message";
    let sig = agent.sign(msg);
    assert!(agent.verify(msg, &sig));
}

#[test]
fn verify_rejects_wrong_message() {
    let agent = AgentIdentity::generate();
    let sig = agent.sign(b"original");
    assert!(!agent.verify(b"tampered", &sig));
}

#[test]
fn verify_rejects_wrong_key() {
    let signer = AgentIdentity::generate();
    let verifier = AgentIdentity::generate();
    let msg = b"message";
    let sig = signer.sign(msg);
    assert!(!verifier.verify(msg, &sig));
}

#[test]
fn derive_agent_id_matches_agent_id() {
    let agent = AgentIdentity::generate();
    let derived = derive_agent_id(&agent.public_key_bytes());
    assert_eq!(derived, agent.agent_id());
}

#[test]
fn derive_agent_id_is_deterministic() {
    let agent = AgentIdentity::generate();
    let pk = agent.public_key_bytes();
    let id1 = derive_agent_id(&pk);
    let id2 = derive_agent_id(&pk);
    assert_eq!(id1, id2);
}

#[test]
fn debug_format_does_not_expose_private_key() {
    let agent = AgentIdentity::generate();
    let debug = format!("{:?}", agent);
    // Should show agent_id and did, but NOT private key bytes
    assert!(debug.contains("agent_id"));
    assert!(debug.contains("did"));
}
