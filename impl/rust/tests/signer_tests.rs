//! Tests for ACPSigner — JCS canonicalization + Ed25519 signing.

use acp_sdk::{AgentIdentity, ACPSigner, jcs_canonicalize};
use serde_json::{json, Value};

fn make_capability() -> Value {
    json!({
        "ver": "1.0",
        "iss": "did:key:zABC123",
        "sub": "agentXYZ",
        "cap": "acp:cap:financial.read",
        "resource": "account:12345",
        "iat": 1700000000_u64,
        "exp": 1700003600_u64,
        "nonce": "test-nonce-001"
    })
}

// ─── JCS canonicalization tests ──────────────────────────────────────────────

#[test]
fn jcs_sorts_keys_lexicographically() {
    let obj = json!({"z": 1, "a": 2, "m": 3});
    let canonical = jcs_canonicalize(&obj).unwrap();
    let s = String::from_utf8(canonical).unwrap();
    assert_eq!(s, r#"{"a":2,"m":3,"z":1}"#);
}

#[test]
fn jcs_handles_nested_objects() {
    let obj = json!({"b": {"z": 1, "a": 2}, "a": true});
    let canonical = jcs_canonicalize(&obj).unwrap();
    let s = String::from_utf8(canonical).unwrap();
    assert_eq!(s, r#"{"a":true,"b":{"a":2,"z":1}}"#);
}

#[test]
fn jcs_handles_arrays() {
    let obj = json!({"arr": [3, 1, 2]});
    let canonical = jcs_canonicalize(&obj).unwrap();
    let s = String::from_utf8(canonical).unwrap();
    // Arrays are NOT sorted — order is preserved
    assert_eq!(s, r#"{"arr":[3,1,2]}"#);
}

#[test]
fn jcs_handles_null_bool_number() {
    let obj = json!({"a": null, "b": true, "c": false, "d": 42});
    let canonical = jcs_canonicalize(&obj).unwrap();
    let s = String::from_utf8(canonical).unwrap();
    assert_eq!(s, r#"{"a":null,"b":true,"c":false,"d":42}"#);
}

#[test]
fn jcs_is_deterministic() {
    let obj = make_capability();
    let c1 = jcs_canonicalize(&obj).unwrap();
    let c2 = jcs_canonicalize(&obj).unwrap();
    assert_eq!(c1, c2);
}

#[test]
fn jcs_produces_no_whitespace() {
    let obj = make_capability();
    let canonical = jcs_canonicalize(&obj).unwrap();
    let s = String::from_utf8(canonical).unwrap();
    assert!(!s.contains(' '));
    assert!(!s.contains('\n'));
}

// ─── sign_capability tests ────────────────────────────────────────────────────

#[test]
fn sign_capability_adds_sig_field() {
    let agent = AgentIdentity::generate();
    let signer = ACPSigner::new(&agent);
    let cap = make_capability();
    let signed = signer.sign_capability(&cap).unwrap();
    assert!(signed.get("sig").is_some());
}

#[test]
fn sign_capability_does_not_mutate_original() {
    let agent = AgentIdentity::generate();
    let signer = ACPSigner::new(&agent);
    let cap = make_capability();
    let _ = signer.sign_capability(&cap).unwrap();
    // Original should not have "sig"
    assert!(cap.get("sig").is_none());
}

#[test]
fn sign_capability_sig_is_base64url() {
    let agent = AgentIdentity::generate();
    let signer = ACPSigner::new(&agent);
    let cap = make_capability();
    let signed = signer.sign_capability(&cap).unwrap();
    let sig = signed["sig"].as_str().unwrap();
    // Base64url chars only (no +, /, =)
    assert!(sig.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
    // Ed25519 sig = 64 bytes → 86 base64url chars (no padding)
    assert_eq!(sig.len(), 86, "unexpected sig length: {}", sig.len());
}

#[test]
fn sign_capability_strips_existing_sig() {
    let agent = AgentIdentity::generate();
    let signer = ACPSigner::new(&agent);
    let mut cap = make_capability();
    cap["sig"] = serde_json::Value::String("old-sig".to_string());

    let signed = signer.sign_capability(&cap).unwrap();
    let new_sig = signed["sig"].as_str().unwrap();
    assert_ne!(new_sig, "old-sig");
}

#[test]
fn different_nonces_produce_different_sigs() {
    let agent = AgentIdentity::generate();
    let signer = ACPSigner::new(&agent);

    let mut cap1 = make_capability();
    cap1["nonce"] = json!("nonce-aaa");
    let mut cap2 = make_capability();
    cap2["nonce"] = json!("nonce-bbb");

    let s1 = signer.sign_capability(&cap1).unwrap();
    let s2 = signer.sign_capability(&cap2).unwrap();
    assert_ne!(s1["sig"], s2["sig"]);
}

// ─── verify_capability tests ───────────────────────────────────────────────────

#[test]
fn verify_valid_signature() {
    let agent = AgentIdentity::generate();
    let signer = ACPSigner::new(&agent);
    let cap = make_capability();
    let signed = signer.sign_capability(&cap).unwrap();
    let pk = agent.public_key_bytes();
    assert!(ACPSigner::verify_capability(&signed, &pk).unwrap());
}

#[test]
fn verify_fails_missing_sig() {
    let agent = AgentIdentity::generate();
    let cap = make_capability();
    let pk = agent.public_key_bytes();
    let result = ACPSigner::verify_capability(&cap, &pk);
    assert!(result.is_err() || !result.unwrap());
}

#[test]
fn verify_fails_tampered_field() {
    let agent = AgentIdentity::generate();
    let signer = ACPSigner::new(&agent);
    let cap = make_capability();
    let mut signed = signer.sign_capability(&cap).unwrap();
    signed["cap"] = json!("acp:cap:financial.write"); // tampered
    let pk = agent.public_key_bytes();
    assert!(!ACPSigner::verify_capability(&signed, &pk).unwrap());
}

#[test]
fn verify_fails_wrong_public_key() {
    let agent = AgentIdentity::generate();
    let other = AgentIdentity::generate();
    let signer = ACPSigner::new(&agent);
    let cap = make_capability();
    let signed = signer.sign_capability(&cap).unwrap();
    let pk = other.public_key_bytes();
    assert!(!ACPSigner::verify_capability(&signed, &pk).unwrap());
}

#[test]
fn verify_fails_invalid_base64() {
    let agent = AgentIdentity::generate();
    let signer = ACPSigner::new(&agent);
    let cap = make_capability();
    let mut signed = signer.sign_capability(&cap).unwrap();
    signed["sig"] = json!("!!!not-base64!!!");
    let pk = agent.public_key_bytes();
    assert!(ACPSigner::verify_capability(&signed, &pk).is_err());
}

// ─── canonicalize public API ──────────────────────────────────────────────────

#[test]
fn canonicalize_matches_jcs_canonicalize() {
    let obj = make_capability();
    let via_signer = ACPSigner::canonicalize(&obj).unwrap();
    let via_fn = jcs_canonicalize(&obj).unwrap();
    assert_eq!(via_signer, via_fn);
}
