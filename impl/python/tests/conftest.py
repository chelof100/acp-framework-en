"""
Shared fixtures for ACP Python SDK tests.

Test key: RFC 8037 §Appendix A — Ed25519 test vector (deterministic across runs).
Seed: 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55
"""
import pytest
from acp.identity import AgentIdentity
from acp.signer import ACPSigner

TEST_SEED_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55"
TEST_SEED = bytes.fromhex(TEST_SEED_HEX)


@pytest.fixture
def test_identity():
    """Deterministic Ed25519 identity from RFC 8037 test key A."""
    return AgentIdentity.from_private_bytes(TEST_SEED)


@pytest.fixture
def test_signer(test_identity):
    return ACPSigner(test_identity)


@pytest.fixture
def sample_capability(test_identity):
    """Valid capability token (non-expired) for signing tests."""
    return {
        "ver": "1.0",
        "iss": test_identity.did,
        "sub": test_identity.agent_id,
        "iat": 1700000000,
        "exp": 9999999999,
        "nonce": "test-nonce-12345",
        "cap": ["acp:cap:financial.payment"],
        "resource": "org.example/accounts/ACC-001",
    }
