ACP-D (Decentralized Capability Protocol)
4.1 DID + VC Based Issuance

Model:

DID Identities

Verifiable Credentials

Distributed Authority

4.2 Collective Issuance

Token valid if:

Signed by quorum

Or derived from verifiable credentials

4.3 Alternative Model: Self-Sovereign Capability

The user generates:

cap_token = ZK-Proof(
    I hold a valid credential
    I have the right to capability X
)

Verifier validates the proof.

There is no central issuer.

4.4 Final Architecture

Three layers:

Decentralized identity (DID)

Verifiable credentials

Capability derived via cryptographic proof

4.5 Security

Resistant to:

Single node compromise

Partial collusion

Byzantine attacks < 1/3 of the network
