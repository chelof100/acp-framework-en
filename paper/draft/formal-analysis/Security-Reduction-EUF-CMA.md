4. Security Reduction of ACP to EUF-CMA Signature Security
4.1 Cryptographic Model

Let:

Σ = (KeyGen, Sign, Verify) be a digital signature scheme.

We assume Σ is existentially unforgeable under chosen-message attack (EUF-CMA).

We define the ACP token as:

T = Sign_skI( m )

where:

m = Encode(
      subject,
      resource,
      context_hash,
      exp,
      nonce,
      policy_version
)

The verifier accepts if:

Verify_pkI(m, T) = 1
∧ exp valid
∧ policy valid
∧ subject binding valid
∧ nonce not reused
4.2 ACP-CMA Security Game

We define the game between Challenger C and adversary A.

Setup

C executes:

(pk, sk) ← KeyGen(1^λ)

pk is delivered to A.

Signing Oracle

A can query an oracle:

O_sign(m):
    return Sign_sk(m)

This models legitimate token issuance.

Attack Phase

A produces a pair (m*, T*) such that:

Verify_pk(m*, T*) = 1

m* was not previously queried to oracle O_sign

If A achieves this, A wins.

4.3 Advantage Definition

We define the advantage of A as:

Adv_ACP(A) = Pr[ A wins ]
4.4 Main Theorem

Theorem 1.

If there exists a PPT adversary A that breaks ACP with advantage ε,
then there exists a PPT adversary B that breaks Σ under EUF-CMA with advantage at least ε.

4.5 Proof by Reduction

We construct B using A as a subroutine.

Reduction Construction B

B interacts with the EUF-CMA game challenger.

Step 1 – Receiving pk

B receives pk from the EUF-CMA challenger.

B delivers pk to A.

Step 2 – Oracle Simulation

When A queries:

O_sign(m)

B forwards m to the real signing oracle and returns the signature to A.

Perfect simulation.

Step 3 – A's Forgery

A produces:

(m*, T*)

such that:

Verify_pk(m*, T*) = 1

m* was not previously queried

B returns exactly (m*, T*) to the EUF-CMA challenger.

Correctness of the Reduction

If A wins in ACP:

m* was not signed by the oracle

T* verifies correctly

Then:

B has produced a valid forgery under EUF-CMA.

4.6 Advantage Relationship

The simulation is perfect.

Therefore:

Adv_EUF-CMA(B) = Adv_ACP(A)

The reduction is tight.

4.7 Implication

If Σ is EUF-CMA secure, then ACP is secure against existential forgery.

In other words:

Breaking ACP implies breaking the underlying signature.

4.8 What This Proof Does Not Cover

This reduction only covers:

✔ Cryptographic forgery
✔ Token integrity

Does not cover:

Replay (requires stateful model)

Policy downgrade

Side-channel

Issuer compromise

Atomicity

That belongs to system security, not the cryptographic primitive.

4.9 Formal Conclusion

Under the assumption that:

Σ is EUF-CMA secure

Encode is deterministic and unambiguous

Hash is collision-resistant

ACP is cryptographically as secure as the underlying signature.

The reduction is direct and tight.
