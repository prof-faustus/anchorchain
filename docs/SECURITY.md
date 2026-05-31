# Security model and honest labelling

This document states precisely what AnchorChain's cryptography does and does not
provide. Where a primitive is weaker than a casual name would imply, it is named
weakly here on purpose.

## Trust root

All verification terminates in a validated BSV block-header chain (`HeaderChain`):
prev-hash linkage, proof-of-work against `bits`, monotonic height. An inclusion
proof is only as strong as the header chain it terminates in. AnchorChain verifies
**header-only** (SPV) — it never trusts a full block or a node's say-so for
inclusion; it reconstructs a Merkle root from a leaf and path and matches it to the
root a header commits to.

## SPV: the OP_RETURN two-tree proof

The batch Merkle root `R` is carried in the anchor transaction's OP_RETURN; the
anchor transaction is itself a leaf of the BLOCK's Merkle tree. So a complete proof
that a memory is anchored is a TWO-tree proof, performed by `AnchorChainService`:

1. the memory leaf is in the batch tree with root `R` (batch Merkle path);
2. `R` is present in the anchor transaction (parse its OP_RETURN);
3. the anchor transaction's txid is in the block (txid → block-Merkle branch);
4. the block's Merkle root is the one its header commits to, in the header chain.

The lower-level `proofentity` helper verifies a single tree (leaf → root → header)
and is correct for the "leaves are the block's transactions" case; it deliberately
does NOT model the OP_RETURN indirection. Use the service for end-to-end anchoring.

## Inclusion proofs are NOT zero-knowledge

- A **plain** Merkle inclusion proof reveals the leaf and its sibling path.
- **Proof-sharding selective disclosure** (`shard`) reveals the disclosed lower
  portion of the path plus public proof-assistance labels. It hides the undisclosed
  portion **by structure**, not cryptographically. It MUST NOT be called
  zero-knowledge.

The optional homomorphic compression of assistance labels (`homomorphicAssistanceSum`)
is a **trusted-environment** convenience only. The audit verification path
(`verifyWithAssistance`) never accepts it; `auditRefusesTrusted` is explicit about
this.

## Zero-knowledge: scope and exact strength

Zero-knowledge is provided ONLY for **confidential amounts** in `privacy` (used by
`credit` and `settlement`). All proofs are **Fiat-Shamir sigma-protocols** over
secp256k1:

- **Schnorr** proof of knowledge of a discrete log.
- **CDS one-out-of-many OR** (membership, and per-bit bit-ness).
- **Range proof**, two interchangeable constructions for `[0, 2^bits)`:
  - *linear* (`proveRange`) — bit decomposition with a per-bit OR proof; size grows
    linearly in `bits`;
  - *logarithmic* (`proveRangeBP`) — a genuine **Bulletproof** (Bunz-Bootle-Boneh
    inner-product argument); size grows as `log2(bits)`. At 64 bits the linear proof
    is 192 group elements / 256 scalars vs the Bulletproof's 16 / 5. Both are sound;
    the Bulletproof has **no trusted setup** and makes **no post-quantum claim**.
- **Conservation**: a Schnorr proof that the net commitment of inputs minus outputs
  has no `G` component, i.e. value is conserved, revealing neither amounts nor the
  excess blinding.

**These are sound and zero-knowledge under the discrete-log assumption in the
random-oracle model.** They are explicitly:

- **NOT zk-STARKs** — no AIR/FRI, no transparent post-quantum argument.
- **NOT Bulletproofs** — no inner-product argument, no logarithmic aggregation. The
  range proof is **linear** in the bit-width.
- **No trusted setup**, **no post-quantum** claim.

## Not delivered: zk-STARK

There is **no zk-STARK** in AnchorChain, and there is no plan to fake one. A sound
STARK (AIR arithmetisation, FRI low-degree test, the full transparent argument)
cannot be implemented correctly and safely from scratch on `@bsv/sdk` within this
project's scope; shipping a toy labelled "STARK" would be dishonest. The wide-value
performance problem a STARK might address is instead solved by the **Bulletproof**
range proof above, which is real and verifier-checked. The transparent,
post-quantum properties a STARK would add are simply not claimed anywhere.

We chose to ship real, sound, honestly-named proofs rather than a stub. Where a
primitive could not be made sound from scratch on the SDK alone — the STARK, and
threshold ECDSA — it is absent or replaced by an honestly-labelled alternative, not
faked.

## Pedersen generator H

Pedersen commitments use `C(v,r) = v*G + r*H`. Binding requires that `log_G(H)` is
unknown; otherwise a committer could open a commitment two ways. `H` is derived by a
**nothing-up-my-sleeve** hash-to-curve (try-and-increment) from the fixed domain
string `AnchorChain/pedersen/H/v1` — nobody knows its discrete log w.r.t. `G`.

## Key custody is reconstruction, not threshold

`custody` splits a key with Shamir secret sharing and signs by **reconstructing** it
from a threshold of shares, then discarding it. There is a moment inside `sign()`
when the full private key exists in memory. This is:

- **NOT threshold ECDSA** and **NOT multi-party computation** — the key is not kept
  distributed through signing.
- A party that gathers a threshold of shares **can recover the key**.

The property provided is "fewer than `t` shares reveal nothing about the key", plus
an anchorable rotation/revocation lifecycle. Rotation invalidates old shares for
signing (they no longer reconstruct the current public key); revocation halts it.

### Threshold Schnorr (no reconstruction)

As a separate, honestly-distinct primitive, `custody` also offers **threshold
Schnorr** signing in which the key is **never reconstructed**: each party emits a
partial signature `s_j = k_j + e·λ_j·x_j` over the aggregated nonce, and the sum is
a valid Schnorr signature because `Σ λ_j x_j = x`. No party ever holds more than its
own share times a public Lagrange coefficient. Nonces are committed in round one to
prevent adaptive choice within a session. This is genuinely "key never exists" — for
SCHNORR. It is **not** threshold ECDSA (which is not attempted), and it is not
hardened for concurrent sessions (that needs the full FROST two-nonce construction);
sign one session at a time.

## Identity and entitlements

Authentication is challenge-response, replay-hardened on three axes: an ECDSA
**signature** over `uuid || nonce || expiry`, a **single-use nonce**, and a
**logical-time expiry**. Entitlements are **non-transferable**: an entitlement names
its holder's UUID and can only be exercised with a fresh authenticated response from
that UUID — a foreign identity is rejected, and a forged response fails the
signature check.

## Confidentiality discipline

No secret, key, key-share, vector content, file content, cleartext amount, or proof
witness is ever logged anywhere in the codebase.

## What is out of scope

AnchorChain secures existence, integrity, identity, and time of committed memories
and files. It does not address model behaviour, data poisoning, prompt injection, or
the correctness of the embeddings themselves.
