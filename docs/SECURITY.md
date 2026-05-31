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
- **Range proof** by bit decomposition: each bit is committed and proven to be 0 or
  1 by an OR proof, with the per-bit blindings fixed so the bits provably re-sum to
  the committed value. Therefore the value lies in `[0, 2^bits)`.
- **Conservation**: a Schnorr proof that the net commitment of inputs minus outputs
  has no `G` component, i.e. value is conserved, revealing neither amounts nor the
  excess blinding.

**These are sound and zero-knowledge under the discrete-log assumption in the
random-oracle model.** They are explicitly:

- **NOT zk-STARKs** — no AIR/FRI, no transparent post-quantum argument.
- **NOT Bulletproofs** — no inner-product argument, no logarithmic aggregation. The
  range proof is **linear** in the bit-width.
- **No trusted setup**, **no post-quantum** claim.

We chose to ship a real, sound, honestly-named sigma-protocol rather than a stub
labelled "STARK" or "Bulletproof". Where a primitive could not be made sound from
scratch on the SDK alone, it is absent, not faked.

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
