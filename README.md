# AnchorChain

Immutable referencing of AI memory states through Bitcoin (BSV) blockchain-indexed
volumetric data linking — with file linking and selective disclosure, an AI credit
system bound to the same chain, and a hardened metering authority.

AnchorChain commits AI memory atoms (and files) as Merkle leaves, anchors each
batch's root in a BSV transaction (post-Genesis OP_RETURN data carrier), and lets
anyone verify, header-only (SPV), that a remembered item existed, unaltered, at a
given time — terminating in the validated BSV block-header chain, the trust root.

## Inclusion proofs: what each reveals

There are **two** inclusion-proof forms, and **neither is zero-knowledge**:

- **plain** — a Merkle inclusion proof: tamper-evident inclusion that **reveals**
  the leaf and its sibling path.
- **shard** — proof-sharding selective disclosure (patents WO 2022/100946,
  WO 2025/119666): discloses only the queried lower portion plus public
  proof-assistance labels, hiding the rest **by structure**. This is selective
  disclosure, **not** zero-knowledge — it reveals the disclosed portion and the
  public labels.

There is no implemented path that hides the identity of a memory leaf while proving
its inclusion. If you need that, it is future work, not a feature here.

## Where zero-knowledge actually appears

Zero-knowledge in AnchorChain is confined to **confidential amounts** in the credit
and settlement layers, via Pedersen commitments built from scratch on the BSV SDK's
secp256k1:

- a **range proof** in two forms — a linear sigma-protocol (bit decomposition +
  per-bit OR) and a genuine **Bulletproof** (inner-product argument) whose size is
  **logarithmic** in the bit-width (at 64 bits: 16 group elements vs the linear
  proof's 192 — see [BENCHMARKS.md](BENCHMARKS.md));
- a **membership proof** (one-out-of-many) — a committed value is in a public set
  without revealing which; also used for set-obfuscated metadata;
- **homomorphic conservation** — the books balance without revealing any amount.

**Honest labelling.** These are sound under discrete log in the random-oracle model,
with **no trusted setup** and **no post-quantum claim**. The Bulletproof is a real
Bulletproof; the rest are sigma-protocols. There is **no zk-STARK** — a sound one
cannot be built honestly from scratch here, so it is not claimed (see
[docs/SECURITY.md](docs/SECURITY.md)).

## What it secures, and what it does not

AnchorChain secures the **integrity of what was remembered** — existence,
integrity, identity, and time of a committed memory/file. It does **not** secure
model behaviour, data poisoning, or prompt injection. Key custody is **Shamir
reconstruction**, not threshold ECDSA: the key is reassembled to sign, then
discarded. A separate **threshold Schnorr** mode signs *without* reconstructing the
key (sound for Schnorr, explicitly not threshold ECDSA). See
[docs/SECURITY.md](docs/SECURITY.md).

## Using it

`AnchorChainService` drives the whole workflow — append a memory → a batch closes →
anchor it in an OP_RETURN transaction → confirm it in a block → verify inclusion
header-only with the correct two-tree (batch + block) SPV proof → recall it
cross-agent. The durable `proofstore` `FileBackend` and the `memstore`/`credit`
snapshots persist state across restarts. The entire public surface is re-exported
from `@anchorchain/api`.

## Packages

Built bottom-up; each layer terminates its verification in the one below, and
ultimately in the header chain.

| layer | packages |
| --- | --- |
| chain | `bsv` (hash, secp256k1, ECDSA, script, tx, header chain, OP_RETURN carrier, node client) |
| commit | `hashing`, `schema`, `merkle`, `shard` |
| anchor | `memstore`, `anchor`, `file` |
| verify | `proofentity`, `proofstore`, `provenance` |
| confidential | `privacy` (Pedersen + sigma-protocol ZK) |
| authority | `custody`, `identity` |
| metering | `credit`, `settlement` |
| surface | `api`, `cli`, `bench` |

## Build and verify

```
npm ci
npm run build        # strict tsc -b across all packages
npm run lint         # format check + BSV-only / no-tool-identity scan
npm test             # full unit suite
npm run selftest     # end-to-end exercise of every layer
npm run reproduce    # regenerate + verify all deterministic vectors and studies
npm run bench        # live micro-benchmarks (host-dependent timings, exact sizes)
```

BSV is the entire technical universe, post-Genesis. The sole chain/crypto
dependency is the BSV SDK. Every number comes from `bench`/`reproduce` at run time
on the host that produced it; no figure is fabricated, and any on-chain fixture used
in a test is genuine.
