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
and settlement layers, via Pedersen commitments and **Fiat-Shamir sigma-protocol**
proofs built from scratch on the BSV SDK's secp256k1:

- a **range proof** (bit decomposition + per-bit OR) — a balance is non-negative
  without revealing it;
- a **membership proof** (one-out-of-many) — a committed value is in a public set
  without revealing which;
- **homomorphic conservation** — the books balance without revealing any amount.

**Honest labelling.** These are sigma-protocol ZK proofs, sound under discrete log
in the random-oracle model, and **linear** in their statement. They are **not**
zk-STARKs and **not** Bulletproofs: no trusted setup, no logarithmic aggregation, no
post-quantum claim. They are real and verifier-checked — see
[docs/SECURITY.md](docs/SECURITY.md).

## What it secures, and what it does not

AnchorChain secures the **integrity of what was remembered** — existence,
integrity, identity, and time of a committed memory/file. It does **not** secure
model behaviour, data poisoning, or prompt injection. Key custody is **Shamir
reconstruction**, not threshold ECDSA: the key is reassembled to sign, then
discarded (see [docs/SECURITY.md](docs/SECURITY.md)).

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
