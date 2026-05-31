# AnchorChain

Immutable referencing of AI memory states through Bitcoin (BSV) blockchain-indexed
volumetric data linking — with file linking and selective disclosure, an AI credit
system bound to the same chain, and a hardened metering authority.

AnchorChain commits AI memory atoms (and files) as Merkle leaves, anchors each
batch's root in a BSV transaction (post-Genesis OP_RETURN data carrier), and lets
anyone verify, header-only (SPV), that a remembered item existed, unaltered, at a
given time — terminating in the validated BSV block-header chain, the trust root.

## Three proof paths (what each reveals — see [docs/SECURITY.md](docs/SECURITY.md))

- **plain** — a Merkle inclusion proof: tamper-evident inclusion that **reveals**
  the leaf and its sibling path. This is **not** zero-knowledge.
- **shard** — proof-sharding selective disclosure (patents WO 2022/100946,
  WO 2025/119666): discloses only the queried portion plus public proof-assistance
  labels, hiding the rest **by structure**. This is selective disclosure, **not**
  zero-knowledge.
- **zk** — a zero-knowledge proof (the only path that may be called ZK): reveals
  nothing about the leaf.

Confidential credit amounts use Pedersen commitments with a zero-knowledge range
proof; balances are conserved homomorphically.

## What it secures, and what it does not

AnchorChain secures the **integrity of what was remembered** — existence,
integrity, identity, and time of a committed memory/file. It does **not** secure
model behaviour, data poisoning, or prompt injection (paper §VII.F).

## Build

```
npm ci
npm run build
npm run lint
npm test
node packages/cli/dist/index.js selftest
node packages/cli/dist/index.js reproduce
```

BSV is the entire technical universe, post-Genesis. The sole chain/crypto
dependency is the BSV SDK. All reported numbers come from `bench`/`reproduce` on
stated hardware; the paper's capacity figures appear only as attributed claims in
the docs.
