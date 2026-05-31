# Architecture

AnchorChain is a bottom-up monorepo. Every layer terminates its verification in the
layer below and ultimately in the BSV block-header chain. Packages are strict
TypeScript project references (`tsc -b`), tested with Node's built-in runner on
type-stripped sources, consumed through their compiled `dist`.

## Layers

### chain — `bsv`
The only package that touches `@bsv/sdk`. Wraps secp256k1 (scalars as `bigint`,
points opaque), the nothing-up-my-sleeve Pedersen generator `H`, ECDSA
(sign/verify, low-s), hashes (internal vs display byte order), post-Genesis script
and transactions, the 80-byte header, the validating `HeaderChain` (the trust
root), the `OP_FALSE OP_RETURN` data carrier (no size cap post-Genesis), and node
clients (offline fixtures + a Teranode transport).

### commit — `hashing`, `schema`, `merkle`, `shard`
Memory-leaf hashing binds an atom to its provenance context. The canonical schema
makes a dimension/type/field difference always change the hash. The Merkle tree
(leaf = double-SHA-256 of the item; node = double-SHA-256 of children; odd
self-pairing) produces the batch root, verified against the header chain.
Proof-sharding implements selective disclosure (not ZK).

### anchor — `memstore`, `anchor`, `file`
An append-only batch log closes batches on a count/interval policy; the anchorer
embeds a batch root in an OP_RETURN carrier transaction (idempotent per batch id),
produces reference proofs, and recovers the root from a raw anchor tx. Files are
chunked deterministically, committed to a file Merkle root, and selectively
disclosed chunk-by-chunk with CAS rehash-binding.

### verify — `proofentity`, `proofstore`, `provenance`
The proof entity is the presentable inclusion credential, verified header-only. The
proof store is durable, availability-only, content-addressed with rehash-binding on
every read. The provenance graph binds identity → object → anchor, supports
verifiable cross-agent recall, and tracks derivation lineage across agents.

### confidential — `privacy`
Pedersen commitments, homomorphic conservation, and sound Fiat-Shamir
sigma-protocol range and membership proofs, plus a metadata-obfuscation mode. See
[SECURITY.md](SECURITY.md) for exact strength and honest labelling.

### authority — `custody`, `identity`
Shamir-reconstruction key custody with an anchorable rotation/revocation lifecycle;
anchorable UUID↔public-key identity binding, replay-hardened challenge-response, and
non-transferable entitlements.

### metering — `credit`, `settlement`
A confidential quota/credit ledger with exactly-once debits (no double-spend), an
anchorable hash chain, overdraft-impossibility (range proof) and conservation; and
per-op vs periodic settlement with an exact homomorphic equivalence property.

### surface — `api`, `cli`, `bench`
`api` exposes typed config, the end-to-end self-test, the deterministic studies, and
reproduction/verification of committed vectors. `cli` exposes `selftest`,
`reproduce`, and `bench`. `bench` measures live timings (host-dependent) and exact
structural sizes (deterministic).

## Determinism and CI

`npm run reproduce` regenerates every deterministic artifact (schema fingerprint, a
fixed memory leaf, a fixed Merkle root, the anchor blob, and all studies) and
compares it field-by-field to `vectors/anchorchain/repro_v1.json`. CI runs the scan,
format check, strict build, full test suite, selftest, reproduce, and a bench smoke
point — every step gating on a non-zero exit.

## Constraints honoured

BSV-only, post-Genesis; no fork ticker, altcoin/ecosystem name, foreign minor-unit
name, or build-tool identity appears anywhere (enforced by `scripts/forbidden-scan.mjs`
over content, filenames, and commit messages). No fabricated number, fee, or chain
fixture; any on-chain data in a test is genuine.
