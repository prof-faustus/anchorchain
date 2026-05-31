# Benchmarks

These figures were measured live by `npm run bench` (the `bench` package). **Timings are wall-clock on the single host below and are NOT a published throughput** — they will differ on other hardware and are provided only for relative comparison. **Sizes are exact, deterministic structural counts** and are reproducible on any host.

## Host

| field | value |
| --- | --- |
| date | 2026-05-31 |
| node | v24.16.0 |
| platform | win32/x64 |
| cpu | Intel(R) Xeon(R) Gold 6430 |
| cores | 64 |

## Timings (host-dependent)

| operation | ms/op | iterations |
| --- | --- | --- |
| range.prove(16b) | 78.5240 | 200 |
| range.verify(16b) | 65.3520 | 200 |
| membership.prove(|S|=8) | 15.3058 | 200 |
| membership.verify(|S|=8) | 15.8041 | 200 |
| merkle.root(1024) | 10.0273 | 50 |

## Sizes (deterministic)

| metric | value | unit |
| --- | --- | --- |
| range.proof.bitCommitments | 16 | group elements |
| range.proof.scalars | 64 | scalars |
| merkle.proof.full | 332 | bytes |
| merkle.proof.disclosedLower | 140 | bytes |

## Range proof: linear vs Bulletproof (deterministic)

From the reproducible studies (`runStudies().rangeProofComparison`). The linear bit-decomposition proof grows with the bit-width; the Bulletproof grows logarithmically.

| bits | linear group elements | linear scalars | Bulletproof group elements | Bulletproof scalars |
| --- | --- | --- | --- | --- |
| 8 | 24 | 32 | 10 | 5 |
| 16 | 48 | 64 | 12 | 5 |
| 32 | 96 | 128 | 14 | 5 |
| 64 | 192 | 256 | 16 | 5 |

Reproduce with: `npm run bench` (timings) and `npm run reproduce` (sizes/studies).
