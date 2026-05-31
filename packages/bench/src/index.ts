// Runtime micro-benchmarks. EVERY number this module reports is measured live on
// the machine it runs on; nothing is hard-coded, asserted against a fixed target,
// or claimed as a headline throughput. A figure here is only meaningful relative to
// the host that produced it. Sizes (group elements / scalars) ARE deterministic and
// are reported as exact counts, not estimates.
import { hashLeaf, merkleRoot, merkleProof } from '@anchorchain/merkle';
import { proofAssistance, shardProof, disclosedBytes } from '@anchorchain/shard';
import { commit, proveRange, verifyRange, proveMembership, verifyMembership, randScalar } from '@anchorchain/privacy';

export interface TimingResult {
  name: string;
  iterations: number;
  totalMs: number;
  perOpMs: number; // host-dependent; not a published throughput
}

export interface SizeResult {
  name: string;
  unit: string;
  value: number; // deterministic structural size
}

export interface BenchReport {
  host: { node: string; platform: string; arch: string };
  timings: TimingResult[];
  sizes: SizeResult[];
  note: string;
}

function time(name: string, iterations: number, fn: () => void): TimingResult {
  const start = performance.now();
  for (let i = 0; i < iterations; i++) fn();
  const totalMs = performance.now() - start;
  return { name, iterations, totalMs, perOpMs: totalMs / iterations };
}

export interface BenchOptions {
  ci?: boolean; // a small, fast iteration count for CI smoke-running
}

export function runBench(opts: BenchOptions = {}): BenchReport {
  const n = opts.ci ? 8 : 200;
  const bits = 16;

  // fixed inputs so the WORK is identical across runs (only timing varies)
  const blinding = randScalar();
  const value = 12_345n % (1n << BigInt(bits));
  const set = [1n, 2n, 3n, 4n, 5n, 6n, 7n, value];
  const cValue = commit(value, blinding);

  const leaves = Array.from({ length: 1024 }, (_, i) => hashLeaf(Uint8Array.of(i & 0xff, (i >> 8) & 0xff)));

  const timings: TimingResult[] = [
    time('range.prove(16b)', n, () => void proveRange(value, blinding, bits)),
    (() => {
      const rp = proveRange(value, blinding, bits);
      if (!rp.ok) throw new Error('range');
      return time('range.verify(16b)', n, () => void verifyRange(rp.commitment, rp.proof));
    })(),
    time('membership.prove(|S|=8)', n, () => void proveMembership(cValue, blinding, set, value)),
    (() => {
      const mp = proveMembership(cValue, blinding, set, value);
      if (!mp.ok) throw new Error('membership');
      return time('membership.verify(|S|=8)', n, () => void verifyMembership(cValue, set, mp.proof));
    })(),
    time('merkle.root(1024)', Math.max(1, n >> 2), () => void merkleRoot(leaves)),
  ];

  // deterministic sizes
  const rp = proveRange(value, blinding, bits);
  const fullProof = merkleProof(leaves, 500);
  const sizes: SizeResult[] = [];
  if (rp.ok) {
    sizes.push({ name: 'range.proof.bitCommitments', unit: 'group elements', value: rp.proof.bitCommits.length });
    sizes.push({ name: 'range.proof.scalars', unit: 'scalars', value: rp.proof.bitProofs.reduce((a, p) => a + p.e.length + p.s.length, 0) });
  }
  if (fullProof.ok) {
    const level = 4;
    const lower = shardProof(fullProof.value, level);
    const assist = proofAssistance(leaves, level);
    sizes.push({ name: 'merkle.proof.full', unit: 'bytes', value: 12 + fullProof.value.siblings.length * 32 });
    if (lower.ok && assist.ok) {
      sizes.push({ name: 'merkle.proof.disclosedLower', unit: 'bytes', value: disclosedBytes({ leaf: leaves[500]!, leafIndex: 500, lower: lower.value.lower }) });
    }
  }

  return {
    host: { node: process.version, platform: process.platform, arch: process.arch },
    timings,
    sizes,
    note: 'Timings are wall-clock on the host above and are NOT a published throughput. Sizes are exact structural counts.',
  };
}

export function formatReport(r: BenchReport): string {
  const lines: string[] = [];
  lines.push(`host: node ${r.host.node} ${r.host.platform}/${r.host.arch}`);
  lines.push('timings (host-dependent):');
  for (const t of r.timings) lines.push(`  ${t.name}: ${t.perOpMs.toFixed(4)} ms/op over ${t.iterations} iters`);
  lines.push('sizes (deterministic):');
  for (const s of r.sizes) lines.push(`  ${s.name}: ${s.value} ${s.unit}`);
  lines.push(r.note);
  return lines.join('\n');
}
