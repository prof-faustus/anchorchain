// Three reproducible studies. Each reports DETERMINISTIC structural quantities
// (sizes, counts, booleans) computed from the real proof objects — never a timing,
// throughput, or any figure that would vary by host or run. `reproduce` regenerates
// these and checks them byte-for-byte against the committed vector.
import { reduceScalar, doubleSha256 } from '@anchorchain/bsv';
import type { Scalar } from '@anchorchain/bsv';
import { proveRange } from '@anchorchain/privacy';
import { hashLeaf, merkleRoot, merkleProof, proofAssistance, shardProofLevel } from './internal-merkle.js';
import { disclosedBytes } from '@anchorchain/shard';
import { settle, equivalent } from '@anchorchain/settlement';

// Deterministic scalar from a label, so studies are reproducible across runs.
function detScalar(label: string): Scalar {
  const s = reduceScalar(doubleSha256(new TextEncoder().encode('anchorchain/study/' + label)));
  return s === 0n ? 1n : s;
}

export interface RangeSizeRow {
  bits: number;
  groupElements: number;
  scalars: number;
}
export interface DisclosureRow {
  leaves: number;
  level: number;
  fullProofBytes: number;
  disclosedLowerBytes: number;
  savedBytes: number;
}
export interface EquivalenceRow {
  ops: number;
  perOpRecords: number;
  periodicRecords: number;
  equivalent: boolean;
}
export interface Studies {
  rangeProofSize: RangeSizeRow[];
  selectiveDisclosure: DisclosureRow[];
  settlementEquivalence: EquivalenceRow;
}

function rangeRow(bits: number): RangeSizeRow {
  const r = proveRange(7n % (1n << BigInt(bits)), detScalar('range/' + bits), bits);
  if (!r.ok) throw new Error('range study');
  const groupElements = r.proof.bitCommits.length + r.proof.bitProofs.reduce((a, p) => a + p.a.length, 0);
  const scalars = r.proof.bitProofs.reduce((a, p) => a + p.e.length + p.s.length, 0);
  return { bits, groupElements, scalars };
}

function disclosureRow(level: number): DisclosureRow {
  const leaves = Array.from({ length: 1024 }, (_, i) => hashLeaf(Uint8Array.of(i & 0xff, (i >> 8) & 0xff)));
  void merkleRoot(leaves);
  const proof = merkleProof(leaves, 511);
  const { lower } = shardProofLevel(proof, level);
  void proofAssistance(leaves, level);
  const fullProofBytes = 12 + proof.siblings.length * 32;
  const disclosedLowerBytes = disclosedBytes({ leaf: leaves[511]!, leafIndex: 511, lower });
  return { leaves: 1024, level, fullProofBytes, disclosedLowerBytes, savedBytes: fullProofBytes - disclosedLowerBytes };
}

function equivalenceRow(): EquivalenceRow {
  const ops = Array.from({ length: 12 }, (_, i) => ({ agentId: i % 3 === 0 ? 'A' : i % 3 === 1 ? 'B' : 'C', amount: BigInt((i % 5) + 1), blinding: detScalar('settle/' + i), logicalTime: BigInt(i) }));
  const perOp = settle(ops, 'per-op');
  const periodic = settle(ops, 'periodic', 4n);
  return { ops: ops.length, perOpRecords: perOp.records.length, periodicRecords: periodic.records.length, equivalent: equivalent(perOp, periodic) };
}

export function runStudies(): Studies {
  return {
    rangeProofSize: [8, 16, 32].map(rangeRow),
    selectiveDisclosure: [2, 4, 6].map(disclosureRow),
    settlementEquivalence: equivalenceRow(),
  };
}
