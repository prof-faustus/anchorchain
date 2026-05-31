// Thin unwrapping adapters over the Result-returning merkle/shard APIs, for the
// self-test and studies where inputs are known-good and a failure is a genuine bug.
import type { Hash } from '@anchorchain/bsv';
import { hashLeaf as hl, merkleRoot as mr, merkleProof as mp, verifyProof } from '@anchorchain/merkle';
import type { MerkleProof } from '@anchorchain/merkle';
import { proofAssistance as pa, shardProof as sp } from '@anchorchain/shard';
import type { ProofAssistance, ProofShard } from '@anchorchain/shard';

export { verifyProof };
export const hashLeaf = hl;

export function merkleRoot(leaves: Hash[]): Hash {
  const r = mr(leaves);
  if (!r.ok) throw new Error('merkleRoot: ' + r.error.message);
  return r.value;
}
export function merkleProof(leaves: Hash[], index: number): MerkleProof {
  const r = mp(leaves, index);
  if (!r.ok) throw new Error('merkleProof: ' + r.error.message);
  return r.value;
}
export function proofAssistance(leaves: Hash[], level: number): ProofAssistance {
  const r = pa(leaves, level);
  if (!r.ok) throw new Error('proofAssistance: ' + r.error.message);
  return r.value;
}
export function shardProofLevel(proof: MerkleProof, level: number): { lower: ProofShard; upper: ProofShard } {
  const r = sp(proof, level);
  if (!r.ok) throw new Error('shardProof: ' + r.error.message);
  return r.value;
}
