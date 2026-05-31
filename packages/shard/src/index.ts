// Proof-sharding selective disclosure (WO 2022/100946, WO 2025/119666). A proof
// is divided into NON-OVERLAPPING, GAPLESS portions; proof-assistance labels are
// published at a predetermined tree level; a verifier completes the inclusion
// check from the disclosed lower portion plus the public assistance labels,
// WITHOUT the other portions, terminating in the BSV header chain. This is
// selective disclosure BY STRUCTURE — it is NOT zero-knowledge (it reveals the
// disclosed portion and the public labels).
import type { Hash, Txid, VerifyResult, Result, HeaderChain, Scalar } from '@anchorchain/bsv';
import { HashOps, TxidOps, toHexLower, ok, err, verifyOk, verifyFail, doubleSha256, reduceScalar, pointMulG, pointAdd, pointToHex } from '@anchorchain/bsv';
import type { MerkleProof } from '@anchorchain/merkle';
import { buildTree, hashNode } from '@anchorchain/merkle';

export type ShardError =
  | { kind: 'BadLevel'; message: string; level: number; height: number }
  | { kind: 'NonContiguous'; message: string }
  | { kind: 'EmptyLeaves'; message: string };

export type ShardVerifyReason =
  | { kind: 'AssistanceMismatch' }
  | { kind: 'AssistanceRootMismatch' }
  | { kind: 'RootNotAnchored' }
  | { kind: 'TrustedModeRefused' };

// IndexKey (the patent's object/transaction attributes).
export type Direction = 'input' | 'output';
export interface IndexKey {
  txid: Txid;
  direction: Direction;
  position: number;
  blockPosition: number;
  lockingScriptHex?: string;
  unlockingScriptHex?: string;
  amountMinorUnits?: bigint;
}
export function serializeKey(k: IndexKey): string {
  const u32 = (n: number) => (n >>> 0).toString(16).padStart(8, '0');
  return [
    't:' + toHexLower(TxidOps.toInternalBytes(k.txid)),
    'd:' + (k.direction === 'input' ? '0' : '1'),
    'p:' + u32(k.position),
    'b:' + u32(k.blockPosition),
    'l:' + (k.lockingScriptHex ?? '-'),
    'u:' + (k.unlockingScriptHex ?? '-'),
    'a:' + (k.amountMinorUnits !== undefined ? k.amountMinorUnits.toString(16) : '-'),
  ].join('|');
}

export interface ProofShard {
  fromLevel: number;
  toLevel: number;
  siblings: Hash[];
}
export interface ProofAssistance {
  predeterminedLevel: number;
  nodeLabels: Hash[];
}
export interface DisclosedPortion {
  leaf: Hash;
  leafIndex: number;
  lower: ProofShard; // levels [0, predeterminedLevel)
}

// Split a proof into a lower [0, level) and upper [level, height) portion. The two
// are non-overlapping and gapless and together cover the whole proof.
export function shardProof(proof: MerkleProof, level: number): Result<{ lower: ProofShard; upper: ProofShard }, ShardError> {
  const height = proof.siblings.length;
  if (level <= 0 || level >= height) return err({ kind: 'BadLevel', message: `level ${level} out of (0, ${height})`, level, height });
  return ok({
    lower: { fromLevel: 0, toLevel: level, siblings: proof.siblings.slice(0, level) },
    upper: { fromLevel: level, toLevel: height, siblings: proof.siblings.slice(level, height) },
  });
}

// Reassemble portions (sorted, contiguity + full coverage checked).
export function reassemble(index: number, shards: ProofShard[]): Result<MerkleProof, ShardError> {
  const sorted = [...shards].sort((a, b) => a.fromLevel - b.fromLevel);
  let expect = 0;
  let siblings: Hash[] = [];
  for (const s of sorted) {
    if (s.fromLevel !== expect || s.siblings.length !== s.toLevel - s.fromLevel) return err({ kind: 'NonContiguous', message: 'gap/overlap in shards' });
    siblings = siblings.concat(s.siblings);
    expect = s.toLevel;
  }
  return ok({ index, siblings });
}

// The proof-assistance: the node labels at the predetermined level of the tree.
export function proofAssistance(leaves: Hash[], level: number): Result<ProofAssistance, ShardError> {
  const tree = buildTree(leaves);
  if (!tree.ok) return err({ kind: 'EmptyLeaves', message: 'no leaves' });
  if (level <= 0 || level >= tree.value.levels.length) return err({ kind: 'BadLevel', message: `level ${level}`, level, height: tree.value.levels.length - 1 });
  return ok({ predeterminedLevel: level, nodeLabels: (tree.value.levels[level] as Hash[]).map((h) => h) });
}

export function labelsHashToRoot(a: ProofAssistance, root: Hash): VerifyResult<ShardVerifyReason> {
  let current = a.nodeLabels;
  while (current.length > 1) {
    const next: Hash[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const l = current[i] as Hash;
      const r = (i + 1 < current.length ? current[i + 1] : current[i]) as Hash;
      next.push(hashNode(l, r));
    }
    current = next;
  }
  return HashOps.equals(current[0] as Hash, root) ? verifyOk() : verifyFail({ kind: 'AssistanceRootMismatch' });
}

// SELECTIVE DISCLOSURE: complete the inclusion check from the disclosed lower
// portion plus the public assistance labels, terminating in the header chain.
export function verifyWithAssistance(disclosed: DisclosedPortion, assistance: ProofAssistance, root: Hash, headerChain: HeaderChain): VerifyResult<ShardVerifyReason> {
  let cur = disclosed.leaf;
  let idx = disclosed.leafIndex;
  for (const sib of disclosed.lower.siblings) {
    cur = (idx & 1) === 0 ? hashNode(cur, sib) : hashNode(sib, cur);
    idx = idx >> 1;
  }
  const labelPos = disclosed.leafIndex >> assistance.predeterminedLevel;
  const label = assistance.nodeLabels[labelPos];
  if (label === undefined || !HashOps.equals(cur, label)) return verifyFail({ kind: 'AssistanceMismatch' });
  const lr = labelsHashToRoot(assistance, root);
  if (!lr.ok) return lr;
  if (headerChain.containsMerkleRoot(root) === undefined) return verifyFail({ kind: 'RootNotAnchored' });
  return verifyOk();
}

// Bytes a verifier receives for the assisted (disclosed) flow vs a full proof.
export function disclosedBytes(d: DisclosedPortion): number {
  return 12 + d.lower.siblings.length * 32;
}

// ---- OPTIONAL trusted-mode homomorphic compression of the assistance data ----
// A sum of secp256k1 points, each representing a node at the predetermined level.
// This is the trusted-environment option ONLY: never the default, and the audit
// verification path (verifyWithAssistance) NEVER accepts it.
export function homomorphicAssistanceSum(assistance: ProofAssistance): string {
  let acc: ReturnType<typeof pointMulG> | undefined;
  for (const label of assistance.nodeLabels) {
    const s: Scalar = reduceScalar(doubleSha256(HashOps.toInternalBytes(label)));
    const p = pointMulG(s === 0n ? 1n : s);
    acc = acc === undefined ? p : pointAdd(acc, p);
  }
  return acc === undefined ? '' : pointToHex(acc);
}
export function verifyTrustedCompression(assistance: ProofAssistance, expectedSumHex: string): VerifyResult<ShardVerifyReason> {
  return homomorphicAssistanceSum(assistance) === expectedSumHex ? verifyOk() : verifyFail({ kind: 'TrustedModeRefused' });
}
// The audit path refuses the trusted mode by construction.
export function auditRefusesTrusted(): VerifyResult<ShardVerifyReason> {
  return verifyFail({ kind: 'TrustedModeRefused' });
}
