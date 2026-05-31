// Merkle batch tree. A leaf is the double-SHA-256 of its data item; an internal
// node is the double-SHA-256 of its concatenated children (internal byte order);
// at an odd level the last node is paired with itself. The root is the batch
// fingerprint R. Verification terminates in the BSV header chain.
import type { Hash, VerifyResult, Result, HeaderChain } from '@anchorchain/bsv';
import { doubleSha256, HashOps, concat, ok, err, verifyOk, verifyFail } from '@anchorchain/bsv';

export type MerkleError =
  | { kind: 'EmptyLeaves'; message: string }
  | { kind: 'IndexOutOfRange'; message: string; index: number; leafCount: number };

export type MerkleVerifyReason = { kind: 'RootMismatch' } | { kind: 'RootNotAnchored' } | { kind: 'NoHeaderAtHeight' };

export interface MerkleProof {
  index: number;
  siblings: Hash[];
}
export interface MerkleTree {
  root: Hash;
  levels: Hash[][];
}

export function hashLeaf(dataItem: Uint8Array): Hash {
  return doubleSha256(dataItem);
}
export function hashNode(left: Hash, right: Hash): Hash {
  return doubleSha256(concat(HashOps.toInternalBytes(left), HashOps.toInternalBytes(right)));
}

function nextLevel(current: readonly Hash[]): Hash[] {
  const next: Hash[] = [];
  for (let i = 0; i < current.length; i += 2) {
    const l = current[i] as Hash;
    const r = (i + 1 < current.length ? current[i + 1] : current[i]) as Hash;
    next.push(hashNode(l, r));
  }
  return next;
}

export function buildTree(leaves: Hash[]): Result<MerkleTree, MerkleError> {
  if (leaves.length === 0) return err({ kind: 'EmptyLeaves', message: 'no leaves' });
  const levels: Hash[][] = [leaves.map((l) => l)];
  let current = levels[0] as Hash[];
  while (current.length > 1) {
    const n = nextLevel(current);
    levels.push(n);
    current = n;
  }
  return ok({ root: current[0] as Hash, levels });
}

export function merkleRoot(leaves: Hash[]): Result<Hash, MerkleError> {
  if (leaves.length === 0) return err({ kind: 'EmptyLeaves', message: 'no leaves' });
  let current: Hash[] = leaves.map((l) => l);
  while (current.length > 1) current = nextLevel(current);
  return ok(current[0] as Hash);
}

export function merkleProof(leaves: Hash[], index: number): Result<MerkleProof, MerkleError> {
  if (index < 0 || index >= leaves.length) return err({ kind: 'IndexOutOfRange', message: `index ${index}`, index, leafCount: leaves.length });
  const tree = buildTree(leaves);
  if (!tree.ok) return tree;
  const siblings: Hash[] = [];
  let pos = index;
  for (let level = 0; level < tree.value.levels.length - 1; level++) {
    const nodes = tree.value.levels[level] as Hash[];
    const sib = (pos % 2 === 0 ? (pos + 1 < nodes.length ? nodes[pos + 1] : nodes[pos]) : nodes[pos - 1]) as Hash;
    siblings.push(sib);
    pos = Math.floor(pos / 2);
  }
  return ok({ index, siblings });
}

export function reconstructRoot(leaf: Hash, proof: MerkleProof): Hash {
  let cur = leaf;
  let idx = proof.index;
  for (const sib of proof.siblings) {
    cur = (idx & 1) === 0 ? hashNode(cur, sib) : hashNode(sib, cur);
    idx = idx >> 1;
  }
  return cur;
}

export function verifyProof(leaf: Hash, proof: MerkleProof, root: Hash): VerifyResult<MerkleVerifyReason> {
  return HashOps.equals(reconstructRoot(leaf, proof), root) ? verifyOk() : verifyFail({ kind: 'RootMismatch' });
}

// Terminate verification in the BSV header chain: the proof's root must be the
// merkle root committed by the header at `height`.
export function proveAgainstChain(leaf: Hash, proof: MerkleProof, height: number, headerChain: HeaderChain): VerifyResult<MerkleVerifyReason> {
  const root = headerChain.merkleRootAtHeight(height);
  if (root === undefined) return verifyFail({ kind: 'NoHeaderAtHeight' });
  if (!HashOps.equals(reconstructRoot(leaf, proof), root)) return verifyFail({ kind: 'RootMismatch' });
  return verifyOk();
}

// Verify a leaf against a root that is asserted (by the caller) to be anchored;
// also confirm the root is present in the header chain.
export function verifyAgainstAnchoredRoot(leaf: Hash, proof: MerkleProof, root: Hash, headerChain: HeaderChain): VerifyResult<MerkleVerifyReason> {
  if (!HashOps.equals(reconstructRoot(leaf, proof), root)) return verifyFail({ kind: 'RootMismatch' });
  if (headerChain.containsMerkleRoot(root) === undefined) return verifyFail({ kind: 'RootNotAnchored' });
  return verifyOk();
}

export function heightForLeafCount(leafCount: number): number {
  if (leafCount <= 1) return 0;
  let height = 0;
  let size = 1;
  while (size < leafCount) {
    size *= 2;
    height++;
  }
  return height;
}
