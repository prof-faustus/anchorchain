import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Hash, BlockHeader } from '@anchorchain/bsv';
import { HashOps, HeaderChain } from '@anchorchain/bsv';
import { hashLeaf, merkleRoot, merkleProof } from '@anchorchain/merkle';
import { proofAssistance, shardProof } from '@anchorchain/shard';
import { makeProofEntity, verifyHeaderOnly, verifyAssistedHeaderOnly, anchoredHeight, claimedRoot } from '@anchorchain/proofentity';

const unwrap = <T>(r: { ok: true; value: T } | { ok: false; error: unknown }): T => {
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r.value;
};
const ZERO = HashOps.fromInternalBytes(new Uint8Array(32)).value;
const leaves = (n: number) => Array.from({ length: n }, (_, i) => hashLeaf(Uint8Array.of(0xa0, i)));

// A header chain that commits to `root` at `height`. Uses a regtest-style target
// and mines a nonce that meets it, so the test controls the anchored merkle root
// while still presenting genuine (target-meeting) proof-of-work to the chain.
function chainCommitting(root: Hash, height: number): HeaderChain {
  const chain = new HeaderChain(height);
  for (let nonce = 0; nonce < 1_000_000; nonce++) {
    const header: BlockHeader = { version: 1, prevBlockHash: ZERO, merkleRoot: root, time: 1_700_000_000, bits: 0x207fffff, nonce };
    if (chain.add(header).ok) return chain;
  }
  throw new Error('could not mine a regtest header for the test root');
}

test('8.1 a full proof entity verifies header-only at its pinned height and reports that height', () => {
  const ls = leaves(6);
  const root = unwrap(merkleRoot(ls));
  const entity = unwrap(makeProofEntity({ leaf: ls[3]!, index: 3, proof: unwrap(merkleProof(ls, 3)), anchorTxidDisplay: 'a'.repeat(64), blockHeight: 820_000, tier: 'critical' }));
  assert.equal(HashOps.equals(claimedRoot(entity), root), true);
  const chain = chainCommitting(root, 820_000);
  assert.equal(verifyHeaderOnly(entity, chain).ok, true);
  assert.equal(anchoredHeight(entity, chain), 820_000);
});

test('8.1 verification is exactly the header chain: wrong height, absent root, and tampered leaf all fail', () => {
  const ls = leaves(6);
  const root = unwrap(merkleRoot(ls));
  const entity = unwrap(makeProofEntity({ leaf: ls[3]!, index: 3, proof: unwrap(merkleProof(ls, 3)), anchorTxidDisplay: 'a'.repeat(64), blockHeight: 820_000 }));
  // committed at a different height than the entity claims
  assert.equal(verifyHeaderOnly(entity, chainCommitting(root, 820_001)).reason!.kind, 'NoHeaderAtHeight');
  // header at the right height commits to a different root
  const other = unwrap(merkleRoot(leaves(7)));
  assert.equal(verifyHeaderOnly(entity, chainCommitting(other, 820_000)).reason!.kind, 'HeightRootMismatch');
  // a tampered leaf reconstructs to a root no header commits to
  const tampered = HashOps.toInternalBytes(ls[3]!);
  tampered[0] ^= 0xff;
  const bad = unwrap(makeProofEntity({ leaf: HashOps.fromInternalBytes(tampered).value, index: 3, proof: unwrap(merkleProof(ls, 3)), anchorTxidDisplay: 'a'.repeat(64) }));
  assert.equal(verifyHeaderOnly(bad, chainCommitting(root, 820_000)).reason!.kind, 'RootNotAnchored');
});

test('8.1 an entity with no pinned height accepts any header committing to its root', () => {
  const ls = leaves(8);
  const root = unwrap(merkleRoot(ls));
  const entity = unwrap(makeProofEntity({ leaf: ls[0]!, index: 0, proof: unwrap(merkleProof(ls, 0)), anchorTxidDisplay: 'b'.repeat(64) }));
  assert.equal(verifyHeaderOnly(entity, chainCommitting(root, 12345)).ok, true);
  assert.equal(anchoredHeight(entity, chainCommitting(root, 12345)), 12345);
});

test('8.1 assisted (selectively-disclosed) presentation verifies header-only without the upper path', () => {
  const ls = leaves(8); // height 3
  const root = unwrap(merkleRoot(ls));
  const idx = 5;
  const full = unwrap(merkleProof(ls, idx));
  const level = 1;
  const lower = unwrap(shardProof(full, level)).lower;
  const assistance = unwrap(proofAssistance(ls, level));
  const chain = chainCommitting(root, 700_000);
  assert.equal(verifyAssistedHeaderOnly({ leaf: ls[idx]!, leafIndex: idx, lower }, assistance, root, chain).ok, true);
  // the correct anchored root, but a header chain that does not commit to it,
  // is rejected as not anchored
  const elsewhere = chainCommitting(unwrap(merkleRoot(leaves(9))), 700_000);
  assert.equal(verifyAssistedHeaderOnly({ leaf: ls[idx]!, leafIndex: idx, lower }, assistance, root, elsewhere).reason!.kind, 'RootNotAnchored');
});

test('8.1 makeProofEntity rejects a malformed anchor txid and a negative index', () => {
  const ls = leaves(4);
  assert.equal(makeProofEntity({ leaf: ls[0]!, index: 0, proof: unwrap(merkleProof(ls, 0)), anchorTxidDisplay: 'short' }).ok, false);
  assert.equal(makeProofEntity({ leaf: ls[0]!, index: -1, proof: unwrap(merkleProof(ls, 0)), anchorTxidDisplay: 'c'.repeat(64) }).ok, false);
});
