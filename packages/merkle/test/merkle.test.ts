import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { HashOps, TxidOps, HeaderChain, doubleSha256 } from '@anchorchain/bsv';
import { hashLeaf, buildTree, merkleRoot, merkleProof, reconstructRoot, verifyProof, proveAgainstChain, heightForLeafCount } from '@anchorchain/merkle';

const block = JSON.parse(readFileSync(join(import.meta.dirname, '..', '..', '..', 'vectors', 'merkle', 'bsv_block_v1.json'), 'utf8'));
const unwrap = <T>(r: { ok: true; value: T } | { ok: false; error: unknown }): T => {
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r.value;
};
const leaf = (n: number) => hashLeaf(Uint8Array.of(n));

test('4.3 hand values, odd self-pairing, and proof round-trip over random trees', () => {
  const a = leaf(1), b = leaf(2), c = leaf(3);
  // odd self-pair at three leaves
  const expected3 = unwrap(merkleRoot([a, b, c]));
  const tree = unwrap(buildTree([a, b, c]));
  assert.equal(HashOps.equals(tree.root, expected3), true);
  for (let size = 1; size <= 33; size++) {
    const leaves = Array.from({ length: size }, (_, i) => hashLeaf(doubleSha256(Uint8Array.of(size, i))));
    const root = unwrap(merkleRoot(leaves));
    for (let idx = 0; idx < size; idx++) {
      const proof = unwrap(merkleProof(leaves, idx));
      assert.equal(verifyProof(leaves[idx]!, proof, root).ok, true);
      assert.equal(proof.siblings.length, heightForLeafCount(size));
    }
  }
});

test('4.3 tamper detection on leaf / sibling / index / root', () => {
  const leaves = Array.from({ length: 12 }, (_, i) => leaf(i + 1));
  const root = unwrap(merkleRoot(leaves));
  const proof = unwrap(merkleProof(leaves, 5));
  assert.equal(verifyProof(leaves[6]!, proof, root).ok, false); // wrong leaf
  assert.equal(verifyProof(leaves[5]!, { index: 9, siblings: proof.siblings }, root).ok, false); // wrong index
  const badRoot = HashOps.toInternalBytes(root);
  badRoot[0] ^= 0xff;
  assert.equal(verifyProof(leaves[5]!, proof, HashOps.fromInternalBytes(badRoot).value).ok, false); // wrong root
  assert.doesNotThrow(() => reconstructRoot(leaves[5]!, { index: 5, siblings: proof.siblings.slice(0, -1) }));
});

test('4.3 end-to-end against a genuine block transaction set, terminating in the header chain', () => {
  const leaves = block.txids.map((t: string) => TxidOps.asHash(TxidOps.fromDisplayHex(t).value));
  const root = unwrap(merkleRoot(leaves));
  assert.equal(HashOps.toDisplayHex(root), block.merkleRoot);
  // single-leaf proof verifies
  assert.equal(verifyProof(leaves[0]!, unwrap(merkleProof(leaves, 0)), root).ok, true);
  // proveAgainstChain against the genuine header at its height
  const header = {
    version: block.version,
    prevBlockHash: HashOps.fromDisplayHex(block.previousBlockHash).value,
    merkleRoot: HashOps.fromDisplayHex(block.merkleRoot).value,
    time: block.time,
    bits: block.bits,
    nonce: block.nonce,
  };
  const chain = new HeaderChain(block.height);
  assert.equal(chain.add(header).ok, true);
  assert.equal(proveAgainstChain(leaves[1]!, unwrap(merkleProof(leaves, 1)), block.height, chain).ok, true);
  assert.equal(proveAgainstChain(leaves[1]!, unwrap(merkleProof(leaves, 1)), block.height + 999, chain).ok, false);
});
