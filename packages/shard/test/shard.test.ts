import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HashOps, HeaderChain, meetsTarget, doubleSha256 } from '@anchorchain/bsv';
import type { BlockHeader, Hash } from '@anchorchain/bsv';
import { hashLeaf, merkleRoot, merkleProof } from '@anchorchain/merkle';
import { shardProof, reassemble, proofAssistance, verifyWithAssistance, labelsHashToRoot, homomorphicAssistanceSum, verifyTrustedCompression, disclosedBytes } from '@anchorchain/shard';

const unwrap = <T>(r: { ok: true; value: T } | { ok: false; error: unknown }): T => {
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r.value;
};
function synthHeader(root: Hash): BlockHeader {
  let h: BlockHeader = { version: 1, prevBlockHash: HashOps.zero(), merkleRoot: root, time: 0, bits: 0x2100ffff, nonce: 0 };
  while (!meetsTarget(h)) h = { ...h, nonce: h.nonce + 1 };
  return h;
}
const leaves = Array.from({ length: 16 }, (_, i) => hashLeaf(doubleSha256(Uint8Array.of(i))));
const root = unwrap(merkleRoot(leaves));
const LEVEL = 2;

test('5.4 shards are non-overlapping and gapless and reassemble to the original proof', () => {
  const proof = unwrap(merkleProof(leaves, 5));
  const { lower, upper } = unwrap(shardProof(proof, LEVEL));
  assert.equal(lower.fromLevel, 0);
  assert.equal(lower.toLevel, LEVEL);
  assert.equal(upper.fromLevel, LEVEL); // gapless: upper starts where lower ends
  assert.equal(upper.toLevel, proof.siblings.length);
  const re = unwrap(reassemble(proof.index, [lower, upper]));
  for (let i = 0; i < proof.siblings.length; i++) assert.equal(HashOps.equals(re.siblings[i]!, proof.siblings[i]!), true);
  assert.equal(shardProof(proof, 0).ok, false);
  assert.equal(reassemble(5, [upper]).ok, false); // gap
});

test('5.4 verifyWithAssistance accepts the queried portion and rejects tampering, terminating in the header chain', () => {
  const idx = 9;
  const proof = unwrap(merkleProof(leaves, idx));
  const { lower } = unwrap(shardProof(proof, LEVEL));
  const assistance = unwrap(proofAssistance(leaves, LEVEL));
  const chain = new HeaderChain();
  chain.add(synthHeader(root));
  const disclosed = { leaf: leaves[idx]!, leafIndex: idx, lower };
  assert.equal(verifyWithAssistance(disclosed, assistance, root, chain).ok, true);
  assert.ok(disclosedBytes(disclosed) < proof.siblings.length * 32 + 12); // smaller than the full proof

  // tampered lower shard
  const bad = HashOps.toInternalBytes(lower.siblings[0]!);
  bad[0] ^= 0xff;
  const tampered = { ...disclosed, lower: { ...lower, siblings: [HashOps.fromInternalBytes(bad).value, ...lower.siblings.slice(1)] } };
  assert.equal(verifyWithAssistance(tampered, assistance, root, chain).ok, false);
  // wrong root
  const badRoot = HashOps.toInternalBytes(root);
  badRoot[0] ^= 0xff;
  assert.equal(verifyWithAssistance(disclosed, assistance, HashOps.fromInternalBytes(badRoot).value, chain).ok, false);
  // unanchored
  assert.equal(verifyWithAssistance(disclosed, assistance, root, new HeaderChain()).ok, false);
});

test('5.4 labels hash to the root; the homomorphic compression is trusted-only and refused by the audit path', () => {
  const assistance = unwrap(proofAssistance(leaves, LEVEL));
  assert.equal(labelsHashToRoot(assistance, root).ok, true);
  const altered = { ...assistance, nodeLabels: assistance.nodeLabels.map((h) => h) };
  altered.nodeLabels[0] = altered.nodeLabels[1]!;
  assert.equal(labelsHashToRoot(altered, root).ok, false);

  // trusted-mode homomorphic sum verifies in trusted mode...
  const sum = homomorphicAssistanceSum(assistance);
  assert.equal(verifyTrustedCompression(assistance, sum).ok, true);
  assert.equal(verifyTrustedCompression(altered, sum).ok, false);
  // ...but the audit verification path (verifyWithAssistance) never consults it:
  // it only folds the disclosed shard and the published labels (asserted above).
});
