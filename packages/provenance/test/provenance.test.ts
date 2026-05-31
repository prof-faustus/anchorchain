import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { Hash, BlockHeader } from '@anchorchain/bsv';
import { HashOps, HeaderChain } from '@anchorchain/bsv';
import { hashLeaf, merkleRoot, merkleProof } from '@anchorchain/merkle';
import { makeProofEntity } from '@anchorchain/proofentity';
import { ProvenanceGraph, verifyRecall } from '@anchorchain/provenance';

const unwrap = <T>(r: { ok: true; value: T } | { ok: false; error: unknown }): T => {
  if (!r.ok) throw new Error(JSON.stringify(r.error));
  return r.value;
};
const ZERO = HashOps.zero();

// A header chain committing to `root` at `height`: regtest-style target, mined
// nonce, so the test controls the anchored merkle root with genuine PoW.
function chainCommitting(root: Hash, height: number): HeaderChain {
  const chain = new HeaderChain(height);
  for (let nonce = 0; nonce < 1_000_000; nonce++) {
    const header: BlockHeader = { version: 1, prevBlockHash: ZERO, merkleRoot: root, time: 1_700_000_000, bits: 0x207fffff, nonce };
    if (chain.add(header).ok) return chain;
  }
  throw new Error('could not mine a regtest header for the test root');
}

// Anchor a set of object leaves into one batch and return a proof entity per index.
function anchorBatch(leaves: Hash[], height: number) {
  const root = unwrap(merkleRoot(leaves));
  const entityAt = (i: number) =>
    unwrap(makeProofEntity({ leaf: leaves[i]!, index: i, proof: unwrap(merkleProof(leaves, i)), anchorTxidDisplay: 'd'.repeat(64), blockHeight: height }));
  return { root, entityAt, chain: chainCommitting(root, height) };
}

test('8.3 identity -> object -> anchor provenance is recorded and queryable', () => {
  const g = new ProvenanceGraph();
  const leaves = [hashLeaf(Uint8Array.of(1)), hashLeaf(Uint8Array.of(2))];
  const { entityAt } = anchorBatch(leaves, 800_000);
  unwrap(g.addObject({ objectId: 'mem-1', contentHash: leaves[0]!, agentId: 'agent-A', kind: 'memory' }, entityAt(0)));
  unwrap(g.addObject({ objectId: 'mem-2', contentHash: leaves[1]!, agentId: 'agent-A', kind: 'memory' }, entityAt(1)));
  assert.equal(g.objectsByAgent('agent-A').length, 2);
  const p = unwrap(g.provenanceOf('mem-1'));
  assert.equal(p.identity.agentId, 'agent-A');
  assert.equal(p.anchor.blockHeight, 800_000);
  assert.equal(p.anchor.anchorTxidDisplay, 'd'.repeat(64));
});

test('8.3 a proof entity that does not prove the object is rejected at insertion', () => {
  const g = new ProvenanceGraph();
  const leaves = [hashLeaf(Uint8Array.of(1)), hashLeaf(Uint8Array.of(2))];
  const { entityAt } = anchorBatch(leaves, 800_000);
  // object claims leaf[1] but is given the proof for leaf[0]
  const r = g.addObject({ objectId: 'mem-x', contentHash: leaves[1]!, agentId: 'agent-A', kind: 'memory' }, entityAt(0));
  assert.equal(r.ok === false && r.error.kind, 'LeafMismatch');
});

test('8.3 cross-agent recall verifies header-only against the producing agent anchor', () => {
  const g = new ProvenanceGraph();
  const leaves = [hashLeaf(Uint8Array.of(7)), hashLeaf(Uint8Array.of(8))];
  const { entityAt, chain } = anchorBatch(leaves, 815_000);
  unwrap(g.addObject({ objectId: 'mem-A', contentHash: leaves[0]!, agentId: 'agent-A', kind: 'memory' }, entityAt(0)));
  // a DIFFERENT agent recalls agent-A's object and verifies it independently
  const recall = unwrap(g.recall('agent-B', 'mem-A'));
  assert.equal(recall.recallingAgent, 'agent-B');
  assert.equal(verifyRecall(recall, chain).ok, true);
  // against a header chain that does not commit to the root, recall fails closed
  const wrong = chainCommitting(unwrap(merkleRoot([hashLeaf(Uint8Array.of(99))])), 815_000);
  assert.equal(verifyRecall(recall, wrong).ok, false);
});

test('8.3 a tampered recall (leaf swapped) is rejected even if the proof is internally valid', () => {
  const g = new ProvenanceGraph();
  const leaves = [hashLeaf(Uint8Array.of(7)), hashLeaf(Uint8Array.of(8))];
  const { entityAt, chain } = anchorBatch(leaves, 815_000);
  unwrap(g.addObject({ objectId: 'mem-A', contentHash: leaves[0]!, agentId: 'agent-A', kind: 'memory' }, entityAt(0)));
  const recall = unwrap(g.recall('agent-B', 'mem-A'));
  const swapped = { ...recall, object: { ...recall.object, contentHash: leaves[1]! } };
  assert.equal(verifyRecall(swapped, chain).reason!.kind, 'LeafNotObject');
});

test('8.3 derivation lineage spans agents: B recalls A then re-anchors a derived object', () => {
  const g = new ProvenanceGraph();
  const aLeaves = [hashLeaf(Uint8Array.of(10))];
  const a = anchorBatch(aLeaves, 820_000);
  unwrap(g.addObject({ objectId: 'mem-A', contentHash: aLeaves[0]!, agentId: 'agent-A', kind: 'memory' }, a.entityAt(0)));
  // agent-B derives a new memory from mem-A and anchors it in its own batch
  const bLeaves = [hashLeaf(Uint8Array.of(11))];
  const b = anchorBatch(bLeaves, 820_500);
  unwrap(g.addObject({ objectId: 'mem-B', contentHash: bLeaves[0]!, agentId: 'agent-B', kind: 'memory' }, b.entityAt(0), 'mem-A'));
  const lineage = unwrap(g.lineage('mem-B'));
  assert.deepEqual(lineage.map((o) => o.objectId), ['mem-B', 'mem-A']);
  assert.deepEqual(lineage.map((o) => o.agentId), ['agent-B', 'agent-A']);
  // deriving from an unrecorded parent is refused
  assert.equal(g.addObject({ objectId: 'mem-C', contentHash: bLeaves[0]!, agentId: 'agent-C', kind: 'memory' }, b.entityAt(0), 'ghost').ok, false);
});
