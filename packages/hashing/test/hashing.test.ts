import { test } from 'node:test';
import assert from 'node:assert/strict';
import { HashOps, doubleSha256 } from '@anchorchain/bsv';
import { memoryLeaf, encodeVector } from '@anchorchain/hashing';
import type { MemoryContext } from '@anchorchain/hashing';

const ctx = (agentId = 'agent-1'): MemoryContext => ({
  agentId,
  sourceDocHash: HashOps.toInternalBytes(doubleSha256(new TextEncoder().encode('doc'))),
  promptChainRef: 'chain-1',
  memoryLayerRef: 'episodic',
});

test('3.3 memoryLeaf is deterministic across calls', () => {
  const v = [1, 2, 3, 4];
  assert.equal(HashOps.equals(memoryLeaf(ctx(), v, 1n), memoryLeaf(ctx(), v, 1n)), true);
});

test('3.3 a dimension mismatch diverges', () => {
  assert.equal(HashOps.equals(memoryLeaf(ctx(), [1, 2, 3], 1n), memoryLeaf(ctx(), [1, 2, 3, 0], 1n)), false);
});

test('3.3 raw and quantised encodings differ; context and timestamp change the leaf', () => {
  const v = [1, 2, 3];
  assert.equal(HashOps.equals(memoryLeaf(ctx(), v, 1n, { encoding: 'raw' }), memoryLeaf(ctx(), v, 1n, { encoding: 'quantised' })), false);
  assert.equal(HashOps.equals(memoryLeaf(ctx('a'), v, 1n), memoryLeaf(ctx('b'), v, 1n)), false);
  assert.equal(HashOps.equals(memoryLeaf(ctx(), v, 1n), memoryLeaf(ctx(), v, 2n)), false);
});

test('3.3 encodeVector length-prefixes so different dimensions never collide', () => {
  assert.notDeepEqual(Array.from(encodeVector([1, 2], 'raw')), Array.from(encodeVector([1, 2, 3], 'raw')));
});
