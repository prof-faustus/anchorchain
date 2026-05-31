import { test } from 'node:test';
import assert from 'node:assert/strict';
import { doubleSha256 } from '@anchorchain/bsv';
import { MemStore, batchLeaves } from '@anchorchain/memstore';
import type { MemoryAtom, BatchPolicy } from '@anchorchain/memstore';

const atom = (i: number, tier: 'ephemeral' | 'critical' = 'critical'): MemoryAtom => ({
  vectorId: `vec-${i}`,
  contentHash: doubleSha256(Uint8Array.of(i)),
  logicalTimestamp: BigInt(i),
  agentStateId: 'agent-1',
  tier,
});

test('7.3 a batch closes on the count threshold; the tier is recorded', () => {
  const policy: BatchPolicy = { closeOnCount: 3, closeOnLogicalInterval: 1000000n, maxBatchSize: 100 };
  const store = new MemStore(policy);
  let closed;
  for (let i = 0; i < 3; i++) closed = store.append(atom(i), BigInt(i));
  assert.equal(closed!.ok, true);
  if (closed!.ok) {
    assert.ok(closed!.value.closed !== undefined);
    assert.equal(closed!.value.closed!.atoms.length, 3);
    assert.equal(closed!.value.closed!.atoms[0]!.tier, 'critical');
    assert.equal(batchLeaves(closed!.value.closed!).length, 3);
  }
});

test('7.3 a batch closes on the logical-interval boundary', () => {
  const policy: BatchPolicy = { closeOnCount: 1000, closeOnLogicalInterval: 10n, maxBatchSize: 100 };
  const store = new MemStore(policy);
  store.append(atom(0), 0n);
  const r = store.append(atom(1), 11n); // interval exceeded
  assert.equal(r.ok, true);
  if (r.ok) assert.ok(r.value.closed !== undefined);
});

test('7.3 invalid atoms and the batch-size bound are rejected', () => {
  const policy: BatchPolicy = { closeOnCount: 1000, closeOnLogicalInterval: 1000n, maxBatchSize: 2 };
  const store = new MemStore(policy);
  assert.equal(store.append({ ...atom(0), vectorId: '' }, 0n).ok, false);
  store.append(atom(1), 1n);
  store.append(atom(2), 2n);
  assert.equal(store.append(atom(3), 3n).ok, false); // over maxBatchSize
});
