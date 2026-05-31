import { test } from 'node:test';
import assert from 'node:assert/strict';
import { doubleSha256 } from '@anchorchain/bsv';
import { MemStore, batchLeaves } from '@anchorchain/memstore';
import type { MemoryAtom } from '@anchorchain/memstore';

const atom = (i: number): MemoryAtom => ({ vectorId: `v${i}`, contentHash: doubleSha256(Uint8Array.of(i)), logicalTimestamp: BigInt(i), agentStateId: 's', tier: i % 2 === 0 ? 'critical' : 'ephemeral' });

test('3.x memstore snapshot/restore preserves the log, open batch, and counters', () => {
  const store = new MemStore({ closeOnCount: 3, closeOnLogicalInterval: 1_000_000n, maxBatchSize: 64 });
  const closed: string[] = [];
  for (let i = 0; i < 5; i++) {
    const r = store.append(atom(i), BigInt(i));
    if (r.ok && r.value.closed) closed.push(r.value.closed.batchId);
  }
  // one batch closed (3 atoms), two atoms left open
  assert.equal(closed.length, 1);
  assert.equal(store.openCount(), 2);

  const snap = JSON.parse(JSON.stringify(store.snapshot())); // round-trip through JSON
  const restored = MemStore.restore(snap);
  assert.equal(restored.openCount(), 2);
  assert.equal(restored.totalAppended(), 5);

  // restored store continues with the same batch numbering and closes identically
  const next = restored.append(atom(5), 5n); // open now has 3 -> closes batch-1
  assert.ok(next.ok && next.value.closed);
  if (next.ok && next.value.closed) {
    assert.equal(next.value.closed.batchId, 'batch-1');
    assert.equal(batchLeaves(next.value.closed).length, 3);
  }
});
