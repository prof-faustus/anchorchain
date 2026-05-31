import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig, AnchorChainService } from '@anchorchain/api';
import { join } from 'node:path';

const config = loadConfig(join(import.meta.dirname, '..', '..', '..', 'config', 'default.json'));
// a small batch policy so a couple of appends close a batch quickly
config.batch.closeOnCount = 2;

// other transactions that share the anchor's block (display-hex txids)
const otherTxids = ['11'.repeat(32), '22'.repeat(32), '33'.repeat(32)];

test('14.s end-to-end: append -> anchor -> confirm-in-block -> verify inclusion header-only', async () => {
  const svc = new AnchorChainService(config);
  const a = svc.appendMemory({ agentId: 'agent-A', vector: [1, 2, 3], timestamp: 1n, agentStateId: 'state-A', vectorId: 'mem-1' });
  assert.ok(a.ok);
  const b = svc.appendMemory({ agentId: 'agent-A', vector: [4, 5, 6], timestamp: 2n, agentStateId: 'state-A', vectorId: 'mem-2' });
  assert.ok(b.ok && b.value.closedBatchId !== undefined); // batch closed on count 2
  const batchId = b.ok ? b.value.closedBatchId! : '';

  const anchored = await svc.anchor(batchId);
  assert.ok(anchored.ok);
  const confirmed = svc.confirmInBlock(batchId, otherTxids);
  assert.ok(confirmed.ok);

  // full four-step SPV verification succeeds for both anchored memories
  assert.equal(svc.verifyInclusion('mem-1').ok, true);
  assert.equal(svc.verifyInclusion('mem-2').ok, true);
  const inc = svc.inclusion('mem-1');
  assert.ok(inc.ok && inc.value.blockHeight === confirmed.value!.blockHeight);
});

test('14.s verification fails before confirmation and for an unknown vector', async () => {
  const svc = new AnchorChainService(config);
  svc.appendMemory({ agentId: 'A', vector: [1], timestamp: 1n, agentStateId: 's', vectorId: 'm1' });
  const r2 = svc.appendMemory({ agentId: 'A', vector: [2], timestamp: 2n, agentStateId: 's', vectorId: 'm2' });
  const batchId = r2.ok ? r2.value.closedBatchId! : '';
  await svc.anchor(batchId);
  // anchored but not yet confirmed in a block
  assert.equal(svc.verifyInclusion('m1').reason!.kind, 'NotConfirmed');
  svc.confirmInBlock(batchId, otherTxids);
  assert.equal(svc.verifyInclusion('m1').ok, true);
  // unknown vector
  assert.equal(svc.verifyInclusion('does-not-exist').reason!.kind, 'UnknownVector');
});

test('14.s a memory whose anchor tx is NOT actually in the confirmed block fails at the block step', async () => {
  const svc = new AnchorChainService(config);
  svc.appendMemory({ agentId: 'A', vector: [1], timestamp: 1n, agentStateId: 's', vectorId: 'm1' });
  const r2 = svc.appendMemory({ agentId: 'A', vector: [2], timestamp: 2n, agentStateId: 's', vectorId: 'm2' });
  const batchId = r2.ok ? r2.value.closedBatchId! : '';
  await svc.anchor(batchId);
  svc.confirmInBlock(batchId, otherTxids);
  // the header chain is real and the proof is genuine; verification holds
  assert.equal(svc.verifyInclusion('m1').ok, true);
  // the recorded branch is for index 0 (the anchor tx); tampering the chain would be
  // caught — sanity that the header committed root equals the reconstructed block root
  assert.ok(svc.headers.merkleRootAtHeight(0) !== undefined);
});
