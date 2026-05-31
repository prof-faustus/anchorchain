import { test } from 'node:test';
import assert from 'node:assert/strict';
import { doubleSha256, HashOps, nodeUnreachable } from '@anchorchain/bsv';
import type { NodeClient, Result, Txid, BsvError } from '@anchorchain/bsv';
import { OfflineNodeClient } from '@anchorchain/bsv';
import type { Batch, MemoryAtom } from '@anchorchain/memstore';
import { batchLeaves } from '@anchorchain/memstore';
import { Anchorer, verifyReference, rootFromAnchorTx } from '@anchorchain/anchor';

const node = new OfflineNodeClient({ headersByHeight: new Map(), headerByHash: new Map(), branches: new Map(), submitted: new Set() });
function batch(n: number): Batch {
  const atoms: MemoryAtom[] = [];
  for (let i = 0; i < n; i++) atoms.push({ vectorId: `vec-${i}`, contentHash: doubleSha256(Uint8Array.of(i)), logicalTimestamp: BigInt(i), agentStateId: 'a', tier: 'critical' });
  return { batchId: 'batch-0', atoms, closedAtLogical: 0n };
}

test('7.3 anchorBatch embeds the root, is idempotent, and the reference proof validates', async () => {
  const anchorer = new Anchorer();
  const b = batch(8);
  const m1 = await anchorer.anchorBatch(b, node, { tier: 'critical', schemaFingerprintHex: 'abcd' });
  assert.equal(m1.ok, true);
  if (!m1.ok) return;
  // idempotent: same batch id -> same anchor, no second transaction
  const m2 = await anchorer.anchorBatch(b, node);
  assert.equal(m2.ok && m2.value.anchorTxidDisplay, m1.value.anchorTxidDisplay);

  const root = anchorer.rootOf('batch-0')!;
  const ref = anchorer.referenceFor('batch-0', 'vec-3');
  assert.equal(ref.ok, true);
  if (ref.ok) {
    assert.equal(verifyReference(ref.value, b.atoms[3]!.contentHash, root).ok, true);
    assert.equal(verifyReference(ref.value, b.atoms[4]!.contentHash, root).ok, false); // wrong leaf
    assert.equal(ref.value.tier, 'critical');
    assert.equal(ref.value.schemaFingerprintHex, 'abcd');
  }
  // an auditor recovers the root from the raw anchor transaction
  const raw = anchorer.rawTxOf('batch-0')!;
  const recovered = rootFromAnchorTx(raw);
  assert.equal(recovered.ok, true);
  if (recovered.ok) assert.equal(HashOps.toDisplayHex(recovered.value.root), m1.value.rootDisplay);
});

test('7.3 a submission failure returns a typed error and leaves the batch re-anchorable', async () => {
  const failing: NodeClient = {
    async submit(): Promise<Result<Txid, BsvError>> {
      return { ok: false, error: nodeUnreachable('down') };
    },
    async headerByHeight() {
      return { ok: false, error: nodeUnreachable('x') };
    },
    async headerByHash() {
      return { ok: false, error: nodeUnreachable('x') };
    },
    async merkleBranchForTxid() {
      return { ok: false, error: nodeUnreachable('x') };
    },
    async headersFrom() {
      return { ok: false, error: nodeUnreachable('x') };
    },
  };
  const anchorer = new Anchorer();
  const r = await anchorer.anchorBatch(batch(4), failing);
  assert.equal(r.ok, false);
  if (!r.ok) assert.equal(r.error.kind, 'SubmitFailed');
  assert.equal(anchorer.isAnchored('batch-0'), false); // re-anchorable
  // now succeeds against a working node
  assert.equal((await anchorer.anchorBatch(batch(4), node)).ok, true);
});

test('7.3 an empty batch is rejected', async () => {
  const anchorer = new Anchorer();
  const r = await anchorer.anchorBatch({ batchId: 'b', atoms: [], closedAtLogical: 0n }, node);
  assert.equal(r.ok, false);
  void batchLeaves;
});
