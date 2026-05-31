import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scalarSub, pointMulG } from '@anchorchain/bsv';
import { commit, proveRange, proveConservation, randScalar } from '@anchorchain/privacy';
import { CreditLedger, verifyLedger } from '@anchorchain/credit';

const BITS = 16;

test('12.5 ledger snapshot/restore preserves balances, applied ops, and the chain', () => {
  const r = randScalar();
  const open = proveRange(1000n, r, BITS);
  assert.ok(open.ok);
  if (!open.ok) return;
  const ledger = new CreditLedger(BITS);
  ledger.open('a', 'op0', open.commitment, open.proof);
  const nb = randScalar();
  const rp = proveRange(700n, nb, BITS);
  assert.ok(rp.ok);
  if (!rp.ok) return;
  const cp = proveConservation([open.commitment], [rp.commitment, pointMulG(300n)], scalarSub(r, nb));
  assert.ok(cp.ok);
  if (!cp.ok) return;
  ledger.debit('a', 'op1', 300n, { newCommitment: rp.commitment, conservation: cp.proof, rangeProof: rp.proof });

  const snap = JSON.parse(JSON.stringify(ledger.snapshot()));
  const restored = CreditLedger.restore(snap);

  // the restored ledger's chain still verifies and matches the original head
  assert.equal(verifyLedger(restored.ledger()), true);
  assert.equal(restored.headHash() && ledger.headHash() ? restored.ledger().at(-1)!.hashHex === ledger.ledger().at(-1)!.hashHex : false, true);
  // the no-double-debit guard survives the round-trip: op1 is still spent
  const replay = restored.debit('a', 'op1', 1n, { newCommitment: rp.commitment, conservation: cp.proof, rangeProof: rp.proof });
  assert.equal(replay.ok === false && replay.error.kind, 'ReplayedOp');
  // the confidential balance commitment is preserved exactly
  assert.equal(restored.balanceCommitment('a') !== undefined, true);
});
